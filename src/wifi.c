/* Saved WiFi profiles + plaintext passwords.
 * Uses wlanapi.dll (loaded dynamically): WlanGetProfile with
 * WLAN_PROFILE_GET_PLAINTEXT_KEY returns the profile XML containing
 * <keyMaterial>. MinGW lacks wlanapi.h so the minimal ABI is declared here. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "wifi.h"
#include "browser/utils.h"

/* ---- minimal wlanapi ABI (matches Vista+ WLANAPI.dll) ---- */
typedef struct WLAN_INTERFACE_INFO {
    GUID  InterfaceGuid;
    WCHAR strInterfaceDescription[256];
    DWORD isState;
} WLAN_INTERFACE_INFO;

typedef struct WLAN_INTERFACE_INFO_LIST {
    DWORD dwNumberOfItems;
    DWORD dwIndex;
    WLAN_INTERFACE_INFO InterfaceInfo[1];
} WLAN_INTERFACE_INFO_LIST;

typedef struct WLAN_PROFILE_INFO {
    WCHAR strProfileName[256];
    DWORD dwFlags;
} WLAN_PROFILE_INFO;

typedef struct WLAN_PROFILE_INFO_LIST {
    DWORD dwNumberOfItems;
    DWORD dwIndex;
    WLAN_PROFILE_INFO ProfileInfo[1];
} WLAN_PROFILE_INFO_LIST;

#define WLAN_PROFILE_GET_PLAINTEXT_KEY 0x00000004

typedef DWORD (WINAPI *fn_WlanOpenHandle)(DWORD dwClientVersion, PVOID pReserved,
                                          PDWORD pdwNegotiatedVersion, PHANDLE phClientHandle);
typedef DWORD (WINAPI *fn_WlanEnumInterfaces)(HANDLE hClientHandle, PVOID pReserved,
                                              WLAN_INTERFACE_INFO_LIST **ppInterfaceList);
typedef DWORD (WINAPI *fn_WlanGetProfileList)(HANDLE hClientHandle, const GUID *pInterfaceGuid,
                                              PVOID pReserved, WLAN_PROFILE_INFO_LIST **ppProfileList);
typedef DWORD (WINAPI *fn_WlanGetProfile)(HANDLE hClientHandle, const GUID *pInterfaceGuid,
                                          LPCWSTR strProfileName, PVOID pReserved,
                                          LPWSTR *pstrProfileXml, DWORD *pdwFlags,
                                          DWORD *pdwGrantedAccess);
typedef void  (WINAPI *fn_WlanFreeMemory)(PVOID pMemory);
typedef DWORD (WINAPI *fn_WlanCloseHandle)(HANDLE hClientHandle, PVOID pReserved);

/* extract inner text of <tag>...</tag> (UTF-16 in, ASCII out) */
static int wifi_xml_tag(const wchar_t* xml, const char* tag, char* out, int out_sz) {
    wchar_t open[64], close[64];
    swprintf(open, 64, L"<%hs>", tag);
    swprintf(close, 64, L"</%hs>", tag);
    const wchar_t* s = wcsstr(xml, open);
    if (!s) return 0;
    s += wcslen(open);
    const wchar_t* e = wcsstr(s, close);
    if (!e || e == s) return 0;
    int n = 0;
    for (const wchar_t* p = s; p < e && n < out_sz - 1; p++) {
        if (*p == '&' && n + 5 < out_sz) {
            /* unescape the handful XML entities WLAN uses */
            if (wcsncmp(p, L"&amp;", 5) == 0)      { out[n++] = '&'; p += 4; }
            else if (wcsncmp(p, L"&lt;", 4) == 0)  { out[n++] = '<'; p += 3; }
            else if (wcsncmp(p, L"&gt;", 4) == 0)  { out[n++] = '>'; p += 3; }
            else if (wcsncmp(p, L"&quot;", 6) == 0){ out[n++] = '"'; p += 5; }
            else if (wcsncmp(p, L"&apos;", 6) == 0){ out[n++] = '\''; p += 5; }
            else out[n++] = (char)*p;
        } else if (*p < 128) {
            out[n++] = (char)*p;
        } else {
            out[n++] = '?';
        }
    }
    out[n] = 0;
    return n > 0;
}

const char* wifi_scan(void) {
    static StrBuilder sb;
    sb_init(&sb);

    HMODULE wlan = LoadLibraryA("wlanapi.dll");
    if (!wlan) {
        sb_printf(&sb, "WLAN service unavailable (wlanapi.dll not found).\n");
        return sb_str(&sb);
    }
    fn_WlanOpenHandle        pOpen  = (fn_WlanOpenHandle)GetProcAddress(wlan, "WlanOpenHandle");
    fn_WlanEnumInterfaces    pEnum  = (fn_WlanEnumInterfaces)GetProcAddress(wlan, "WlanEnumInterfaces");
    fn_WlanGetProfileList    pList  = (fn_WlanGetProfileList)GetProcAddress(wlan, "WlanGetProfileList");
    fn_WlanGetProfile        pProf  = (fn_WlanGetProfile)GetProcAddress(wlan, "WlanGetProfile");
    fn_WlanFreeMemory        pFree  = (fn_WlanFreeMemory)GetProcAddress(wlan, "WlanFreeMemory");
    fn_WlanCloseHandle       pClose = (fn_WlanCloseHandle)GetProcAddress(wlan, "WlanCloseHandle");
    if (!pOpen || !pEnum || !pList || !pProf || !pFree || !pClose) {
        sb_printf(&sb, "WLAN API entry points missing.\n");
        FreeLibrary(wlan);
        return sb_str(&sb);
    }

    DWORD version = 0;
    HANDLE h = NULL;
    if (pOpen(2, NULL, &version, &h) != 0) {
        sb_printf(&sb, "WLAN service not running (WlanOpenHandle failed).\n");
        FreeLibrary(wlan);
        return sb_str(&sb);
    }

    WLAN_INTERFACE_INFO_LIST* ifaces = NULL;
    int total = 0, with_key = 0;
    if (pEnum(h, NULL, &ifaces) == 0 && ifaces) {
        for (DWORD i = 0; i < ifaces->dwNumberOfItems; i++) {
            GUID guid = ifaces->InterfaceInfo[i].InterfaceGuid;
            char ifname[256];
            if (WideCharToMultiByte(CP_UTF8, 0, ifaces->InterfaceInfo[i].strInterfaceDescription, -1,
                                ifname, sizeof(ifname), NULL, NULL) <= 0) ifname[0] = 0;

            WLAN_PROFILE_INFO_LIST* profiles = NULL;
            if (pList(h, &guid, NULL, &profiles) != 0 || !profiles) continue;

            for (DWORD j = 0; j < profiles->dwNumberOfItems; j++) {
                DWORD flags = WLAN_PROFILE_GET_PLAINTEXT_KEY;
                DWORD granted = 0;
                wchar_t* xml = NULL;
                if (pProf(h, &guid, profiles->ProfileInfo[j].strProfileName, NULL,
                          &xml, &flags, &granted) != 0 || !xml)
                    continue;

                char ssid[256] = {0}, auth[64] = {0}, key[512] = {0};
                wifi_xml_tag(xml, "name", ssid, sizeof(ssid));
                wifi_xml_tag(xml, "authentication", auth, sizeof(auth));
                int has_key = wifi_xml_tag(xml, "keyMaterial", key, sizeof(key));

                char pname[256];
                WideCharToMultiByte(CP_UTF8, 0, profiles->ProfileInfo[j].strProfileName, -1,
                                    pname, sizeof(pname), NULL, NULL);

                sb_printf(&sb, "    ---------------------------------------------------------\n");
                sb_printf(&sb, "    [+] SSID: %s (profile: %s)\n",
                          ssid[0] ? ssid : pname, pname);
                sb_printf(&sb, "    [+] Interface: %s\n", ifname);
                if (auth[0]) sb_printf(&sb, "    [+] Auth: %s\n", auth);
                if (has_key && key[0]) {
                    sb_printf(&sb, "    [+] Password: %s\n", key);
                    with_key++;
                } else if (flags & WLAN_PROFILE_GET_PLAINTEXT_KEY) {
                    sb_printf(&sb, "    [+] Password: (open network / none)\n");
                } else {
                    sb_printf(&sb, "    [+] Password: (denied - run elevated for plaintext)\n");
                }
                total++;
                pFree(xml);
            }
            pFree(profiles);
        }
        pFree(ifaces);
    }
    pClose(h, NULL);
    FreeLibrary(wlan);

    if (total == 0) sb_printf(&sb, "  (no saved WiFi profiles found)\n");
    else sb_printf(&sb, "\n  %d profile(s), %d with password\n", total, with_key);
    return sb_str(&sb);
}
