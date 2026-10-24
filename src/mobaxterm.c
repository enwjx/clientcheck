/* MobaXterm password extraction.
 * Ported from MobaXtermDecryptor (Softwares/MobaXterm.cs + Utils/AES.cs):
 *  - no master password: custom nibble substitution cipher keyed from
 *    SessionP (extended to 20 chars, upper/lower key space)
 *  - master password: DPAPI(entropy=SessionP) unwrap -> AES key ->
 *    AES-128/256-CFB8 (Zeros padding) decrypt of the base64 blob
 * Sources merged: MobaXterm.ini ([Passwords], [Credentials]) and installer
 * registry HKCU\Software\Mobatek\MobaXterm (P, C, SessionP, M). */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <wincrypt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mobaxterm.h"
#include "browser/crypto.h"
#include "browser/utils.h"
#include "tinycrypto.h"

static char g_diag_moba[256];

#define MOBA_MAX_ENTRIES 512

/* ---------------- base64 encode ---------------- */
static void moba_b64_encode(const uint8_t* in, int len, char* out) {
    static const char* t = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int i, j = 0;
    for (i = 0; i + 2 < len; i += 3) {
        out[j++] = t[(in[i] >> 2) & 0x3F];
        out[j++] = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
        out[j++] = t[((in[i + 1] & 0xF) << 2) | (in[i + 2] >> 6)];
        out[j++] = t[in[i + 2] & 0x3F];
    }
    if (i < len) {
        out[j++] = t[(in[i] >> 2) & 0x3F];
        if (i + 1 < len) { out[j++] = t[((in[i] & 3) << 4) | (in[i + 1] >> 4)];
                           out[j++] = t[(in[i + 1] & 0xF) << 2]; }
        else out[j++] = t[(in[i] & 3) << 4];
        out[j++] = '=';
    }
    out[j] = 0;
}

/* ---------------- key derivation + nibble cipher ---------------- */
static void moba_rotate_right(uint8_t key[16]) {
    uint8_t last = key[15];
    memmove(key + 1, key, 15);
    key[0] = last;
}

static int moba_key_index(const uint8_t key[16], uint8_t c) {
    for (int i = 0; i < 16; i++)
        if (key[i] == c) return i;
    return -1;
}

static void moba_derive_key(const char* sessionp, uint8_t key[16]) {
    char sp[64];
    int sl = (int)strlen(sessionp ? sessionp : "");
    if (sl > 40) sl = 40;
    memcpy(sp, sessionp, sl);
    sp[sl] = 0;
    /* self-concatenate to at least 20 chars, truncate to 20 (C# Append
     * semantics: append a snapshot of the current content, no overlap) */
    while ((int)strlen(sp) > 0 && (int)strlen(sp) < 20) {
        int cur = (int)strlen(sp);
        int room = (int)sizeof(sp) - cur - 1;
        int copy = cur < room ? cur : room;
        if (copy <= 0) break;
        memcpy(sp + cur, sp, copy);
        sp[cur + copy] = 0;
    }
    if (!sp[0]) snprintf(sp, sizeof(sp), "20");

    memcpy(key, "0d5e9n1348/U2+67", 16);
    const char* valid = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+/";
    for (int i = 0; i < 16; i++) {
        /* C#: keySpace = {SessionP.ToUpper(), SessionP.ToLower()};
         * selector = (i+1) % 2  -> even i uses upper, odd i uses lower */
        char c = (((i + 1) % 2) == 0)
            ? (char)toupper((unsigned char)sp[i % 20])
            : (char)tolower((unsigned char)sp[i % 20]);
        if (moba_key_index(key, (uint8_t)c) < 0 && strchr(valid, c)) key[i] = (uint8_t)c;
    }
}

static int moba_decrypt_custom(const char* ct, const char* sessionp,
                               char* out, int out_sz) {
    uint8_t key[16];
    moba_derive_key(sessionp, key);
    int len = (int)strlen(ct);
    uint8_t filtered[2048];
    int fl = 0;
    for (int i = 0; i < len && fl < (int)sizeof(filtered); i++) {
        unsigned char c = (unsigned char)ct[i];
        if (c < 128 && moba_key_index(key, c) >= 0) filtered[fl++] = c;
    }
    if (fl % 2 != 0) { out[0] = 0; return -1; }
    int o = 0;
    for (int i = 0; i + 1 < fl && o < out_sz - 1; i += 2) {
        int l = moba_key_index(key, filtered[i]);
        moba_rotate_right(key);
        int h = moba_key_index(key, filtered[i + 1]);
        moba_rotate_right(key);
        if (l < 0 || h < 0) continue;
        out[o++] = (char)(uint8_t)(16 * h + l);
    }
    out[o] = 0;
    return 0;
}

/* Adaptive decryption: MobaXterm stores P/C values with the custom nibble
 * cipher (often prefixed "_@" which the cipher's character filter drops)
 * when no master password is used; values encrypted under a master password
 * are pure base64 for the DPAPI+AES-CFB8 path. The custom result is only
 * accepted when it is printable; otherwise the master path is tried. */
static int moba_decrypt_master(const char* ct_b64, const char* master_b64,
                               const char* sessionp, char* out, int out_sz);

static int moba_printable_ratio(const char* s) {
    int n = 0, ok = 0;
    for (; *s; s++) {
        if ((unsigned char)*s >= 32 && (unsigned char)*s < 127) ok++;
        n++;
    }
    if (n == 0) return 0;
    return (ok * 100) / n;
}

static int moba_decrypt_auto(const char* ct, const char* sessionp,
                             const char* master, char* out, int out_sz) {
    char custom_out[4096];
    int rc = moba_decrypt_custom(ct, sessionp, custom_out, sizeof(custom_out));
    if (rc == 0 && custom_out[0] && strlen(custom_out) >= 6 &&
        moba_printable_ratio(custom_out) >= 80) {
        snprintf(out, out_sz, "%s", custom_out);
        snprintf(g_diag_moba, sizeof(g_diag_moba), "custom cipher");
        return 0;
    }
    if (master && master[0])
        return moba_decrypt_master(ct, master, sessionp, out, out_sz);
    /* no master path or it failed: a non-printable custom result is noise,
     * never report it as a recovered password */
    snprintf(g_diag_moba, sizeof(g_diag_moba),
             rc == 0 ? "no readable result from custom cipher" : "no printable result from any path");
    out[0] = 0;
    return -1;
}

/* ---------------- master-password path (DPAPI + AES-CFB8) ---------------- */
static const uint8_t MOBA_DPAPI_HEADER[20] = {
    0x01, 0x00, 0x00, 0x00, 0xd0, 0x8c, 0x9d, 0xdf, 0x01, 0x15,
    0xd1, 0x11, 0x8c, 0x7a, 0x00, 0xc0, 0x4f, 0xc2, 0x97, 0xeb
};

/* SHA-512 via CNG (bcrypt.dll), first 32 bytes -> out.
 * key = SHA512(master_password)[:32] for MobaXterm v25+. */
static int moba_sha512_32(const char* input, int len, uint8_t out32[32]) {
    HMODULE bc = LoadLibraryA("bcrypt.dll");
    if (!bc) return -1;
    typedef void* BCRYPT_ALG_HANDLE;
    typedef void* BCRYPT_HASH_HANDLE;
    typedef LONG (WINAPI *fn_Open)(void**, wchar_t*, wchar_t*, unsigned long);
    typedef LONG (WINAPI *fn_GetProp)(void*, wchar_t*, unsigned char*, unsigned long, unsigned long*);
    typedef LONG (WINAPI *fn_CreateHash)(void*, void*, unsigned char*, unsigned long,
                                         unsigned char*, unsigned long, unsigned long);
    typedef LONG (WINAPI *fn_HashData)(BCRYPT_HASH_HANDLE, unsigned char*, unsigned long, unsigned long);
    typedef LONG (WINAPI *fn_FinishHash)(BCRYPT_HASH_HANDLE, unsigned char*, unsigned long, unsigned long);
    typedef LONG (WINAPI *fn_DestroyHash)(void*);
    typedef LONG (WINAPI *fn_CloseProv)(void*);
    fn_Open  pOpen  = (fn_Open)GetProcAddress(bc, "BCryptOpenAlgorithmProvider");
    fn_GetProp pProp = (fn_GetProp)GetProcAddress(bc, "BCryptGetProperty");
    fn_CreateHash pCreate = (fn_CreateHash)GetProcAddress(bc, "BCryptCreateHash");
    fn_HashData pHData = (fn_HashData)GetProcAddress(bc, "BCryptHashData");
    fn_FinishHash pFin = (fn_FinishHash)GetProcAddress(bc, "BCryptFinishHash");
    fn_DestroyHash pDest = (fn_DestroyHash)GetProcAddress(bc, "BCryptDestroyHash");
    fn_CloseProv pClose = (fn_CloseProv)GetProcAddress(bc, "BCryptCloseAlgorithmProvider");
    if (!pOpen || !pProp || !pCreate || !pHData || !pFin || !pDest || !pClose) {
        FreeLibrary(bc); return -1;
    }
    void* alg = NULL;
    if (pOpen(&alg, (wchar_t*)L"SHA512", NULL, 0) != 0) { FreeLibrary(bc); return -1; }
    unsigned char obj[1024];
    unsigned long obj_len = 0, cb = 0;
    if (pProp(alg, (wchar_t*)L"ObjectLength", obj, sizeof(obj), &cb) != 0) {
        pClose(alg); FreeLibrary(bc); return -1;
    }
    obj_len = *(unsigned long*)obj;
    void* hh = NULL;
    if (pCreate(alg, &hh, obj, obj_len, NULL, 0, 0) != 0) {
        pClose(alg); FreeLibrary(bc); return -1;
    }
    pHData((BCRYPT_HASH_HANDLE)hh, (unsigned char*)input, (unsigned long)len, 0);
    uint8_t digest[64];
    if (pFin((BCRYPT_HASH_HANDLE)hh, digest, 64, 0) != 0) {
        pDest(hh); pClose(alg); FreeLibrary(bc); return -1;
    }
    pDest(hh);
    pClose(alg);
    FreeLibrary(bc);
    memcpy(out32, digest, 32);
    return 0;
}

/* base64 decode with MobaXterm's altchars: '@'->'+', '_'->'/' */
static int moba_b64_decode_alt(const char* in, uint8_t* out, int out_sz) {
    char* norm = (char*)malloc(strlen(in) + 1);
    if (!norm) return -1;
    for (size_t i = 0; i <= strlen(in); i++) {
        char c = in[i];
        norm[i] = (c == '@') ? '+' : (c == '_') ? '/' : c;
    }
    int n = base64_decode(norm, out, out_sz);
    free(norm);
    return n;
}

/* Derive the AES-256 key: unwrap the master password with DPAPI
 * (entropy = SessionP), then key = SHA512(master_password)[:32]. */
/* Explicit master password supplied via -moba-master: overrides the (possibly
 * stale) registry M value. Key = SHA512(password)[:32]. */
static char g_master_pw_explicit[256] = { 0 };

void moba_set_master_password(const char* pw) {
    if (!pw) return;
    strncpy(g_master_pw_explicit, pw, sizeof(g_master_pw_explicit) - 1);
    g_master_pw_explicit[sizeof(g_master_pw_explicit) - 1] = 0;
}

static int moba_derive_master_key(const char* master_b64, const char* sessionp,
                                  uint8_t key32[32], char* mp_out, int mp_sz) {
    if (g_master_pw_explicit[0]) {
        /* direct password path: key = SHA512(password)[:32] */
        moba_sha512_32(g_master_pw_explicit, (int)strlen(g_master_pw_explicit), key32);
        if (mp_out && mp_sz > 0) {
            strncpy(mp_out, g_master_pw_explicit, (size_t)mp_sz - 1);
            mp_out[mp_sz - 1] = 0;
        }
        return 0;
    }
    uint8_t master[4096];
    int ml = base64_decode(master_b64, master, sizeof(master));
    if (ml <= 0) { snprintf(g_diag_moba, sizeof(g_diag_moba), "master b64 fail"); return -1; }

    uint8_t full[4096 + 20];
    memcpy(full, MOBA_DPAPI_HEADER, 20);
    memcpy(full + 20, master, ml);

    DATA_BLOB din, dout, dent;
    din.pbData = full;
    din.cbData = (DWORD)(20 + ml);
    dent.pbData = (BYTE*)sessionp;
    dent.cbData = (DWORD)strlen(sessionp);
    if (!CryptUnprotectData(&din, NULL, &dent, NULL, NULL, 0, &dout)) {
        snprintf(g_diag_moba, sizeof(g_diag_moba), "DPAPI fail gle=%lu", GetLastError());
        return -1;
    }
    char* mp = (char*)malloc((size_t)dout.cbData + 1);
    if (!mp) { LocalFree(dout.pbData); snprintf(g_diag_moba, sizeof(g_diag_moba), "oom"); return -1; }
    memcpy(mp, dout.pbData, (size_t)dout.cbData);
    mp[dout.cbData] = 0;
    LocalFree(dout.pbData);
    if (mp_out) snprintf(mp_out, (size_t)mp_sz, "%s", mp);
    /* mp is base64 text of the 64-byte SHA512(master_password) digest;
     * the AES key is the first 32 bytes of that DECODED digest. */
    {
        uint8_t dec[128];
        int dl = base64_decode(mp, dec, sizeof(dec));
        if (dl >= 32) {
            memcpy(key32, dec, 32);
            free(mp);
            return 0;
        }
    }
    int rc = moba_sha512_32(mp, (int)strlen(mp), key32);
    free(mp);
    return rc;
}

/* AES-256-CFB8 (ciphertext feedback, Zeros padding) */
static void moba_cfb8_decrypt(const uint8_t key[32], const uint8_t iv[16],
                              const uint8_t* ct, int ct_len, char* out, int out_sz) {
    aes_ctx a;
    aes_setkey_enc(&a, key, 256);
    uint8_t sr[16], ks[16];
    memcpy(sr, iv, 16);
    int o = 0;
    for (int i = 0; i < ct_len && o < out_sz - 1; i++) {
        aes_encrypt_block(&a, sr, ks);
        out[o] = (char)(uint8_t)(ct[i] ^ ks[0]);
        memmove(sr, sr + 1, 15);
        sr[15] = ct[i];
        o++;
    }
    out[o] = 0;
    while (o > 0 && out[o - 1] == 0) out[--o] = 0;
}

/* MobaXterm v25+/v26 (_@ prefix, random inline IV) and legacy (<v25,
 * fixed IV = AES-ECB(key, zeros16)) password decryption. */
static int moba_decrypt_master(const char* ct_b64, const char* master_b64,
                               const char* sessionp, char* out, int out_sz) {
    uint8_t key32[32];
    if (moba_derive_master_key(master_b64, sessionp, key32, NULL, 0) != 0) {
        out[0] = 0; return -1;
    }

    uint8_t body[4096];
    uint8_t iv[16];
    int bl;
    if (strncmp(ct_b64, "_@", 2) == 0) {
        /* v25+: IV = the 16 ASCII chars after "_@"; decode with altchars;
         * decoded body drops the first 15 bytes. */
        if (strlen(ct_b64) < 18) {
            snprintf(g_diag_moba, sizeof(g_diag_moba), "v25 ciphertext too short");
            out[0] = 0; return -1;
        }
        memcpy(iv, ct_b64 + 2, 16);
        bl = moba_b64_decode_alt(ct_b64, body, sizeof(body));
        if (bl < 15) {
            snprintf(g_diag_moba, sizeof(g_diag_moba), "v25 body too short bl=%d", bl);
            out[0] = 0; return -1;
        }
        if (bl == 15) {
            /* empty password: ciphertext is IV only */
            snprintf(g_diag_moba, sizeof(g_diag_moba), "empty password");
            snprintf(out, (size_t)out_sz, "(empty password)");
            return 0;
        }
        memmove(body, body + 15, (size_t)bl - 15);
        bl -= 15;
    } else {
        /* legacy <=v24: fixed IV = AES-ECB(key, 0^128); full body */
        uint8_t zeros[16] = { 0 };
        aes_ctx a;
        aes_setkey_enc(&a, key32, 256);
        aes_encrypt_block(&a, zeros, iv);
        bl = moba_b64_decode_alt(ct_b64, body, sizeof(body));
        if (bl <= 0) {
            snprintf(g_diag_moba, sizeof(g_diag_moba), "ct b64 fail len=%d", (int)strlen(ct_b64));
            out[0] = 0; return -1;
        }
    }

    char plain[4096];
    moba_cfb8_decrypt(key32, iv, body, bl, plain, sizeof(plain));
    /* trim trailing NUL/Zeros padding, keep printable prefix */
    int o = (int)strlen(plain);
    /* honest result: a wrong key yields binary noise — do not print it */
    {
        int printable = 0, total = o > 0 ? o : 1;
        for (int i = 0; i < o; i++)
            if ((unsigned char)plain[i] >= 32 && (unsigned char)plain[i] < 127) printable++;
        if (o < 1 || printable * 100 < total * 80) {
            snprintf(g_diag_moba, sizeof(g_diag_moba),
                     "not readable with stored master key (password changed?)");
            snprintf(out, (size_t)out_sz, "(unreadable with stored key)");
            return -1;
        }
    }
    snprintf(out, (size_t)out_sz, "%.*s", o, plain);
    if (o == 0) {
        snprintf(g_diag_moba, sizeof(g_diag_moba), "empty plaintext");
        return -1;
    }
    return 0;
}

/* ---------------- entry structures ---------------- */
typedef struct {
    char name[256];
    char user[256];
    char ct[2048];
} MobaCred;

typedef struct {
    char conn[256];
    char ct[2048];
} MobaPwd;

/* ---------------- INI parsing (lightweight) ---------------- */
typedef struct {
    char (*data)[2048];  /* flattened "section\0key\0value\0" segments count */
    int count;
    char* buf;
    int buf_len;
} MobaIni;

static int moba_ini_load(const char* path, char** sections_out, int* count_out) {
    FILE* f = fopen(path, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0 || sz > 32 * 1024 * 1024) { fclose(f); return -1; }
    char* text = (char*)malloc(sz + 1);
    size_t rd = fread(text, 1, sz, f);
    fclose(f);
    text[rd] = 0;

    /* flatten: for each key line emit "section\0key\0value\0" */
    int cap = 65536;
    char* flat = (char*)malloc(cap);
    int fl = 0, count = 0;
    char section[128] = {0};
    char* save = NULL;
    char* line = strtok_s(text, "\r\n", &save);
    while (line) {
        char* s = line;
        while (*s == ' ' || *s == '\t') s++;
        if (*s == '[') {
            char* e = strchr(s, ']');
            if (e) {
                size_t n = (size_t)(e - s - 1);
                if (n >= sizeof(section)) n = sizeof(section) - 1;
                memcpy(section, s + 1, n);
                section[n] = 0;
            }
        } else if (*s == ';' || *s == '#') {
            /* comment */
        } else if (*s) {
            char* eq = strchr(s, '=');
            if (eq && section[0] && fl + strlen(section) + strlen(s) + 8 < (size_t)cap) {
                *eq = 0;
                char* key = s;
                char* val = eq + 1;
                size_t slen = strlen(section), klen = strlen(key), vlen = strlen(val);
                memcpy(flat + fl, section, slen); fl += (int)slen; flat[fl++] = 0;
                memcpy(flat + fl, key, klen);     fl += (int)klen; flat[fl++] = 0;
                memcpy(flat + fl, val, vlen);     fl += (int)vlen; flat[fl++] = 0;
                count++;
            }
        }
        line = strtok_s(NULL, "\r\n", &save);
    }
    flat[fl] = 0;
    free(text);
    *sections_out = flat;
    *count_out = count;
    return 0;
}

/* find first "section/key" value */
static const char* moba_ini_get(const char* flat, const char* section, const char* key) {
    if (!flat) return NULL;
    const char* p = flat;
    while (*p) {
        const char* s = p;
        const char* k = s + strlen(s) + 1;
        const char* v = k + strlen(k) + 1;
        if (_stricmp(s, section) == 0 && _stricmp(k, key) == 0) return v;
        p = v + strlen(v) + 1;
    }
    return NULL;
}

/* iterate all key/values of one section */
typedef int (*MobaIniIter)(const char* key, const char* value, void* ctx);
static void moba_ini_iter(const char* flat, const char* section, MobaIniIter fn, void* ctx) {
    if (!flat) return;
    const char* p = flat;
    while (*p) {
        const char* s = p;
        const char* k = s + strlen(s) + 1;
        const char* v = k + strlen(k) + 1;
        if (_stricmp(s, section) == 0) fn(k, v, ctx);
        p = v + strlen(v) + 1;
    }
}

/* ---------------- collection ---------------- */
static MobaCred g_creds[MOBA_MAX_ENTRIES];
static MobaPwd g_pwds[MOBA_MAX_ENTRIES];
static int g_cred_count = 0, g_pwd_count = 0;
static char g_sessionp[256] = {0};
static char g_master[2048] = {0};
static char g_source[256] = {0};

static int collect_cred_ini(const char* key, const char* value, void* ctx) {
    (void)ctx;
    if (g_cred_count >= MOBA_MAX_ENTRIES || !value || !value[0]) return 0;
    const char* colon = strchr(value, ':');
    snprintf(g_creds[g_cred_count].name, sizeof(g_creds[g_cred_count].name), "%s", key);
    if (colon) {
        size_t ul = (size_t)(colon - value);
        if (ul >= sizeof(g_creds[g_cred_count].user)) ul = sizeof(g_creds[g_cred_count].user) - 1;
        memcpy(g_creds[g_cred_count].user, value, ul);
        g_creds[g_cred_count].user[ul] = 0;
        snprintf(g_creds[g_cred_count].ct, sizeof(g_creds[g_cred_count].ct), "%s", colon + 1);
    } else {
        g_creds[g_cred_count].user[0] = 0;
        snprintf(g_creds[g_cred_count].ct, sizeof(g_creds[g_cred_count].ct), "%s", value);
    }
    g_cred_count++;
    return 0;
}

static int collect_pwd_ini(const char* key, const char* value, void* ctx) {
    (void)ctx;
    if (g_pwd_count >= MOBA_MAX_ENTRIES || !value || !value[0]) return 0;
    snprintf(g_pwds[g_pwd_count].conn, sizeof(g_pwds[g_pwd_count].conn), "%s", key);
    snprintf(g_pwds[g_pwd_count].ct, sizeof(g_pwds[g_pwd_count].ct), "%s", value);
    g_pwd_count++;
    return 0;
}

static int moba_read_registry_source(void) {
    HKEY hroot;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Mobatek\\MobaXterm", 0, KEY_READ, &hroot) != 0)
        return -1;
    char sp[256] = {0};
    {
        DWORD sz = sizeof(sp), type = 0;
        RegQueryValueExA(hroot, "SessionP", NULL, &type, (BYTE*)sp, &sz);
    }
    if (!sp[0]) { RegCloseKey(hroot); return -1; }
    snprintf(g_sessionp, sizeof(g_sessionp), "%s", sp);
    snprintf(g_source, sizeof(g_source), "registry");

    /* master password M\<user@machine> */
    {
        char upn[128];
        char user[64] = {0}, machine[64] = {0};
        GetEnvironmentVariableA("USERNAME", user, sizeof(user));
        GetEnvironmentVariableA("COMPUTERNAME", machine, sizeof(machine));
        snprintf(upn, sizeof(upn), "%s@%s", user, machine);
        HKEY hm;
        if (RegOpenKeyExA(hroot, "M", 0, KEY_READ, &hm) == 0) {
            DWORD sz = sizeof(g_master), type = 0;
            RegQueryValueExA(hm, upn, NULL, &type, (BYTE*)g_master, &sz);
            RegCloseKey(hm);
            if (!g_master[0]) g_master[0] = 0;
        }
    }

    /* P (passwords) and C (credentials) subkeys */
    HKEY hp;
    if (RegOpenKeyExA(hroot, "P", 0, KEY_READ, &hp) == 0) {
        DWORD nvals = 0, maxlen = 0, maxdata = 0;
        if (RegQueryInfoKeyA(hp, NULL, NULL, NULL, NULL, NULL, NULL, &nvals, &maxlen, &maxdata, NULL, NULL) == 0) {
            for (DWORD i = 0; i < nvals && g_pwd_count < MOBA_MAX_ENTRIES; i++) {
                char vname[256];
                DWORD vname_sz = sizeof(vname);
                BYTE data[4096];
                DWORD data_sz = sizeof(data), type = 0;
                if (RegEnumValueA(hp, i, vname, &vname_sz, NULL, &type, data, &data_sz) != ERROR_SUCCESS)
                    continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                data[data_sz < sizeof(data) - 1 ? data_sz : sizeof(data) - 1] = 0;
                snprintf(g_pwds[g_pwd_count].conn, sizeof(g_pwds[g_pwd_count].conn), "%s", vname);
                snprintf(g_pwds[g_pwd_count].ct, sizeof(g_pwds[g_pwd_count].ct), "%s", (char*)data);
                g_pwd_count++;
            }
        }
        RegCloseKey(hp);
    }
    HKEY hc;
    if (RegOpenKeyExA(hroot, "C", 0, KEY_READ, &hc) == 0) {
        DWORD nvals = 0;
        if (RegQueryInfoKeyA(hc, NULL, NULL, NULL, NULL, NULL, NULL, &nvals, NULL, NULL, NULL, NULL) == 0) {
            for (DWORD i = 0; i < nvals && g_cred_count < MOBA_MAX_ENTRIES; i++) {
                char vname[256];
                DWORD vname_sz = sizeof(vname);
                BYTE data[4096];
                DWORD data_sz = sizeof(data), type = 0;
                if (RegEnumValueA(hc, i, vname, &vname_sz, NULL, &type, data, &data_sz) != ERROR_SUCCESS)
                    continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;
                data[data_sz < sizeof(data) - 1 ? data_sz : sizeof(data) - 1] = 0;
                char* val = (char*)data;
                snprintf(g_creds[g_cred_count].name, sizeof(g_creds[g_cred_count].name), "%s", vname);
                const char* colon = strchr(val, ':');
                if (colon) {
                    size_t ul = (size_t)(colon - val);
                    if (ul >= sizeof(g_creds[g_cred_count].user)) ul = sizeof(g_creds[g_cred_count].user) - 1;
                    memcpy(g_creds[g_cred_count].user, val, ul);
                    g_creds[g_cred_count].user[ul] = 0;
                    snprintf(g_creds[g_cred_count].ct, sizeof(g_creds[g_cred_count].ct), "%s", colon + 1);
                } else {
                    g_creds[g_cred_count].user[0] = 0;
                    snprintf(g_creds[g_cred_count].ct, sizeof(g_creds[g_cred_count].ct), "%s", val);
                }
                g_cred_count++;
            }
        }
        RegCloseKey(hc);
    }
    RegCloseKey(hroot);
    return 0;
}

static int moba_read_ini_source(const char* ini_path) {
    char* flat = NULL;
    int count = 0;
    if (moba_ini_load(ini_path, &flat, &count) != 0) return -1;
    snprintf(g_source, sizeof(g_source), "%s", ini_path);

    const char* sp = moba_ini_get(flat, "Misc", "SessionP");
    if (sp && sp[0]) snprintf(g_sessionp, sizeof(g_sessionp), "%s", sp);

    /* master password from ini [Sesspass]\<user@machine> if present */
    {
        char user[64] = {0}, machine[64] = {0};
        GetEnvironmentVariableA("USERNAME", user, sizeof(user));
        GetEnvironmentVariableA("COMPUTERNAME", machine, sizeof(machine));
        char upn[128];
        snprintf(upn, sizeof(upn), "%s@%s", user, machine);
        const char* mp = moba_ini_get(flat, "Sesspass", upn);
        if (mp && mp[0]) snprintf(g_master, sizeof(g_master), "%s", mp);
    }

    moba_ini_iter(flat, "Credentials", collect_cred_ini, NULL);
    moba_ini_iter(flat, "Passwords", collect_pwd_ini, NULL);
    free(flat);
    return 0;
}

const char* mobaxterm_scan(void) {
    static StrBuilder sb;
    sb_init(&sb);
    char uprofile[MAX_PATH];
    GetEnvironmentVariableA("USERPROFILE", uprofile, sizeof(uprofile));

    /* candidate ini paths: registry LastIniPath, Documents, Roaming */
    char ini_paths[3][MAX_PATH];
    int n_ini = 0;
    {
        char last[MAX_PATH] = {0};
        DWORD sz = sizeof(last), type = 0;
        HKEY h;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\Mobatek\\MobaXterm", 0, KEY_READ, &h) == 0) {
            RegQueryValueExA(h, "LastIniPath", NULL, &type, (BYTE*)last, &sz);
            RegCloseKey(h);
        }
        if (last[0]) snprintf(ini_paths[n_ini++], MAX_PATH, "%s", last);
        snprintf(ini_paths[n_ini++], MAX_PATH, "%s\\Documents\\MobaXterm\\MobaXterm.ini", uprofile);
        snprintf(ini_paths[n_ini++], MAX_PATH, "%s\\AppData\\Roaming\\MobaXterm\\MobaXterm.ini", uprofile);
    }

    int ini_found = -1;
    for (int i = 0; i < n_ini; i++) {
        DWORD a = GetFileAttributesA(ini_paths[i]);
        if (a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY)) {
            ini_found = i;
            break;
        }
    }

    g_sessionp[0] = 0; g_master[0] = 0;
    g_cred_count = 0; g_pwd_count = 0;
    g_source[0] = 0;

    if (ini_found >= 0)
        moba_read_ini_source(ini_paths[ini_found]);
    moba_read_registry_source();  /* always merge registry (installer P/C) */

    if (!g_sessionp[0] && g_cred_count == 0 && g_pwd_count == 0) {
        sb_printf(&sb, "MobaXterm does not exist on this machine.\n");
        return sb_str(&sb);
    }

    sb_printf(&sb, "Source: %s\n", g_source[0] ? g_source : "(unknown)");
    sb_printf(&sb, "SessionP: %s\n", g_sessionp[0] ? "(present)" : "(absent)");
    sb_printf(&sb, "Master password: %s\n", g_master[0] ? "set (DPAPI path)" : "not set (custom cipher)");

    if (g_cred_count > 0)
        sb_printf(&sb, "\n--- MobaXterm Credentials (%d) ---\n", g_cred_count);
    for (int i = 0; i < g_cred_count; i++) {
        char pw[4096];
        int rc = moba_decrypt_auto(g_creds[i].ct, g_sessionp, g_master, pw, sizeof(pw));
        sb_printf(&sb, "    ---------------------------------------------------------\n");
        sb_printf(&sb, "    [+] Name: %s\n", g_creds[i].name);
        sb_printf(&sb, "    [+] Username: %s\n", g_creds[i].user);
        if (rc == 0) sb_printf(&sb, "    [+] Password: %s\n", pw);
        else sb_printf(&sb, "    [+] Password: (decrypt failed: %s)\n", g_diag_moba);
    }

    if (g_pwd_count > 0)
        sb_printf(&sb, "\n--- MobaXterm Passwords (%d) ---\n", g_pwd_count);
    for (int i = 0; i < g_pwd_count; i++) {
        char pw[4096];
        int rc = moba_decrypt_auto(g_pwds[i].ct, g_sessionp, g_master, pw, sizeof(pw));
        sb_printf(&sb, "    ---------------------------------------------------------\n");
        sb_printf(&sb, "    [+] ConnName: %s\n", g_pwds[i].conn);
        if (rc == 0) sb_printf(&sb, "    [+] Password: %s\n", pw);
        else sb_printf(&sb, "    [+] Password: (decrypt failed: %s)\n", g_diag_moba);
    }

    if (g_cred_count == 0 && g_pwd_count == 0)
        sb_printf(&sb, "  (no saved passwords found)\n");

    return sb_str(&sb);
}
