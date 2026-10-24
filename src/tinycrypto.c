/*
 * tinycrypto.c — Self-contained crypto library
 *
 * Compact, public-domain implementations of:
 *   AES (128/192/256), AES-GCM, AES-CBC, 3DES-CBC, DES, SHA-1, SHA-256,
 *   MD5, HMAC, PBKDF2, RC4, Base64, hex decode
 *
 * Replaces all OpenSSL usage in this project. Zero external dependencies.
 */

#include "tinycrypto.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

/* ==================================================================
 * AES — FIPS-197 (T-table implementation)
 * ================================================================== */
/* forward S-box */
static const uint8_t SBOX[256] = {
    0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,
    0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,
    0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,
    0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,
    0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,
    0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,
    0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,
    0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,
    0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,
    0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,
    0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,
    0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,
    0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,
    0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,
    0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,
    0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16,
};
/* inverse S-box */
static const uint8_t RSBOX[256] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x81,0xF3,0xD7,0xFB,
    0x7C,0xE3,0x39,0x82,0x9B,0x2F,0xFF,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xEE,0x4C,0x95,0x0B,0x42,0xFA,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF8,0xF6,0x64,0x86,0x68,0x98,0x16,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFD,0xED,0xB9,0xDA,0x5E,0x15,0x46,0x57,0xA7,0x8D,0x9D,0x84,
    0x90,0xD8,0xAB,0x00,0x8C,0xBC,0xD3,0x0A,0xF7,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x0F,0x02,0xC1,0xAF,0xBD,0x03,0x01,0x13,0x8A,0x6B,
    0x3A,0x91,0x11,0x41,0x4F,0x67,0xDC,0xEA,0x97,0xF2,0xCF,0xCE,0xF0,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x85,0xE2,0xF9,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF1,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0E,0xAA,0x18,0xBE,0x1B,
    0xFC,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFE,0x78,0xCD,0x5A,0xF4,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x12,0x10,0x59,0x27,0x80,0xEC,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEF,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF5,0xB0,0xC8,0xEB,0xBB,0x3C,0x83,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x14,0x63,0x55,0x21,0x0C,0x7D,
};

static const uint8_t RCON[] = {0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1B,0x36};

static void aes_xtime(uint8_t* a) {
    uint8_t h = (uint8_t)((int8_t)(*a) >> 7);
    *a = (uint8_t)((*a << 1) ^ (h & 0x1B));
}

static void aes_add_round_key(uint8_t s[4][4], const uint32_t* rk) {
    for (int c = 0; c < 4; c++) {
        uint32_t w = rk[c];
        s[0][c] ^= (uint8_t)(w >> 24);
        s[1][c] ^= (uint8_t)(w >> 16);
        s[2][c] ^= (uint8_t)(w >> 8);
        s[3][c] ^= (uint8_t)(w);
    }
}

static void aes_sub_bytes(uint8_t s[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = SBOX[s[r][c]];
}

static void aes_inv_sub_bytes(uint8_t s[4][4]) {
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = RSBOX[s[r][c]];
}

static void aes_shift_rows(uint8_t s[4][4]) {
    uint8_t t;
    t = s[1][0]; s[1][0]=s[1][1]; s[1][1]=s[1][2]; s[1][2]=s[1][3]; s[1][3]=t;
    t = s[2][0]; s[2][0]=s[2][2]; s[2][2]=t; t = s[2][1]; s[2][1]=s[2][3]; s[2][3]=t;
    t = s[3][3]; s[3][3]=s[3][2]; s[3][2]=s[3][1]; s[3][1]=s[3][0]; s[3][0]=t;
}

static void aes_inv_shift_rows(uint8_t s[4][4]) {
    uint8_t t;
    t = s[1][3]; s[1][3]=s[1][2]; s[1][2]=s[1][1]; s[1][1]=s[1][0]; s[1][0]=t;
    t = s[2][3]; s[2][3]=s[2][1]; s[2][1]=t; t = s[2][2]; s[2][2]=s[2][0]; s[2][0]=t;
    t = s[3][0]; s[3][0]=s[3][1]; s[3][1]=s[3][2]; s[3][2]=s[3][3]; s[3][3]=t;
}

static void aes_mix_columns(uint8_t s[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a0 = s[0][c], a1 = s[1][c], a2 = s[2][c], a3 = s[3][c];
        uint8_t b0 = a0; aes_xtime(&b0); /* {02}*a0 */
        uint8_t b1 = a1; aes_xtime(&b1); /* {02}*a1 */
        uint8_t b2 = a2; aes_xtime(&b2); /* {02}*a2 */
        uint8_t b3 = a3; aes_xtime(&b3); /* {02}*a3 */
        /* {02}*a0^{03}*a1^a2^a3, etc. */
        s[0][c] = b0 ^ b1 ^ a1 ^ a2 ^ a3;
        s[1][c] = a0 ^ b1 ^ b2 ^ a2 ^ a3;
        s[2][c] = a0 ^ a1 ^ b2 ^ b3 ^ a3;
        s[3][c] = b0 ^ a0 ^ a1 ^ a2 ^ b3;
    }
}

static void aes_inv_mix_columns(uint8_t s[4][4]) {
    for (int c = 0; c < 4; c++) {
        uint8_t a[4] = {s[0][c], s[1][c], s[2][c], s[3][c]};
        uint8_t x2[4], x4[4], x8[4];
        for (int i = 0; i < 4; i++) {
            x2[i] = a[i]; aes_xtime(&x2[i]);           /* {02}*a[i] */
            x4[i] = x2[i]; aes_xtime(&x4[i]);           /* {04}*a[i] */
            x8[i] = x4[i]; aes_xtime(&x8[i]);           /* {08}*a[i] */
        }
        /* {0e}=x8^x4^x2, {0b}=x8^x2^a, {0d}=x8^x4^a, {09}=x8^a */
        s[0][c] = x8[0]^x4[0]^x2[0] ^ x8[1]^x2[1]^a[1] ^ x8[2]^x4[2]^a[2] ^ x8[3]^a[3];
        s[1][c] = x8[0]^a[0] ^ x8[1]^x4[1]^x2[1] ^ x8[2]^x2[2]^a[2] ^ x8[3]^x4[3]^a[3];
        s[2][c] = x8[0]^x4[0]^a[0] ^ x8[1]^a[1] ^ x8[2]^x4[2]^x2[2] ^ x8[3]^x2[3]^a[3];
        s[3][c] = x8[0]^x2[0]^a[0] ^ x8[1]^x4[1]^a[1] ^ x8[2]^a[2] ^ x8[3]^x4[3]^x2[3];
    }
}

void aes_setkey_enc(aes_ctx* ctx, const uint8_t* key, int bits) {
    int Nk = bits / 32, Nr;
    switch (bits) {
        case 128: Nr = 10; break;
        case 192: Nr = 12; break;
        case 256: Nr = 14; break;
        default:  return;
    }
    ctx->rounds = Nr;
    uint32_t* rk = ctx->rk;
    for (int i = 0; i < Nk; i++)
        rk[i] = ((uint32_t)key[4*i]<<24)|((uint32_t)key[4*i+1]<<16)|((uint32_t)key[4*i+2]<<8)|key[4*i+3];
    for (int i = Nk; i < 4*(Nr+1); i++) {
        uint32_t t = rk[i-1];
        if (i % Nk == 0) {
            /* SubWord(RotWord(t)) */
            t = ((uint32_t)SBOX[(t>>16)&0xFF]<<24) |
                ((uint32_t)SBOX[(t>>8)&0xFF]<<16) |
                ((uint32_t)SBOX[t&0xFF]<<8) |
                ((uint32_t)SBOX[(t>>24)&0xFF]);
            t ^= (uint32_t)RCON[i/Nk] << 24;
        } else if (Nk > 6 && i % Nk == 4) {
            t = ((uint32_t)SBOX[(t>>24)&0xFF]<<24) |
                ((uint32_t)SBOX[(t>>16)&0xFF]<<16) |
                ((uint32_t)SBOX[(t>>8)&0xFF]<<8) |
                ((uint32_t)SBOX[t&0xFF]);
        }
        rk[i] = rk[i-Nk] ^ t;
    }
}

void aes_setkey_dec(aes_ctx* ctx, const uint8_t* key, int bits) {
    /* Use same round keys as encryption — decrypt_block uses them in reverse. */
    aes_setkey_enc(ctx, key, bits);
}

void aes_encrypt_block(const aes_ctx* ctx, const uint8_t in[16], uint8_t out[16]) {
    uint8_t s[4][4];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = in[r + 4*c];
    const uint32_t* rk = ctx->rk;
    aes_add_round_key(s, rk);
    for (int round = 1; round < ctx->rounds; round++) {
        aes_sub_bytes(s);
        aes_shift_rows(s);
        aes_mix_columns(s);
        aes_add_round_key(s, rk + 4*round);
    }
    aes_sub_bytes(s);
    aes_shift_rows(s);
    aes_add_round_key(s, rk + 4*ctx->rounds);
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[r + 4*c] = s[r][c];
}

void aes_decrypt_block(const aes_ctx* ctx, const uint8_t in[16], uint8_t out[16]) {
    /* Standard AES-128/192/256 decryption per FIPS-197.
     * Uses the SAME round keys as encryption, but in REVERSE order. */
    uint8_t s[4][4];
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            s[r][c] = in[r + 4*c];
    const uint32_t* rk = ctx->rk;
    int Nr = ctx->rounds;
    /* AddRoundKey with last round key first */
    aes_add_round_key(s, rk + 4*Nr);
    for (int round = Nr - 1; round >= 1; round--) {
        aes_inv_shift_rows(s);
        aes_inv_sub_bytes(s);
        aes_add_round_key(s, rk + 4*round);
        aes_inv_mix_columns(s);
    }
    /* Final round: no InvMixColumns */
    aes_inv_shift_rows(s);
    aes_inv_sub_bytes(s);
    aes_add_round_key(s, rk);
    for (int r = 0; r < 4; r++)
        for (int c = 0; c < 4; c++)
            out[r + 4*c] = s[r][c];
}

/* ==================================================================
 * GHASH / GCM
 * ================================================================== */
static void ghash_mul(uint8_t x[16], const uint8_t y[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16]; memcpy(v, y, 16);
    for (int i = 0; i < 128; i++) {
        int byte = i / 8, bit = 7 - (i % 8);
        if (x[byte] & (1 << bit)) {
            for (int j = 0; j < 16; j++) z[j] ^= v[j];
        }
        int lsb = v[15] & 1;
        for (int j = 15; j > 0; j--)
            v[j] = (uint8_t)((v[j] >> 1) | (v[j-1] << 7));
        v[0] >>= 1;
        if (lsb) v[0] ^= 0xE1;
    }
    memcpy(x, z, 16);
}

static void gcm_inc32(uint8_t counter[16]) {
    for (int j = 15; j >= 12; j--) {
        counter[j]++;
        if (counter[j]) break;
    }
}

/* Tag mask: CTR starting at J0 (used only for the 16-byte tag block). */
static void gcm_ctr(const aes_ctx* aes, const uint8_t* iv, int iv_len, uint8_t* buf, int buf_len,
                    int inc_first) {
    uint8_t counter[16] = {0};
    if (iv_len == 12) {
        memcpy(counter, iv, 12);
        counter[15] = 1;
    } else {
        /* For non-96-bit IV: GHASH the IV */
        uint8_t j0[16] = {0};
        int pos = 0;
        while (pos < iv_len) {
            int chunk = iv_len - pos;
            if (chunk > 16) chunk = 16;
            for (int i = 0; i < chunk; i++) j0[i] ^= iv[pos + i];
            ghash_mul(j0, j0);
            pos += chunk;
        }
        /* Multiply by (len*8) */
        uint64_t bits = (uint64_t)iv_len * 8;
        uint8_t lb[16] = {0};
        lb[8] = (uint8_t)(bits >> 56); lb[9] = (uint8_t)(bits >> 48);
        lb[10] = (uint8_t)(bits >> 40); lb[11] = (uint8_t)(bits >> 32);
        lb[12] = (uint8_t)(bits >> 24); lb[13] = (uint8_t)(bits >> 16);
        lb[14] = (uint8_t)(bits >> 8); lb[15] = (uint8_t)(bits);
        for (int i = 0; i < 16; i++) j0[i] ^= lb[i];
        ghash_mul(j0, j0);
        memcpy(counter, j0, 16);
    }
    /* Standard GCM: data encryption/decryption starts at inc32(J0), only the
     * tag mask block uses J0 itself. */
    if (inc_first) gcm_inc32(counter);
    for (int i = 0; i < buf_len; i += 16) {
        int chunk = buf_len - i;
        if (chunk > 16) chunk = 16;
        uint8_t keystream[16];
        aes_encrypt_block(aes, counter, keystream);
        for (int j = 0; j < chunk; j++) buf[i+j] ^= keystream[j];
        /* Increment counter */
        for (int j = 15; j >= 0; j--) {
            counter[j]++;
            if (counter[j] != 0) break;
        }
    }
}

static void gcm_ghash(const uint8_t* hkey, const uint8_t* aad, int aad_len,
                      const uint8_t* ct, int ct_len, uint8_t tag[16]) {
    uint8_t s[16] = {0};
    /* Hash AAD */
    for (int i = 0; i < aad_len; i += 16) {
        int chunk = aad_len - i;
        if (chunk > 16) chunk = 16;
        for (int j = 0; j < chunk; j++) s[j] ^= aad[i+j];
        ghash_mul(s, hkey);
    }
    /* Hash ciphertext */
    for (int i = 0; i < ct_len; i += 16) {
        int chunk = ct_len - i;
        if (chunk > 16) chunk = 16;
        for (int j = 0; j < chunk; j++) s[j] ^= ct[i+j];
        ghash_mul(s, hkey);
    }
    /* Length block */
    uint8_t lb[16] = {0};
    uint64_t aad_bits = (uint64_t)aad_len * 8;
    uint64_t ct_bits  = (uint64_t)ct_len * 8;
    lb[0] = (uint8_t)(aad_bits >> 56); lb[1] = (uint8_t)(aad_bits >> 48);
    lb[2] = (uint8_t)(aad_bits >> 40); lb[3] = (uint8_t)(aad_bits >> 32);
    lb[4] = (uint8_t)(aad_bits >> 24); lb[5] = (uint8_t)(aad_bits >> 16);
    lb[6] = (uint8_t)(aad_bits >> 8);  lb[7] = (uint8_t)(aad_bits);
    lb[8] = (uint8_t)(ct_bits >> 56);  lb[9] = (uint8_t)(ct_bits >> 48);
    lb[10] = (uint8_t)(ct_bits >> 40); lb[11] = (uint8_t)(ct_bits >> 32);
    lb[12] = (uint8_t)(ct_bits >> 24); lb[13] = (uint8_t)(ct_bits >> 16);
    lb[14] = (uint8_t)(ct_bits >> 8);  lb[15] = (uint8_t)(ct_bits);
    for (int i = 0; i < 16; i++) s[i] ^= lb[i];
    ghash_mul(s, hkey);
    memcpy(tag, s, 16);
}

int tc_aes_gcm_encrypt(const uint8_t* key, int key_len,
                    const uint8_t* iv, int iv_len,
                    const uint8_t* aad, int aad_len,
                    const uint8_t* pt, int pt_len,
                    uint8_t* ct, uint8_t* tag, int tag_len) {
    (void)tag_len;
    if (key_len != 16 && key_len != 24 && key_len != 32) return -1;
    aes_ctx aes;
    aes_setkey_enc(&aes, key, key_len * 8);
    /* Compute hash subkey H = AES_K(0^128) */
    uint8_t H[16] = {0};
    aes_encrypt_block(&aes, H, H);
    /* Encrypt plaintext with CTR mode */
    memcpy(ct, pt, pt_len);
    gcm_ctr(&aes, iv, iv_len, ct, pt_len, 1);
    /* Compute authentication tag */
    uint8_t full_tag[16];
    gcm_ghash(H, aad, aad_len, ct, pt_len, full_tag);
    gcm_ctr(&aes, iv, iv_len, full_tag, 16, 0);
    memcpy(tag, full_tag, tag_len > 16 ? 16 : tag_len);
    return 0;
}

int tc_aes_gcm_decrypt(const uint8_t* key, int key_len,
                    const uint8_t* iv, int iv_len,
                    const uint8_t* aad, int aad_len,
                    const uint8_t* ct, int ct_len,
                    const uint8_t* tag, int tag_len,
                    uint8_t* pt) {
    if (key_len != 16 && key_len != 24 && key_len != 32) return -1;
    if (tag_len < 1 || tag_len > 16) return -1;
    aes_ctx aes;
    aes_setkey_enc(&aes, key, key_len * 8);
    /* Hash subkey */
    uint8_t H[16] = {0};
    aes_encrypt_block(&aes, H, H);
    /* Verify tag first (compute expected tag from ciphertext) */
    uint8_t expected_tag[16];
    gcm_ghash(H, aad, aad_len, ct, ct_len, expected_tag);
    gcm_ctr(&aes, iv, iv_len, expected_tag, 16, 0);
    /* Compare tags in constant time */
    uint8_t diff = 0;
    for (int i = 0; i < tag_len; i++) diff |= expected_tag[i] ^ tag[i];
    if (diff != 0) return -1;
    /* Decrypt */
    memcpy(pt, ct, ct_len);
    gcm_ctr(&aes, iv, iv_len, pt, ct_len, 1);
    return 0;
}

/* ==================================================================
 * AES-CBC (128-bit key only — matches OpenSSL EVP_aes_128_cbc)
 * ================================================================== */
static void pcks7_pad(const uint8_t* in, int in_len, int block_size,
                      uint8_t* out, int* out_len) {
    int pad = block_size - (in_len % block_size);
    memcpy(out, in, in_len);
    memset(out + in_len, pad, pad);
    *out_len = in_len + pad;
}

static int pcks7_unpad(uint8_t* data, int len, int block_size) {
    if (len < block_size || len % block_size != 0) return -1;
    int pad = data[len - 1];
    if (pad < 1 || pad > block_size) return -1;
    for (int i = len - pad; i < len; i++)
        if (data[i] != pad) return -1;
    return len - pad;
}

int tc_aes128_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* pt, int pt_len,
                       uint8_t* out, int* out_len) {
    aes_ctx aes;
    aes_setkey_enc(&aes, key, 128);
    uint8_t* padded = (uint8_t*)malloc(pt_len + 16);
    if (!padded) return -1;
    int plen;
    pcks7_pad(pt, pt_len, 16, padded, &plen);
    uint8_t cv[16]; memcpy(cv, iv, 16);
    for (int i = 0; i < plen; i += 16) {
        for (int j = 0; j < 16; j++) padded[i+j] ^= cv[j];
        aes_encrypt_block(&aes, padded + i, out + i);
        memcpy(cv, out + i, 16);
    }
    *out_len = plen;
    free(padded);
    return 0;
}

int tc_aes128_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len) {
    if (ct_len < 16 || ct_len % 16 != 0) return -1;
    aes_ctx aes;
    aes_setkey_dec(&aes, key, 128);
    uint8_t cv[16]; memcpy(cv, iv, 16);
    for (int i = 0; i < ct_len; i += 16) {
        uint8_t pt[16];
        aes_decrypt_block(&aes, ct + i, pt);
        for (int j = 0; j < 16; j++) pt[j] ^= cv[j];
        memcpy(cv, ct + i, 16);
        memcpy(out + i, pt, 16);
    }
    int unpadded = pcks7_unpad(out, ct_len, 16);
    if (unpadded < 0) return -1;
    *out_len = unpadded;
    return 0;
}

/* Raw CBC decrypt with NO padding handling. For formats that use zero
 * padding or no padding (e.g. Navicat v12) — caller trims padding itself. */
int tc_aes128_cbc_decrypt_raw(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len) {
    if (ct_len < 16 || ct_len % 16 != 0) return -1;
    aes_ctx aes;
    aes_setkey_dec(&aes, key, 128);
    uint8_t cv[16]; memcpy(cv, iv, 16);
    for (int i = 0; i < ct_len; i += 16) {
        uint8_t pt[16];
        aes_decrypt_block(&aes, ct + i, pt);
        for (int j = 0; j < 16; j++) pt[j] ^= cv[j];
        memcpy(cv, ct + i, 16);
        memcpy(out + i, pt, 16);
    }
    *out_len = ct_len;
    return 0;
}

int tc_aes256_cbc_decrypt_raw(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len) {
    if (ct_len < 16 || ct_len % 16 != 0) return -1;
    aes_ctx aes;
    aes_setkey_dec(&aes, key, 256);
    uint8_t cv[16]; memcpy(cv, iv, 16);
    for (int i = 0; i < ct_len; i += 16) {
        uint8_t pt[16];
        aes_decrypt_block(&aes, ct + i, pt);
        for (int j = 0; j < 16; j++) pt[j] ^= cv[j];
        memcpy(cv, ct + i, 16);
        memcpy(out + i, pt, 16);
    }
    *out_len = ct_len;
    return 0;
}

/* ==================================================================
 * DES (single, ECB) — for FinalShell
 * ================================================================== */
static const uint8_t DES_IP[64] = {
    58,50,42,34,26,18,10,2, 60,52,44,36,28,20,12,4,
    62,54,46,38,30,22,14,6, 64,56,48,40,32,24,16,8,
    57,49,41,33,25,17, 9,1, 59,51,43,35,27,19,11,3,
    61,53,45,37,29,21,13,5, 63,55,47,39,31,23,15,7,
};
static const uint8_t DES_FP[64] = {
    40,8,48,16,56,24,64,32, 39,7,47,15,55,23,63,31,
    38,6,46,14,54,22,62,30, 37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28, 35,3,43,11,51,19,59,27,
    34,2,42,10,50,18,58,26, 33,1,41, 9,49,17,57,25,
};
static const uint8_t DES_PC1[56] = {
    57,49,41,33,25,17, 9, 1,58,50,42,34,26,18,10, 2,59,51,43,35,27,19,11, 3,60,52,44,36,
    63,55,47,39,31,23,15, 7,62,54,46,38,30,22,14, 6,61,53,45,37,29,21,13, 5,28,20,12, 4,
};
static const uint8_t DES_PC2[48] = {
    14,17,11,24, 1, 5, 3,28,15, 6,21,10,23,19,12, 4,26, 8,16, 7,27,20,13, 2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32,
};
static const uint8_t DES_SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const uint8_t DES_E[48] = {
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32, 1,
};
static const uint8_t DES_P[32] = {
    16, 7,20,21,29,12,28,17, 1,15,23,26, 5,18,31,10,
     2, 8,24,14,32,27, 3, 9,19,13,30, 6,22,11, 4,25,
};
static const uint8_t DES_S[8][64] = {
{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11},
};

static void des_permute(const uint8_t* in, uint8_t* out, const uint8_t* table, int n) {
    memset(out, 0, (n+7)/8);
    for (int i = 0; i < n; i++) {
        int bit = table[i] - 1;
        if (in[bit/8] & (1 << (7 - bit%8)))
            out[i/8] |= (uint8_t)(1 << (7 - i%8));
    }
}

static void des_key_schedule(uint8_t k[16][6], const uint8_t key[8]) {
    uint8_t pc1[7]; des_permute(key, pc1, DES_PC1, 56);
    uint8_t C[17], D[17]; /* 28-bit halves stored in 17 bytes */
    memset(C,0,17); memset(D,0,17);
    for (int i = 0; i < 28; i++) {
        int bit = (pc1[i/8] >> (7 - i%8)) & 1;
        if (bit) C[i/8] |= (uint8_t)(1 << (7 - i%8));
    }
    for (int i = 0; i < 28; i++) {
        int bit = (pc1[(i+28)/8] >> (7 - (i+28)%8)) & 1;
        if (bit) D[i/8] |= (uint8_t)(1 << (7 - i%8));
    }
    for (int r = 0; r < 16; r++) {
        int s = DES_SHIFTS[r];
        /* Rotate left C by s bits */
        uint8_t c_carry = (uint8_t)(C[0] >> (8-s));
        for (int i = 0; i < 4; i++) C[i] = (uint8_t)((C[i] << s) | (C[i+1] >> (8-s)));
        C[3] = (uint8_t)((C[3] << s) | (c_carry >> 4)); /* only 4 bytes for 28 bits */
        uint8_t d_carry = (uint8_t)(D[0] >> (8-s));
        for (int i = 0; i < 4; i++) D[i] = (uint8_t)((D[i] << s) | (D[i+1] >> (8-s)));
        D[3] = (uint8_t)((D[3] << s) | (d_carry >> 4));
        /* Combine and apply PC2 */
        uint8_t cd[7];
        for (int i = 0; i < 4; i++) cd[i] = C[i];
        for (int i = 0; i < 4; i++) cd[i] |= (uint8_t)(D[i] >> 4);
        cd[3] = (uint8_t)((cd[3] & 0xF0) | (D[0] & 0x0F));
        for (int i = 1; i < 4; i++) cd[i+3] = (uint8_t)((D[i-1] << 4) | (D[i] >> 4));
        des_permute(cd, k[r], DES_PC2, 48);
    }
}

static void des_f(uint8_t R[4], const uint8_t k[6], uint8_t out[4]) {
    uint8_t e[6]; des_permute(R, e, DES_E, 48);
    for (int i = 0; i < 6; i++) e[i] ^= k[i];
    uint8_t s_out[4] = {0};
    for (int i = 0; i < 8; i++) {
        int row = ((e[i*6/8] >> (7 - i*6%8)) & 1) << 1;
        if (i*6%8 <= 2 && (i+1)*6 <= 8*(i*6/8+1)) {
            int bit_pos = 7 - (i*6+5)%8;
            if (bit_pos >= 0 && bit_pos < 8)
                row |= (e[i*6/8] >> bit_pos) & 1;
        } else if (i*6/8+1 < 6) {
            int idx = (i*6/8+1 < 6) ? (i*6/8+1) : 5;
            row |= (e[idx] >> (7 - (i*6+5)%8)) & 1;
        }
        int col = 0;
        for (int b = 1; b <= 4; b++) {
            int bit_pos = 7 - (i*6 + 1 + b) % 8;
            int byte_idx = (i*6 + 1 + b) / 8;
            if (byte_idx < 6 && bit_pos >= 0 && bit_pos < 8)
                col = (col << 1) | ((e[byte_idx] >> bit_pos) & 1);
        }
        uint8_t val = DES_S[i][(row << 4) | col];
        for (int b = 0; b < 4; b++)
            if (val & (1 << (3-b)))
                s_out[i/2] |= (uint8_t)(1 << (7 - (i%2)*4 - b));
    }
    des_permute(s_out, out, DES_P, 32);
}

void des_setkey(des_ctx* ctx, const uint8_t key[8]) {
    des_key_schedule(ctx->k, key);
}

void des_ecb_crypt(const des_ctx* ctx, const uint8_t in[8], uint8_t out[8], int decrypt) {
    uint8_t ip[8]; des_permute(in, ip, DES_IP, 64);
    uint8_t L[4], R[4], tmp[4];
    memcpy(L, ip, 4); memcpy(R, ip+4, 4);
    for (int r = 0; r < 16; r++) {
        memcpy(tmp, R, 4);
        int ridx = decrypt ? 15 - r : r;
        des_f(R, ctx->k[ridx], R); /* R = f(old_R, k) */
        for (int i = 0; i < 4; i++) R[i] ^= L[i];
        memcpy(L, tmp, 4);
    }
    /* Swap: output = R|L */
    uint8_t pre[8];
    memcpy(pre, R, 4); memcpy(pre+4, L, 4);
    des_permute(pre, out, DES_FP, 64);
}

/* ==================================================================
 * 3DES (DES-EDE3-CBC)
 * ================================================================== */
int tc_des3_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                     const uint8_t* ct, int ct_len,
                     uint8_t* out, int* out_len) {
    if (ct_len < 8 || ct_len % 8 != 0) return -1;
    des_ctx ctx1, ctx2, ctx3;
    des_setkey(&ctx1, key);
    des_setkey(&ctx2, key + 8);
    des_setkey(&ctx3, key + 16);
    uint8_t cv[8]; memcpy(cv, iv, 8);
    for (int i = 0; i < ct_len; i += 8) {
        uint8_t dec[8], pt[8];
        des_ecb_crypt(&ctx3, ct + i, dec, 1);
        des_ecb_crypt(&ctx2, dec, dec, 0);
        des_ecb_crypt(&ctx1, dec, dec, 1);
        for (int j = 0; j < 8; j++) pt[j] = (uint8_t)(dec[j] ^ cv[j]);
        memcpy(cv, ct + i, 8);
        memcpy(out + i, pt, 8);
    }
    int unpadded = pcks7_unpad(out, ct_len, 8);
    if (unpadded < 0) return -1;
    *out_len = unpadded;
    return 0;
}

int tc_des3_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                     const uint8_t* pt, int pt_len,
                     uint8_t* out, int* out_len) {
    des_ctx ctx1, ctx2, ctx3;
    des_setkey(&ctx1, key);
    des_setkey(&ctx2, key + 8);
    des_setkey(&ctx3, key + 16);
    uint8_t* padded = (uint8_t*)malloc(pt_len + 8);
    if (!padded) return -1;
    int plen;
    pcks7_pad(pt, pt_len, 8, padded, &plen);
    uint8_t cv[8]; memcpy(cv, iv, 8);
    for (int i = 0; i < plen; i += 8) {
        for (int j = 0; j < 8; j++) padded[i+j] ^= cv[j];
        uint8_t enc[8];
        des_ecb_crypt(&ctx1, padded + i, enc, 0);
        des_ecb_crypt(&ctx2, enc, enc, 1);
        des_ecb_crypt(&ctx3, enc, enc, 0);
        memcpy(out + i, enc, 8);
        memcpy(cv, enc, 8);
    }
    *out_len = plen;
    free(padded);
    return 0;
}

/* ==================================================================
 * SHA-1
 * ================================================================== */
#define SHA_ROR32(v,n) (((v)>>(n))|((v)<<(32-(n))))

void sha1_init(sha1_ctx* c) {
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE;
    c->h[3]=0x10325476; c->h[4]=0xC3D2E1F0;
    c->total=0; c->buf_idx=0;
}

/* Process one 64-byte block: sha1_update helper */
static void sha1_block(sha1_ctx* c, const uint8_t block[64]) {
    uint32_t w[80];
    for (int i = 0; i < 16; i++)
        w[i] = ((uint32_t)block[i*4]<<24)|((uint32_t)block[i*4+1]<<16)|
               ((uint32_t)block[i*4+2]<<8)|block[i*4+3];
    for (int i = 16; i < 80; i++) {
        uint32_t x = w[i-3]^w[i-8]^w[i-14]^w[i-16];
        w[i] = (x << 1) | (x >> 31);  /* ROTL(x, 1) per FIPS 180-4 */
    }
    uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4];
    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i<20)      { f=(b&cc)|(~b&d); k=0x5A827999; }
        else if (i<40) { f=b^cc^d;        k=0x6ED9EBA1; }
        else if (i<60) { f=(b&cc)|(b&d)|(cc&d); k=0x8F1BBCDC; }
        else           { f=b^cc^d;        k=0xCA62C1D6; }
        uint32_t t = ((a << 5) | (a >> 27)) + f + e + k + w[i];
        e=d; d=cc; cc=((b << 30) | (b >> 2)); b=a; a=t;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; c->h[4]+=e;
}

void sha1_update(sha1_ctx* c, const uint8_t* data, int len) {
    c->total += (uint64_t)len;
    while (len > 0) {
        int space = 64 - c->buf_idx;
        int chunk = len < space ? len : space;
        memcpy(c->buf + c->buf_idx, data, chunk);
        c->buf_idx += chunk; data += chunk; len -= chunk;
        if (c->buf_idx == 64) {
            sha1_block(c, c->buf);
            c->buf_idx = 0;
        }
    }
}

void sha1_final(sha1_ctx* c, uint8_t out[20]) {
    uint64_t bits = c->total * 8;
    c->buf[c->buf_idx++] = 0x80;
    if (c->buf_idx > 56) {
        memset(c->buf + c->buf_idx, 0, 64 - c->buf_idx);
        sha1_block(c, c->buf);
        c->buf_idx = 0;
    }
    memset(c->buf + c->buf_idx, 0, 56 - c->buf_idx);
    for (int i = 0; i < 8; i++)
        c->buf[56+i] = (uint8_t)(bits >> (56 - i*8));
    sha1_block(c, c->buf);
    for (int i = 0; i < 5; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

void tc_sha1_hash(const uint8_t* data, int len, uint8_t out[20]) {
    sha1_ctx c; sha1_init(&c); sha1_update(&c, data, len); sha1_final(&c, out);
}

/* ==================================================================
 * SHA-256
 * ================================================================== */
static const uint32_t SHA256_K[64] = {
    0x428A2F98,0x71374491,0xB5C0FBCF,0xE9B5DBA5,0x3956C25B,0x59F111F1,0x923F82A4,0xAB1C5ED5,
    0xD807AA98,0x12835B01,0x243185BE,0x550C7DC3,0x72BE5D74,0x80DEB1FE,0x9BDC06A7,0xC19BF174,
    0xE49B69C1,0xEFBE4786,0x0FC19DC6,0x240CA1CC,0x2DE92C6F,0x4A7484AA,0x5CB0A9DC,0x76F988DA,
    0x983E5152,0xA831C66D,0xB00327C8,0xBF597FC7,0xC6E00BF3,0xD5A79147,0x06CA6351,0x14292967,
    0x27B70A85,0x2E1B2138,0x4D2C6DFC,0x53380D13,0x650A7354,0x766A0ABB,0x81C2C92E,0x92722C85,
    0xA2BFE8A1,0xA81A664B,0xC24B8B70,0xC76C51A3,0xD192E819,0xD6990624,0xF40E3585,0x106AA070,
    0x19A4C116,0x1E376C08,0x2748774C,0x34B0BCB5,0x391C0CB3,0x4ED8AA4A,0x5B9CCA4F,0x682E6FF3,
    0x748F82EE,0x78A5636F,0x84C87814,0x8CC70208,0x90BEFFFA,0xA4506CEB,0xBEF9A3F7,0xC67178F2,
};

void sha256_init(sha256_ctx* c) {
    c->h[0]=0x6A09E667; c->h[1]=0xBB67AE85; c->h[2]=0x3C6EF372; c->h[3]=0xA54FF53A;
    c->h[4]=0x510E527F; c->h[5]=0x9B05688C; c->h[6]=0x1F83D9AB; c->h[7]=0x5BE0CD19;
    c->total=0; c->buf_idx=0;
}

void sha256_update(sha256_ctx* c, const uint8_t* data, int len) {
    c->total += (uint64_t)len;
    while (len > 0) {
        int space = 64 - c->buf_idx;
        int chunk = len < space ? len : space;
        memcpy(c->buf + c->buf_idx, data, chunk);
        c->buf_idx += chunk; data += chunk; len -= chunk;
        if (c->buf_idx == 64) {
            for (int i = 0; i < 16; i++)
                c->w[i] = ((uint32_t)c->buf[i*4]<<24)|((uint32_t)c->buf[i*4+1]<<16)|
                          ((uint32_t)c->buf[i*4+2]<<8)|c->buf[i*4+3];
            for (int i = 16; i < 64; i++) {
                uint32_t s0 = SHA_ROR32(c->w[i-15],7)^SHA_ROR32(c->w[i-15],18)^(c->w[i-15]>>3);
                uint32_t s1 = SHA_ROR32(c->w[i-2],17)^SHA_ROR32(c->w[i-2],19)^(c->w[i-2]>>10);
                c->w[i] = c->w[i-16] + s0 + c->w[i-7] + s1;
            }
            uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4], f=c->h[5], g=c->h[6], h=c->h[7];
            for (int i = 0; i < 64; i++) {
                uint32_t S1 = SHA_ROR32(e,6)^SHA_ROR32(e,11)^SHA_ROR32(e,25);
                uint32_t ch = (e&f)^(~e&g);
                uint32_t t1 = h + S1 + ch + SHA256_K[i] + c->w[i];
                uint32_t S0 = SHA_ROR32(a,2)^SHA_ROR32(a,13)^SHA_ROR32(a,22);
                uint32_t maj = (a&b)^(a&cc)^(b&cc);
                uint32_t t2 = S0 + maj;
                h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
            }
            c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
            c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h;
            c->buf_idx=0;
        }
    }
}

void sha256_final(sha256_ctx* c, uint8_t out[32]) {
    uint64_t bits = c->total * 8;
    c->buf[c->buf_idx++] = 0x80;
    if (c->buf_idx > 56) {
        memset(c->buf + c->buf_idx, 0, 64 - c->buf_idx);
        /* Process full block directly */
        for (int i = 0; i < 16; i++)
            c->w[i] = ((uint32_t)c->buf[i*4]<<24)|((uint32_t)c->buf[i*4+1]<<16)|
                      ((uint32_t)c->buf[i*4+2]<<8)|c->buf[i*4+3];
        for (int i = 16; i < 64; i++) {
            uint32_t s0 = SHA_ROR32(c->w[i-15],7)^SHA_ROR32(c->w[i-15],18)^(c->w[i-15]>>3);
            uint32_t s1 = SHA_ROR32(c->w[i-2],17)^SHA_ROR32(c->w[i-2],19)^(c->w[i-2]>>10);
            c->w[i] = c->w[i-16] + s0 + c->w[i-7] + s1;
        }
        { uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4], f=c->h[5], g=c->h[6], h=c->h[7];
        for (int i = 0; i < 64; i++) {
            uint32_t S1 = SHA_ROR32(e,6)^SHA_ROR32(e,11)^SHA_ROR32(e,25);
            uint32_t ch = (e&f)^(~e&g);
            uint32_t t1 = h + S1 + ch + SHA256_K[i] + c->w[i];
            uint32_t S0 = SHA_ROR32(a,2)^SHA_ROR32(a,13)^SHA_ROR32(a,22);
            uint32_t maj = (a&b)^(a&cc)^(b&cc);
            uint32_t t2 = S0 + maj;
            h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
        }
        c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
        c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h; }
        c->buf_idx = 0;
    }
    memset(c->buf + c->buf_idx, 0, 56 - c->buf_idx);
    for (int i = 0; i < 8; i++)
        c->buf[56+i] = (uint8_t)(bits >> (56 - i*8));
    /* Process final block */
    for (int i = 0; i < 16; i++)
        c->w[i] = ((uint32_t)c->buf[i*4]<<24)|((uint32_t)c->buf[i*4+1]<<16)|
                  ((uint32_t)c->buf[i*4+2]<<8)|c->buf[i*4+3];
    for (int i = 16; i < 64; i++) {
        uint32_t s0 = SHA_ROR32(c->w[i-15],7)^SHA_ROR32(c->w[i-15],18)^(c->w[i-15]>>3);
        uint32_t s1 = SHA_ROR32(c->w[i-2],17)^SHA_ROR32(c->w[i-2],19)^(c->w[i-2]>>10);
        c->w[i] = c->w[i-16] + s0 + c->w[i-7] + s1;
    }
    { uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3], e=c->h[4], f=c->h[5], g=c->h[6], h=c->h[7];
    for (int i = 0; i < 64; i++) {
        uint32_t S1 = SHA_ROR32(e,6)^SHA_ROR32(e,11)^SHA_ROR32(e,25);
        uint32_t ch = (e&f)^(~e&g);
        uint32_t t1 = h + S1 + ch + SHA256_K[i] + c->w[i];
        uint32_t S0 = SHA_ROR32(a,2)^SHA_ROR32(a,13)^SHA_ROR32(a,22);
        uint32_t maj = (a&b)^(a&cc)^(b&cc);
        uint32_t t2 = S0 + maj;
        h=g; g=f; f=e; e=d+t1; d=cc; cc=b; b=a; a=t1+t2;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
    c->h[4]+=e; c->h[5]+=f; c->h[6]+=g; c->h[7]+=h; }
    for (int i = 0; i < 8; i++) {
        out[i*4]   = (uint8_t)(c->h[i] >> 24);
        out[i*4+1] = (uint8_t)(c->h[i] >> 16);
        out[i*4+2] = (uint8_t)(c->h[i] >> 8);
        out[i*4+3] = (uint8_t)(c->h[i]);
    }
}

void tc_sha256_hash(const uint8_t* data, int len, uint8_t out[32]) {
    sha256_ctx c; sha256_init(&c); sha256_update(&c, data, len); sha256_final(&c, out);
}

/* ==================================================================
 * MD5
 * ================================================================== */
#define MD5_F(x,y,z) (((x)&(y))|(~(x)&(z)))
#define MD5_G(x,y,z) (((x)&(z))|((y)&~(z)))
#define MD5_H(x,y,z) ((x)^(y)^(z))
#define MD5_I(x,y,z) ((y)^((x)|~(z)))
#define MD5_ROL32(v,n) (((v)<<(n))|((v)>>(32-(n))))

static const uint32_t MD5_S[64] = {
    7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
    5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
    4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
    6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21,
};
static const uint32_t MD5_T[64] = {
    0xD76AA478,0xE8C7B756,0x242070DB,0xC1BDCEEE,0xF57C0FAF,0x4787C62A,0xA8304613,0xFD469501,
    0x698098D8,0x8B44F7AF,0xFFFF5BB1,0x895CD7BE,0x6B901122,0xFD987193,0xA679438E,0x49B40821,
    0xF61E2562,0xC040B340,0x265E5A51,0xE9B6C7AA,0xD62F105D,0x02441453,0xD8A1E681,0xE7D3FBC8,
    0x21E1CDE6,0xC33707D6,0xF4D50D87,0x455A14ED,0xA9E3E905,0xFCEFA3F8,0x676F02D9,0x8D2A4C8A,
    0xFFFA3942,0x8771F681,0x6D9D6122,0xFDE5380C,0xA4BEEA44,0x4BDECFA9,0xF6BB4B60,0xBEBFBC70,
    0x289B7EC6,0xEAA127FA,0xD4EF3085,0x04881D05,0xD9D4D039,0xE6DB99E5,0x1FA27CF8,0xC4AC5665,
    0xF4292244,0x432AFF97,0xAB9423A7,0xFC93A039,0x655B59C3,0x8F0CCC92,0xFFEFF47D,0x85845DD1,
    0x6FA87E4F,0xFE2CE6E0,0xA3014314,0x4E0811A1,0xF7537E82,0xBD3AF235,0x2AD7D2BB,0xEB86D391,
};

void md5_init(md5_ctx* c) {
    c->h[0]=0x67452301; c->h[1]=0xEFCDAB89; c->h[2]=0x98BADCFE; c->h[3]=0x10325476;
    c->total=0; c->buf_idx=0;
}

void md5_update(md5_ctx* c, const uint8_t* data, int len) {
    c->total += (uint64_t)len;
    while (len > 0) {
        int space = 64 - c->buf_idx;
        int chunk = len < space ? len : space;
        memcpy(c->buf + c->buf_idx, data, chunk);
        c->buf_idx += chunk; data += chunk; len -= chunk;
        if (c->buf_idx == 64) {
            for (int i = 0; i < 16; i++)
                c->w[i] = (uint32_t)c->buf[i*4]|((uint32_t)c->buf[i*4+1]<<8)|
                          ((uint32_t)c->buf[i*4+2]<<16)|((uint32_t)c->buf[i*4+3]<<24);
            uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3];
            for (int i = 0; i < 64; i++) {
                uint32_t f; int g;
                if (i<16)      { f=MD5_F(b,cc,d); g=i; }
                else if (i<32) { f=MD5_G(b,cc,d); g=(5*i+1)%16; }
                else if (i<48) { f=MD5_H(b,cc,d); g=(3*i+5)%16; }
                else           { f=MD5_I(b,cc,d); g=(7*i)%16; }
                uint32_t t = d;
                d = cc;
                cc = b;
                b = b + MD5_ROL32(a + f + MD5_T[i] + c->w[g], MD5_S[i]);
                a = t;
            }
            c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
            c->buf_idx=0;
        }
    }
}

void md5_final(md5_ctx* c, uint8_t out[16]) {
    uint64_t bits = c->total * 8;
    c->buf[c->buf_idx++] = 0x80;
    if (c->buf_idx > 56) {
        memset(c->buf + c->buf_idx, 0, 64 - c->buf_idx);
        /* Process full block directly */
        for (int i = 0; i < 16; i++)
            c->w[i] = (uint32_t)c->buf[i*4]|((uint32_t)c->buf[i*4+1]<<8)|
                      ((uint32_t)c->buf[i*4+2]<<16)|((uint32_t)c->buf[i*4+3]<<24);
        uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3];
        for (int i = 0; i < 64; i++) {
            uint32_t f; int g;
            if (i<16)      { f=MD5_F(b,cc,d); g=i; }
            else if (i<32) { f=MD5_G(b,cc,d); g=(5*i+1)%16; }
            else if (i<48) { f=MD5_H(b,cc,d); g=(3*i+5)%16; }
            else           { f=MD5_I(b,cc,d); g=(7*i)%16; }
            uint32_t t = d; d = cc; cc = b;
            b = b + MD5_ROL32(a + f + MD5_T[i] + c->w[g], MD5_S[i]); a = t;
        }
        c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d;
        c->buf_idx = 0;
    }
    memset(c->buf + c->buf_idx, 0, 56 - c->buf_idx);
    for (int i = 0; i < 8; i++)
        c->buf[56+i] = (uint8_t)(bits >> (i*8));
    /* Process final block */
    for (int i = 0; i < 16; i++)
        c->w[i] = (uint32_t)c->buf[i*4]|((uint32_t)c->buf[i*4+1]<<8)|
                  ((uint32_t)c->buf[i*4+2]<<16)|((uint32_t)c->buf[i*4+3]<<24);
    { uint32_t a=c->h[0], b=c->h[1], cc=c->h[2], d=c->h[3];
    for (int i = 0; i < 64; i++) {
        uint32_t f; int g;
        if (i<16)      { f=MD5_F(b,cc,d); g=i; }
        else if (i<32) { f=MD5_G(b,cc,d); g=(5*i+1)%16; }
        else if (i<48) { f=MD5_H(b,cc,d); g=(3*i+5)%16; }
        else           { f=MD5_I(b,cc,d); g=(7*i)%16; }
        uint32_t t = d; d = cc; cc = b;
        b = b + MD5_ROL32(a + f + MD5_T[i] + c->w[g], MD5_S[i]); a = t;
    }
    c->h[0]+=a; c->h[1]+=b; c->h[2]+=cc; c->h[3]+=d; }
    for (int i = 0; i < 4; i++) {
        out[i*4]   = (uint8_t)(c->h[i]);
        out[i*4+1] = (uint8_t)(c->h[i] >> 8);
        out[i*4+2] = (uint8_t)(c->h[i] >> 16);
        out[i*4+3] = (uint8_t)(c->h[i] >> 24);
    }
}

void tc_md5_hash(const uint8_t* data, int len, uint8_t out[16]) {
    md5_ctx c; md5_init(&c); md5_update(&c, data, len); md5_final(&c, out);
}

/* ==================================================================
 * HMAC + PBKDF2
 * ================================================================== */
static void hmac_sha1(const uint8_t* key, int key_len,
                      const uint8_t* msg, int msg_len,
                      uint8_t mac[20]) {
    uint8_t ikey[64], okey[64];
    uint8_t tk[20];
    if (key_len > 64) { tc_sha1_hash(key, key_len, tk); key=tk; key_len=20; }
    memset(ikey, 0x36, 64); memset(okey, 0x5C, 64);
    for (int i = 0; i < key_len; i++) { ikey[i] ^= key[i]; okey[i] ^= key[i]; }
    sha1_ctx c;
    uint8_t ihash[20];
    sha1_init(&c); sha1_update(&c, ikey, 64); sha1_update(&c, msg, msg_len); sha1_final(&c, ihash);
    sha1_init(&c); sha1_update(&c, okey, 64); sha1_update(&c, ihash, 20); sha1_final(&c, mac);
}

static void hmac_sha256(const uint8_t* key, int key_len,
                        const uint8_t* msg, int msg_len,
                        uint8_t mac[32]) {
    uint8_t ikey[64], okey[64];
    uint8_t tk[32];
    if (key_len > 64) { tc_sha256_hash(key, key_len, tk); key=tk; key_len=32; }
    memset(ikey, 0x36, 64); memset(okey, 0x5C, 64);
    for (int i = 0; i < key_len; i++) { ikey[i] ^= key[i]; okey[i] ^= key[i]; }
    sha256_ctx c;
    uint8_t ihash[32];
    sha256_init(&c); sha256_update(&c, ikey, 64); sha256_update(&c, msg, msg_len); sha256_final(&c, ihash);
    sha256_init(&c); sha256_update(&c, okey, 64); sha256_update(&c, ihash, 32); sha256_final(&c, mac);
}

void tc_hmac_sha1(const uint8_t* key, int key_len,
                  const uint8_t* msg, int msg_len,
                  uint8_t mac[20]) {
    hmac_sha1(key, key_len, msg, msg_len, mac);
}

int pbkdf2_hmac_sha1(const uint8_t* pass, int pass_len,
                     const uint8_t* salt, int salt_len,
                     int iterations, int dk_len, uint8_t* dk) {
    if (iterations < 1) return -1;
    int hlen = 20, blocks = (dk_len + hlen - 1) / hlen;
    for (int b = 1; b <= blocks; b++) {
        uint8_t u[20], t[20] = {0};
        uint8_t sb[520]; /* salt + 4 bytes */
        memcpy(sb, salt, salt_len);
        sb[salt_len]   = (uint8_t)(b >> 24);
        sb[salt_len+1] = (uint8_t)(b >> 16);
        sb[salt_len+2] = (uint8_t)(b >> 8);
        sb[salt_len+3] = (uint8_t)(b);
        hmac_sha1(pass, pass_len, sb, salt_len + 4, u);
        for (int i = 0; i < hlen; i++) t[i] = u[i];
        for (int iter = 1; iter < iterations; iter++) {
            hmac_sha1(pass, pass_len, u, hlen, u);
            for (int i = 0; i < hlen; i++) t[i] ^= u[i];
        }
        int copy = (b < blocks || dk_len % hlen == 0) ? hlen : dk_len % hlen;
        memcpy(dk + (b-1)*hlen, t, copy);
    }
    return 0;
}

int pbkdf2_hmac_sha256(const uint8_t* pass, int pass_len,
                       const uint8_t* salt, int salt_len,
                       int iterations, int dk_len, uint8_t* dk) {
    if (iterations < 1) return -1;
    int hlen = 32, blocks = (dk_len + hlen - 1) / hlen;
    for (int b = 1; b <= blocks; b++) {
        uint8_t u[32], t[32] = {0};
        uint8_t sb[520];
        memcpy(sb, salt, salt_len);
        sb[salt_len]   = (uint8_t)(b >> 24);
        sb[salt_len+1] = (uint8_t)(b >> 16);
        sb[salt_len+2] = (uint8_t)(b >> 8);
        sb[salt_len+3] = (uint8_t)(b);
        hmac_sha256(pass, pass_len, sb, salt_len + 4, u);
        for (int i = 0; i < hlen; i++) t[i] = u[i];
        for (int iter = 1; iter < iterations; iter++) {
            hmac_sha256(pass, pass_len, u, hlen, u);
            for (int i = 0; i < hlen; i++) t[i] ^= u[i];
        }
        int copy = (b < blocks || dk_len % hlen == 0) ? hlen : dk_len % hlen;
        memcpy(dk + (b-1)*hlen, t, copy);
    }
    return 0;
}

/* ==================================================================
 * RC4
 * ================================================================== */
void tc_rc4_crypt(const uint8_t* key, int key_len,
               const uint8_t* in, int in_len, uint8_t* out) {
    uint8_t S[256]; int i=0, j=0;
    for (i=0;i<256;i++) S[i]=(uint8_t)i;
    for (i=0;i<256;i++) { j=(j+S[i]+key[i%key_len])&0xFF; uint8_t t=S[i]; S[i]=S[j]; S[j]=t; }
    i=j=0;
    for (int k=0;k<in_len;k++) { i=(i+1)&0xFF; j=(j+S[i])&0xFF; uint8_t t=S[i]; S[i]=S[j]; S[j]=t; out[k]=(uint8_t)(in[k]^S[(S[i]+S[j])&0xFF]); }
}

/* ==================================================================
 * Base64
 * ================================================================== */
static const char B64_ENC[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

int tc_base64_encode(const uint8_t* in, int in_len, char* out) {
    int pos = 0;
    for (int i = 0; i < in_len; i += 3) {
        uint32_t v = (uint32_t)in[i] << 16;
        if (i+1 < in_len) v |= (uint32_t)in[i+1] << 8;
        if (i+2 < in_len) v |= in[i+2];
        out[pos++] = B64_ENC[(v>>18)&0x3F];
        out[pos++] = B64_ENC[(v>>12)&0x3F];
        out[pos++] = (i+1 < in_len) ? B64_ENC[(v>>6)&0x3F] : '=';
        out[pos++] = (i+2 < in_len) ? B64_ENC[v&0x3F] : '=';
    }
    out[pos] = '\0';
    return pos;
}

int tc_base64_decode(const char* in, uint8_t* out, int out_size) {
    static const uint8_t dec[128] = {
        0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0, 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
        0,0,0,0,0,0,0,0,0,0,0,62,0,0,0,63, 52,53,54,55,56,57,58,59,60,61,0,0,0,0,0,0,
        0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9,10,11,12,13,14, 15,16,17,18,19,20,21,22,23,24,25,0,0,0,0,0,
        0,26,27,28,29,30,31,32,33,34,35,36,37,38,39,40, 41,42,43,44,45,46,47,48,49,50,51,0,0,0,0,0,
    };
    int pos = 0, len = (int)strlen(in);
    for (int i = 0; i < len; i += 4) {
        if (in[i] == '=' || pos >= out_size) break;
        int ndata = 0;
        uint32_t v = 0;
        for (int j = 0; j < 4 && i+j < len && in[i+j] != '='; j++) {
            v = (v << 6) | dec[(int)(unsigned char)in[i+j]];
            ndata++;
        }
        /* ndata=4:3bytes(v>>16,(v>>8)&0xff,v&0xff) ndata=3:2bytes(v>>10,(v>>2)&0xff) ndata=2:1byte(v>>4) */
        if (ndata >= 2) out[pos++] = (uint8_t)(v >> (ndata*6 - 8));
        if (ndata >= 3) out[pos++] = (uint8_t)(v >> (ndata*6 - 16));
        if (ndata >= 4) out[pos++] = (uint8_t)(v);
    }
    return pos;
}

/* ==================================================================
 * Hex decode
 * ================================================================== */
int tc_hex_decode(const char* hex, uint8_t* out, int out_size) {
    int len = (int)strlen(hex);
    if (len % 2 != 0) return -1;
    int n = len / 2;
    if (n > out_size) return -1;
    for (int i = 0; i < n; i++) {
        char hi = hex[i*2], lo = hex[i*2+1];
        int vh = (hi>='0'&&hi<='9')?hi-'0':(hi>='a'&&hi<='f')?hi-'a'+10:(hi>='A'&&hi<='F')?hi-'A'+10:-1;
        int vl = (lo>='0'&&lo<='9')?lo-'0':(lo>='a'&&lo<='f')?lo-'a'+10:(lo>='A'&&lo<='F')?lo-'A'+10:-1;
        if (vh<0||vl<0) return -1;
        out[i] = (uint8_t)((vh<<4)|vl);
    }
    return n;
}

/* ==================================================================
 * File read
 * ================================================================== */
uint8_t* tc_read_file(const char* path, int* out_len) {
    FILE* f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return NULL; }
    uint8_t* buf = (uint8_t*)malloc(sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, sz, f) != (size_t)sz) { free(buf); fclose(f); return NULL; }
    buf[sz] = '\0';
    fclose(f);
    *out_len = (int)sz;
    return buf;
}

/* ==================================================================
 * Self-tests — validates crypto primitives against known vectors
 * ================================================================== */
#include <stdio.h>
static int g_tc_self_test_ok = 0;

int tc_self_test(void) {
    if (g_tc_self_test_ok) return 0;
    int failures = 0;

    /* ---- AES-128 encrypt/decrypt roundtrip ---- */
    {
        uint8_t key[16] = {0x2b,0x7e,0x15,0x16,0x28,0xae,0xd2,0xa6,
                           0xab,0xf7,0x15,0x88,0x09,0xcf,0x4f,0x3c};
        uint8_t pt[16]  = {0x32,0x43,0xf6,0xa8,0x88,0x5a,0x30,0x8d,
                           0x31,0x31,0x98,0xa2,0xe0,0x37,0x07,0x34};
        uint8_t expected_ct[16] = {0x39,0x25,0x84,0x1d,0x02,0xdc,0x09,0xfb,
                                   0xdc,0x11,0x85,0x97,0x19,0x6a,0x0b,0x32};
        aes_ctx ctx;
        uint8_t ct[16], rt[16];

        /* First: simple roundtrip with a basic key */
        {
            uint8_t k2[16] = {0};
            uint8_t p2[16] = {0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
                              0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10};
            uint8_t c2[16], r2[16];
            aes_setkey_enc(&ctx, k2, 128);
            aes_encrypt_block(&ctx, p2, c2);
            aes_setkey_dec(&ctx, k2, 128);
            aes_decrypt_block(&ctx, c2, r2);
            if (memcmp(r2, p2, 16) != 0) {
                fprintf(stderr, "[!] AES roundtrip FAILED with zero key\n");
                fprintf(stderr, "  pt: ");
                for(int i=0;i<16;i++) fprintf(stderr, "%02x", p2[i]);
                fprintf(stderr, "\n  rt: ");
                for(int i=0;i<16;i++) fprintf(stderr, "%02x", r2[i]);
                fprintf(stderr, "\n");
                failures++;
            }
        }

        /* FIPS-197 test vector */
        aes_setkey_enc(&ctx, key, 128);
        aes_encrypt_block(&ctx, pt, ct);
        if (memcmp(ct, expected_ct, 16) != 0) {
            fprintf(stderr, "[!] AES-128 encrypt FAILED\n");
            failures++;
        }
        aes_setkey_dec(&ctx, key, 128);
        aes_decrypt_block(&ctx, ct, rt);
        if (memcmp(rt, pt, 16) != 0) {
            fprintf(stderr, "[!] AES-128 decrypt FAILED\n");
            fprintf(stderr, "  got back: ");
            for(int i=0;i<16;i++) fprintf(stderr, "%02x", rt[i]);
            fprintf(stderr, "\n  original: ");
            for(int i=0;i<16;i++) fprintf(stderr, "%02x", pt[i]);
            fprintf(stderr, "\n");
            failures++;
        }
    }

    /* ---- AES-CBC decrypt ---- */
    {
        uint8_t key[16] = "libcckeylibcckey";
        uint8_t iv[16]  = "libcciv libcciv ";
        /* Encrypt "test1234" with PKCS7 padding = 16 bytes */
        uint8_t ct[16]; int ct_len;
        int ret = tc_aes128_cbc_encrypt(key, iv, (uint8_t*)"test1234", 8, ct, &ct_len);
        if (ret != 0 || ct_len != 16) {
            fprintf(stderr, "[!] AES-CBC encrypt FAILED\n");
            failures++;
        } else {
            uint8_t pt[32]; int pt_len;
            ret = tc_aes128_cbc_decrypt(key, iv, ct, ct_len, pt, &pt_len);
            if (ret != 0 || pt_len != 8 || memcmp(pt, "test1234", 8) != 0) {
                fprintf(stderr, "[!] AES-CBC decrypt FAILED (got len=%d)\n", pt_len);
                failures++;
            }
        }
    }

    /* ---- SHA-256 test vector (empty string) ---- */
    {
        const uint8_t expected[32] = {
            0xe3,0xb0,0xc4,0x42,0x98,0xfc,0x1c,0x14,
            0x9a,0xfb,0xf4,0xc8,0x99,0x6f,0xb9,0x24,
            0x27,0xae,0x41,0xe4,0x64,0x9b,0x93,0x4c,
            0xa4,0x95,0x99,0x1b,0x78,0x52,0xb8,0x55
        };
        uint8_t out[32];
        tc_sha256_hash((uint8_t*)"", 0, out);
        if (memcmp(out, expected, 32) != 0) {
            fprintf(stderr, "[!] SHA-256 FAILED\n");
            failures++;
        }
    }

    /* ---- SHA-256 test vector ("abc") ---- */
    {
        const uint8_t expected[32] = {
            0xba,0x78,0x16,0xbf,0x8f,0x01,0xcf,0xea,
            0x41,0x41,0x40,0xde,0x5d,0xae,0x22,0x23,
            0xb0,0x03,0x61,0xa3,0x96,0x17,0x7a,0x9c,
            0xb4,0x10,0xff,0x61,0xf2,0x00,0x15,0xad
        };
        uint8_t out[32];
        tc_sha256_hash((uint8_t*)"abc", 3, out);
        if (memcmp(out, expected, 32) != 0) {
            fprintf(stderr, "[!] SHA-256(abc) FAILED\n");
            failures++;
        }
    }

    /* ---- SHA-1 test vector ("abc") ---- */
    {
        const uint8_t expected[20] = {
            0xA9,0x99,0x3E,0x36,0x47,0x06,0x81,0x6A,
            0xBA,0x3E,0x25,0x71,0x78,0x50,0xC2,0x6C,
            0x9C,0xD0,0xD8,0x9D
        };
        uint8_t out[20];
        tc_sha1_hash((uint8_t*)"abc", 3, out);
        if (memcmp(out, expected, 20) != 0) {
            fprintf(stderr, "[!] SHA-1 FAILED\n");
            failures++;
        }
    }

    /* ---- MD5 test vector ("") ---- */
    {
        const uint8_t expected[16] = {
            0xd4,0x1d,0x8c,0xd9,0x8f,0x00,0xb2,0x04,
            0xe9,0x80,0x09,0x98,0xec,0xf8,0x42,0x7e
        };
        uint8_t out[16];
        tc_md5_hash((uint8_t*)"", 0, out);
        if (memcmp(out, expected, 16) != 0) {
            fprintf(stderr, "[!] MD5 FAILED\n");
            failures++;
        }
    }

    /* ---- RC4 test vector ---- */
    {
        /* "Key" = "Key", "Plaintext" = "Plaintext" */
        uint8_t key[] = "Key";
        uint8_t pt[]  = "Plaintext";
        uint8_t expected[] = {0xBB,0xF3,0x16,0xE8,0xD9,0x40,0xAF,0x0A,0xD3};
        uint8_t out[9];
        tc_rc4_crypt(key, 3, pt, 9, out);
        if (memcmp(out, expected, 9) != 0) {
            fprintf(stderr, "[!] RC4 FAILED\n");
            failures++;
        }
    }

    if (failures == 0) {
        g_tc_self_test_ok = 1;
    }
    return failures;
}
