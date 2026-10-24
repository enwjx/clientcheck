/*
 * tinycrypto.h — Self-contained crypto library
 * Replaces OpenSSL dependency entirely.
 * Implements: AES(-GCM/-CBC), 3DES, SHA1/256, MD5, PBKDF2, RC4, Base64
 * Public domain / MIT-licensed compact implementations.
 */
#ifndef TINYCRYPTO_H
#define TINYCRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---- AES (128/192/256) -------------------------------------------- */
#define AES_BLOCK_SIZE 16    /* 128 bits = 16 bytes */
#define AES_MAX_ROUNDS 14    /* AES-256 */
#define AES_MAX_RK     60    /* (14+1)*4 */

typedef struct {
    uint32_t rk[AES_MAX_RK];
    int      rounds;
} aes_ctx;

void aes_setkey_enc(aes_ctx* ctx, const uint8_t* key, int bits);
void aes_setkey_dec(aes_ctx* ctx, const uint8_t* key, int bits);
void aes_encrypt_block(const aes_ctx* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);
void aes_decrypt_block(const aes_ctx* ctx, const uint8_t in[AES_BLOCK_SIZE], uint8_t out[AES_BLOCK_SIZE]);

/* ---- AES-GCM ------------------------------------------------------ */
int tc_aes_gcm_decrypt(const uint8_t* key, int key_len,
                    const uint8_t* iv, int iv_len,
                    const uint8_t* aad, int aad_len,
                    const uint8_t* ct, int ct_len,
                    const uint8_t* tag, int tag_len,
                    uint8_t* out_pt);

int tc_aes_gcm_encrypt(const uint8_t* key, int key_len,
                    const uint8_t* iv, int iv_len,
                    const uint8_t* aad, int aad_len,
                    const uint8_t* pt, int pt_len,
                    uint8_t* out_ct, uint8_t* out_tag, int tag_len);

/* ---- AES-CBC ------------------------------------------------------ */
int tc_aes128_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len);
/* Raw CBC decrypt without padding removal (Navicat zero-padding) */
int tc_aes128_cbc_decrypt_raw(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len);
/* AES-256-CBC raw decrypt (Firefox 144+ master keys / NSS PBE) */
int tc_aes256_cbc_decrypt_raw(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len);
int tc_aes128_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* pt, int pt_len,
                       uint8_t* out, int* out_len);

/* ---- 3DES (DES-EDE3-CBC) ------------------------------------------ */
#define DES_BLOCK_SIZE 8
#define DES_KEY_SIZE   24

int tc_des3_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                     const uint8_t* ct, int ct_len,
                     uint8_t* out, int* out_len);
int tc_des3_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                     const uint8_t* pt, int pt_len,
                     uint8_t* out, int* out_len);

/* ---- DES (single, ECB) — for FinalShell --------------------------- */
typedef struct {
    uint8_t k[16][6]; /* 16 round subkeys */
} des_ctx;

void des_setkey(des_ctx* ctx, const uint8_t key[8]);
void des_ecb_crypt(const des_ctx* ctx, const uint8_t in[8], uint8_t out[8], int decrypt);

/* ---- SHA-1 -------------------------------------------------------- */
#define SHA1_DIGEST_SIZE 20
typedef struct {
    uint32_t h[5], w[16];
    uint64_t total;
    uint8_t  buf[64]; int buf_idx;
} sha1_ctx;

void sha1_init(sha1_ctx* c);
void sha1_update(sha1_ctx* c, const uint8_t* data, int len);
void sha1_final(sha1_ctx* c, uint8_t out[SHA1_DIGEST_SIZE]);
void tc_sha1_hash(const uint8_t* data, int len, uint8_t out[SHA1_DIGEST_SIZE]);

/* ---- SHA-256 ------------------------------------------------------ */
#define SHA256_DIGEST_SIZE 32
typedef struct {
    uint32_t h[8], w[64];
    uint64_t total;
    uint8_t  buf[64]; int buf_idx;
} sha256_ctx;

void sha256_init(sha256_ctx* c);
void sha256_update(sha256_ctx* c, const uint8_t* data, int len);
void sha256_final(sha256_ctx* c, uint8_t out[SHA256_DIGEST_SIZE]);
void tc_sha256_hash(const uint8_t* data, int len, uint8_t out[SHA256_DIGEST_SIZE]);

/* ---- MD5 ---------------------------------------------------------- */
#define MD5_DIGEST_SIZE 16
typedef struct {
    uint32_t h[4], w[16];
    uint64_t total;
    uint8_t  buf[64]; int buf_idx;
} md5_ctx;

void md5_init(md5_ctx* c);
void md5_update(md5_ctx* c, const uint8_t* data, int len);
void md5_final(md5_ctx* c, uint8_t out[MD5_DIGEST_SIZE]);
void tc_md5_hash(const uint8_t* data, int len, uint8_t out[MD5_DIGEST_SIZE]);

/* ---- PBKDF2-HMAC -------------------------------------------------- */
int pbkdf2_hmac_sha1(const uint8_t* pass, int pass_len,
                     const uint8_t* salt, int salt_len,
                     int iterations, int dk_len, uint8_t* dk);

int pbkdf2_hmac_sha256(const uint8_t* pass, int pass_len,
                       const uint8_t* salt, int salt_len,
                       int iterations, int dk_len, uint8_t* dk);

/* ---- HMAC-SHA1 (exported for NSS PBE key derivation) -------------- */
void tc_hmac_sha1(const uint8_t* key, int key_len,
                  const uint8_t* msg, int msg_len,
                  uint8_t mac[20]);

/* ---- RC4 ---------------------------------------------------------- */
void tc_rc4_crypt(const uint8_t* key, int key_len,
               const uint8_t* in, int in_len, uint8_t* out);

/* ---- Base64 ------------------------------------------------------- */
int  tc_base64_encode(const uint8_t* in, int in_len, char* out);
int  tc_base64_decode(const char* in, uint8_t* out, int out_size);

/* ---- Hex decode --------------------------------------------------- */
int tc_hex_decode(const char* hex, uint8_t* out, int out_size);

/* ---- File read ---------------------------------------------------- */
uint8_t* tc_read_file(const char* path, int* out_len);

/* Self-test — returns 0 on success, non-zero on failure */
int tc_self_test(void);

#ifdef __cplusplus
}
#endif

#endif /* TINYCRYPTO_H */
