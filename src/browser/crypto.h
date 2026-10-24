#ifndef BROWSER_CRYPTO_H
#define BROWSER_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>

/* Read entire file into allocated buffer (caller must free) */
uint8_t* read_file(const char* path, int* out_len);

/* AES-GCM Decrypt */
int aes_gcm_decrypt(const uint8_t* key, int key_len,
                    const uint8_t* iv, int iv_len,
                    const uint8_t* aad, int aad_len,
                    const uint8_t* ct, int ct_len,
                    const uint8_t* tag, int tag_len,
                    uint8_t* out, int* out_len);

/* AES-128-CBC Decrypt */
int aes128_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* ct, int ct_len,
                       uint8_t* out, int* out_len);

/* AES-128-CBC Encrypt */
int aes128_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                       const uint8_t* pt, int pt_len,
                       uint8_t* out, int* out_len);

/* 3DES-CBC Decrypt */
int des3_cbc_decrypt(const uint8_t* key, const uint8_t* iv,
                     const uint8_t* ct, int ct_len,
                     uint8_t* out, int* out_len);

/* 3DES-CBC Encrypt */
int des3_cbc_encrypt(const uint8_t* key, const uint8_t* iv,
                     const uint8_t* pt, int pt_len,
                     uint8_t* out, int* out_len);

/* Blowfish (for Navicat) �?ECB mode with custom XOR chaining */
int blowfish_cbc_decrypt_custom(const uint8_t* key, int key_len,
                                 const uint8_t* iv,
                                 const uint8_t* ct, int ct_len,
                                 uint8_t* out, int* out_len);

/* DPAPI decrypt using Windows CryptUnprotectData */
int dpapi_decrypt(const uint8_t* data, int data_len,
                  uint32_t flags,
                  uint8_t* out, int* out_len);

/* PBKDF2 key derivation */
int pbkdf2_derive(const uint8_t* pass, int pass_len,
                  const uint8_t* salt, int salt_len,
                  int iterations, int key_len,
                  const char* hash_name, /* "sha1", "sha256" */
                  uint8_t* out);

/* RC4 stream cipher */
void rc4_crypt(const uint8_t* key, int key_len,
               const uint8_t* in, int in_len,
               uint8_t* out);

/* SHA1 hash */
void sha1_hash(const uint8_t* data, int len, uint8_t out[20]);

/* SHA256 hash */
void sha256_hash(const uint8_t* data, int len, uint8_t out[32]);

/* MD5 hash */
void md5_hash(const uint8_t* data, int len, uint8_t out[16]);

/* Base64 encode/decode */
int  base64_decode(const char* in, uint8_t* out, int out_size);
char* base64_encode(const uint8_t* in, int in_len);

/* Hex decode (e.g. "deadbeef" -> bytes) */
int hex_decode(const char* hex, uint8_t* out, int out_size);

/*
 * Chrome/Firefox key extraction
 * Returns allocated key buffer (caller must free), key_len set to length.
 * Returns NULL on failure.
 */
uint8_t* get_master_key(const char* state_file_path, int* key_len);
uint8_t* decrypt_with_system_dpapi(const char* state_file_path, int* key_len);
uint8_t* decrypt_with_user_dpapi(const uint8_t* system_key, int system_key_len,
                                  const char* state_file_path, int* key_len);

/*
 * Decrypt Chromium encrypted data (v10/v11/v20 format detection)
 * Returns allocated string (caller must free), or NULL.
 */
char* decrypt_data(const uint8_t* encrypted, int len, const uint8_t* master_key, int master_key_len);

/*
 * Unified Chromium key bundle + decrypt helpers.
 * Consolidates system/user/master key loading used by cookies/logins/cards.
 */
typedef struct {
    uint8_t* system_key;
    int      system_key_len;
    uint8_t* user_key;
    int      user_key_len;
    uint8_t* master_key;
    int      master_key_len;
} ChromiumKeys;

/* Load keys from Local State (ABE/system + user + master). Always safe to free. */
int  chromium_keys_load(const char* state_file_path, ChromiumKeys* keys);
void chromium_keys_free(ChromiumKeys* keys);

/*
 * Decrypt Chromium encrypted blob using best available key.
 * Tries user_key -> master_key -> system_key for v10/v11/v20,
 * then DPAPI direct for legacy data. Returns allocated string (caller free) or NULL.
 */
char* chromium_decrypt(const uint8_t* encrypted, int len, const ChromiumKeys* keys);

/* Base64-encoded variant (SQLite BLOB path). Returns allocated string or NULL. */
char* chromium_decrypt_b64(const char* b64, const ChromiumKeys* keys);


/*
 * Firefox ASN.1 PBE types — full DER parser (mirrors HackBrowserData
 * crypto/asn1pbe.go; NSS reference lowpbe.c). Supports:
 *   - privateKeyPBE  (nssPrivate.a11 blobs, PBE-SHA1-3DES)
 *   - passwordCheckPBE (metaData.item2, PBKDF2-HMAC-SHA256 + AES-256-CBC)
 *   - credentialPBE  (logins.json blobs; 3DES legacy / AES-256-CBC FF144+)
 */
typedef enum {
    ASN1_PBE_NSS   = 0,
    ASN1_PBE_META  = 1,
    ASN1_PBE_LOGIN = 2,
    ASN1_PBE_UNKNOWN = -1
} ASN1PBEType;

typedef struct {
    ASN1PBEType type;
    /* NSS */
    uint8_t  entry_salt[64];
    int      entry_salt_len;
    /* META (PBKDF2 params + IV) */
    uint8_t  pb_salt[64];
    int      pb_salt_len;
    int      iteration;
    int      key_size;
    uint8_t  meta_iv[16];
    int      meta_iv_len;
    /* LOGIN */
    uint8_t  login_iv[16];
    int      login_iv_len;
    /* encrypted payload (points into the caller's buffer — keep it alive) */
    const uint8_t* encrypted;
    int      encrypted_len;
    bool     valid;
} ASN1PBE;

ASN1PBE* asn1_pbe_parse(const uint8_t* data, int len);
int      asn1_pbe_decrypt(ASN1PBE* pbe, const uint8_t* key, int key_len,
                          uint8_t* out, int* out_len);
void     asn1_pbe_free(ASN1PBE* pbe);

/* Firefox master key decryption from key4.db data */
uint8_t* firefox_decrypt_master_key(
    const uint8_t* meta_item1, int m1_len,
    const uint8_t* meta_item2, int m2_len,
    const uint8_t* nss_a11, int a11_len,
    const uint8_t* nss_a102, int a102_len,
    int* out_key_len
);

/* Firefox data decryption (login passwords, cookie values) */
int firefox_decrypt_data(const uint8_t* encrypted, int enc_len,
                          const uint8_t* key, int key_len,
                          uint8_t* out, int* out_len);

#endif /* BROWSER_CRYPTO_H */
