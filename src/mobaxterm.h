#ifndef MOBAXTERM_H
#define MOBAXTERM_H

/* MobaXterm saved-password extraction (portable + installer editions).
 * Sources: MobaXterm.ini ([Passwords]/[Credentials]/[Misc] SessionP/
 * [Sesspass] master key) and the installer registry hive
 * HKCU\Software\Mobatek\MobaXterm (SessionP, P, C, M). Both sources are
 * scanned and merged. Decryption supports the no-master-password custom
 * nibble cipher and the master-password DPAPI + AES-CFB8 path. */
const char* mobaxterm_scan(void);
/* Optional: supply the MobaXterm master password directly (e.g. via
 * -moba-master). Overrides the registry M value when deriving the AES key
 * (key = SHA512(password)[:32]). */
void moba_set_master_password(const char* pw);

#endif
