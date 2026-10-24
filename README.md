# clientcheck (C Version)

Windows credential harvesting tool — C language port of the Go original.
Single self-contained binary, **no OpenSSL and no external runtime dependencies**.

## Features

1. **Chromium browsers** — Chrome, Edge, Brave, QQ, Opera/GX, 360, Vivaldi, CocCoc,
   Yandex, Sogou (old/new), Arc, DuckDuckGo, Vought and more
   History (incl. search terms), Downloads, Cookies, Bookmarks, Saved Passwords,
   Credit Cards, Extensions, LocalStorage / SessionStorage (LevelDB fragment recovery)
2. **Firefox** — History, Cookies, Bookmarks, Downloads (moz_annos join), Login
   credentials (key4.db full NSS PBE chain: password-check verification,
   multi-candidate nssPrivate master key validated against logins.json, legacy
   3DES and Firefox 144+ AES-256-CBC credential blobs), Extensions
   (extensions.json, app-profile only), LocalStorage (webappsstore.sqlite,
   reversed-origin decoding)
3. **IE** — Vault credentials (vaultcli.dll), TypedURLs history, Favorites
4. **RDP** — Credential Manager (`TERMSRV/*`), DPAPI recovery of `Microsoft\Credentials`
   files (with user-session token impersonation / helper-process fallback), Windows
   Vault, Terminal Server Client history (offline hives loaded via `RegLoadKey`),
   `.rdp` / `.rdg` artifacts (RDCMan.settings discovery). Undecryptable credential
   files report their masterkey GUIDs for out-of-band recovery (mimikatz
   `sekurlsa::dpapi` + `dpapi::cred /masterkey:`)
5. **Navicat** — registry (recursive) + `.ncx` files; v12 AES and v11 Blowfish decryption
6. **DBeaver** — credentials-config.json (AES) + data-sources.json, JDBC URL parsing
7. **FinalShell** — conn JSON files, Java `Random` LCG + DES password decryption
8. **Xshell / Xftp** — session files with version-specific RC4 password decryption
9. **FileZilla** — XML site manager (base64 / plaintext passwords)
10. **WinSCP** — registry + INI, classic hex-password decryption
11. **VNC** — RealVNC / TightVNC / TigerVNC / ORL registry trees (all users) +
    UltraVNC ini, classic d3des fixed-key decryption
12. **ToDesk** — detection + live memory extraction (GhostWolf approach): device
    code, temp password, security password and the saved device list with
    passwords, read from the running ToDesk.exe process (x64, requires
    ToDesk running; elevated for other users' sessions)
13. **Sunlogin (向日葵)** — detection + config extraction (fastcode / encry_pwd /
    sunlogincode) from the Uninstall registry key, HKU\.DEFAULT Oray keys and
    the client/service config INIs (SharpDecryptPwd approach)
14. **TeamViewer** — ID/password capture from the running main window via
    FindWindow + EnumChildWindows
15. **Xmanager** — session files share the NetSarang .xsh format; handled by the
    Xshell module with the same version-specific RC4 decryption
16. **TortoiseSVN** — cached credentials in %APPDATA%\Subversion\auth\svn.simple
    (K/V auth files), DPAPI password decryption
17. **RDCMan** — .rdg files discovered via RDCMan.settings (FilesToOpen) and the
    Documents/Desktop/Downloads scan, DPAPI password decryption
18. **MobaXterm** — installer registry (`HKCU\Software\Mobatek\MobaXterm` P/C/M)
    and portable `MobaXterm.ini` ([Passwords]/[Credentials]/[Misc] SessionP),
    both sources merged; three decryption paths auto-selected per entry:
    no-master-password custom nibble cipher, legacy <=v24 master password
    (DPAPI entropy=SessionP -> key=SHA512(mp)[:32], fixed IV), and
    v25+/v26 random-IV format (`_@` + inline IV, CVE-2025-0714 layout)
19. **Sensitive file search** — config scanning with noise filtering
    (`-sensitive-mode normal|strict`)

## Build

Requirements: **Windows**, **CMake 3.15+**, MSVC or MinGW-w64.
SQLite3 amalgamation is vendored in `external/` (replace with a fresh copy from
https://sqlite.org/download.html if desired). No OpenSSL needed — all crypto
(AES-GCM/CBC, 3DES, DES, Blowfish, SHA1/256, MD5, PBKDF2, RC4, Base64) lives in
`src/tinycrypto.c` and is verified by a startup self-test.

```powershell
# MinGW
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build

# or MSVC
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## Usage

```
clientcheck -all -output "result.txt"
clientcheck -only <m1,m2,...> -output "result.txt"
clientcheck -all -no-vnc -no-teamviewer -output "result.txt"
```

| Option | Effect |
|--------|--------|
| `-all` | Execute all modules (default) |
| `-output <file>` | UTF-8 result file (required) |
| `-only <m1,m2,...>` | Run ONLY the listed modules/groups (comma-separated) |
| `-no-<module>` | Exclude one module or group (repeatable; e.g. `-no-vnc -no-navicat`) |
| `-sensitive-mode <normal\|strict>` | Search aggressiveness (default: normal) |
| `-browser-format <csv\|json>` | Also export browser data (history/cookies/logins/bookmarks/extensions) into `out\` |
| `-modules` | List available modules and groups |
| `-help` | Show help |

Modules: `todesk, sunlogin, dbeaver, finalshell, xshell, xftp, xmanager,
filezilla, navicat, rdp, winscp, vnc, tortoisesvn, teamviewer, chromium,
firefox, ie, sensitive`

Groups (usable in `-only` and `-no-`): `browser` (= chromium,firefox,ie),
`rdp`, `sensitive`, `remote` (= todesk,sunlogin,teamviewer).

The same executable also acts as an internal DPAPI helper:
`clientcheck --rdp-dpapi-unprotect <blob_file> <out_file>` — used by the RDP
module to decrypt inside a target user's logon session via
`CreateProcessWithTokenW`; not a documented user-facing mode.

## Project Structure

```
clientcheck/
├── CMakeLists.txt
├── external/
│   ├── sqlite3.c          # SQLite amalgamation (vendored, real source)
│   └── sqlite3.h
└── src/
    ├── main.c             # CLI entry, stdout→file redirection, module runner
    ├── help.c/h           # Help text
    ├── tinycrypto.c/h     # Self-contained crypto + startup self-test
    ├── browser/
    │   ├── utils.c/h      # Locked-file copy (handle duplication), CSV/JSON, StrBuilder
    │   ├── sqlite.c/h     # SQLite wrapper (row-major string API)
    │   ├── crypto.c/h     # DPAPI, Chromium key chain, Firefox PBE, Blowfish
    │   ├── chromium.c/h   # 18 Chromium-based browsers
    │   ├── firefox.c/h    # Firefox profiles
    │   └── ie.c/h         # IE Vault + registry history
    ├── rdp.c/h            # RDP credential recovery (largest module)
    ├── navicat.c/h        # Navicat v11/v12
    ├── dbeaver.c/h        # DBeaver
    ├── finalshell.c/h     # FinalShell
    ├── xshell.c/h         # Xshell/Xftp
    ├── winscp.c/h         # WinSCP
    ├── filezilla.c/h      # FileZilla
    ├── vnc.c/h            # VNC family
    ├── remotecontrol.c/h  # ToDesk (memory) + Sunlogin (config)
    ├── tortoisesvn.c/h    # TortoiseSVN cached credentials
    ├── teamviewer.c/h     # TeamViewer GUI capture
    └── search.c/h         # Sensitive config search
```

## Dependencies

| Library | Usage | Notes |
|---------|-------|-------|
| Windows SDK | DPAPI, Vault, CredMan, WTS, Registry, Process tokens | Built-in |
| crypt32.dll | DPAPI | Built-in |
| vaultcli.dll | Windows Vault (loaded dynamically) | Built-in |
| SQLite3 | Browser profile databases | Vendored amalgamation |

## Known Limitations

1. **WinSCP** — only the classic hex password format (pre-5.x style registry/INI
   entries); newer AES-encrypted WinSCP configurations are not supported.
2. **Chromium App-Bound (v20)** — fully supported: the master key is retrieved
   via IElevator reflective injection (browser-spawned payload, user mode,
   no admin needed). v10 profiles use plain DPAPI. Cookie values strip the
   SHA256(host_key) prefix with verification; passwords are raw secrets.
3. **ToDesk/Sunlogin** — detection only; no memory credential extraction.
4. **IE Vault items** — parsed via fixed struct offsets with `IsBadReadPtr` guards;
   undocumented layout that may shift across Windows builds.

## Conversion Notes (from the Go original)

- Go `syscall` → C Windows API
- Go GC → manual memory management (`malloc`/`free`, `goto cleanup`)
- Go goroutines → single-threaded (search module)
- Go `encoding/json` → in-place JSON scanning helpers
- Go `database/sql` → direct SQLite3 C API
- Go `golang.org/x/crypto` + OpenSSL → `src/tinycrypto.c`

## License

Same as the original clientcheck project.
