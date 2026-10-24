# clientcheck

A Windows post-exploitation credential recovery toolkit written in pure C.
Single self-contained binary, **no OpenSSL and no external runtime dependencies**.

> [中文说明 (Chinese README)](README.zh-CN.md)

## ⚠️ Disclaimer

This tool is provided **for lawful security research, authorized penetration
testing, and digital forensics on systems you own or are explicitly authorized
to assess**. It is intended for red-team operators, security researchers, and
incident responders.

By using this tool you agree that:

1. You will only use it against systems for which you have **written,
   explicit authorization** (your own lab, an engagement with signed rules of
   engagement, or a sanctioned forensic acquisition).
2. You are responsible for complying with all applicable local, state, and
   national laws. Unauthorized access to computer systems is a crime in most
   jurisdictions (e.g. CFAA in the US, Criminal Law Art. 285/286 in China).
3. The authors and contributors assume **no liability** for any damage, data
   loss, or legal consequences caused by misuse of this tool.

If you obtained this binary from someone else and did not authorize its use on
your machine, note that its entire purpose is credential recovery — treat any
finding as a security incident.

## Features

1. **Chromium browsers** — Chrome, Edge, Brave, QQ, Opera/GX, 360, Vivaldi, CocCoc,
   Yandex, Sogou (old/new), Arc, DuckDuckGo and more
   History (incl. search terms), Downloads, Cookies, Bookmarks, Saved Passwords,
   Credit Cards, Extensions, LocalStorage / SessionStorage (LevelDB fragment recovery).
   Chromium App-Bound Encryption (v20) is handled via IElevator reflective
   injection (browser-spawned payload, user mode, no admin needed).
2. **Firefox** — History, Cookies, Bookmarks, Downloads, Login credentials
   (key4.db full NSS PBE chain, legacy 3DES and Firefox 144+ AES-256-CBC blobs),
   Extensions, LocalStorage
3. **IE** — Vault credentials, TypedURLs history, Favorites
4. **RDP** — Credential Manager (`TERMSRV/*`), DPAPI recovery of
   `Microsoft\Credentials` files (with user-session token impersonation /
   helper-process fallback), Windows Vault, Terminal Server Client history
   (offline hives), `.rdp` / `.rdg` artifacts, plus an opt-in
   **25-point extended ecosystem checklist** (`-rdp-extended`): other RDP
   clients (mRemoteNG, Remmina, Royal TS, RDM, Devolutions), VNC servers,
   session artifacts. Undecryptable credential files report their
   masterkey GUIDs for out-of-band recovery (mimikatz
   `sekurlsa::dpapi` + `dpapi::cred /masterkey:`)
5. **Navicat** — registry (recursive) + `.ncx` files; v12 AES and v11 Blowfish
6. **DBeaver** — credentials-config.json (AES) + data-sources.json, JDBC URLs
7. **FinalShell** — conn JSON files, Java `Random` LCG + DES decryption
8. **Xshell / Xftp / Xmanager** — NetSarang session files, version-specific RC4
9. **FileZilla** — XML site manager (base64 / plaintext)
10. **WinSCP** — registry + INI, classic hex-password decryption, plus **PuTTY
    Saved Sessions** enumeration (host/port/protocol/user/private key path,
    URL-decoded session names)
11. **VNC** — RealVNC / TightVNC / TigerVNC / ORL registry trees (all users) +
    UltraVNC ini, classic d3des fixed-key decryption
12. **ToDesk** — live memory extraction from the running ToDesk.exe process:
    device code, temp password, security password, saved device list
13. **Sunlogin (向日葵)** — config extraction (fastcode / encry_pwd /
    sunlogincode) from registry + client/service INIs
14. **TeamViewer** — ID/password capture from the running main window
15. **TortoiseSVN** — cached credentials in
    `%APPDATA%\Subversion\auth\svn.simple`, DPAPI decryption
16. **RDCMan** — `.rdg` files via RDCMan.settings discovery, DPAPI decryption
17. **MobaXterm** — installer registry (`HKCU\Software\Mobatek\MobaXterm`)
    and portable `MobaXterm.ini`, merged; three decryption paths auto-selected:
    no-master-password nibble cipher, legacy ≤v24 master-password format, and
    the v25+/v26 random-IV format (`_@` prefix). Master password may be
    supplied explicitly via `-moba-master <password>` when the registry hash is
    stale. Empty passwords and unreadable entries are reported explicitly.
18. **WiFi** — saved profiles with key material, interface enumeration,
    802.1X identity extraction from profile XML
19. **Sensitive file search** — config scanning with noise filtering
    (`-sensitive-mode normal|strict`), plus **private key / password database
    discovery** (.kdbx/.ppk/.pem/.key/id_rsa/... with passphrase detection) and
    **cloud/SCM credential files** (.aws/credentials, .kube/config,
    .git-credentials, .npmrc, unattend.xml)

## Build

Requirements: **Windows**, **CMake 3.15+**, MSVC or MinGW-w64.
SQLite3 amalgamation is vendored in `external/`. No OpenSSL — all crypto
(AES-GCM/CBC/CFB8, 3DES, DES, Blowfish, SHA1/256/512, MD5, PBKDF2, RC4, Base64,
d3des) lives in `src/tinycrypto.c` and is verified by a startup self-test.

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
clientcheck -only rdp -rdp-extended -output "result.txt"
clientcheck -only mobaxterm -moba-master "password" -output "result.txt"
```

| Option | Effect |
|--------|--------|
| `-all` | Execute all modules (default) |
| `-output <file>` | UTF-8 result file (required) |
| `-only <m1,m2,...>` | Run ONLY the listed modules/groups |
| `-no-<module>` | Exclude one module or group (repeatable) |
| `-sensitive-mode <normal\|strict>` | Search aggressiveness (default: normal) |
| `-browser-format <csv\|json>` | Also export browser data into `out\` |
| `-rdp-extended` | Enable the 25-point RDP ecosystem checklist (default off) |
| `-moba-master <password>` | Supply the MobaXterm master password explicitly |
| `-modules` | List available modules and groups |
| `-help` | Show help |

Modules: `todesk, sunlogin, dbeaver, finalshell, xshell, xftp, xmanager,
filezilla, navicat, rdp, winscp, vnc, tortoisesvn, teamviewer, chromium,
firefox, ie, sensitive, mobaxterm, wifi`

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
│   ├── sqlite3.c          # SQLite amalgamation (vendored)
│   └── sqlite3.h
└── src/
    ├── main.c             # CLI entry, module runner, timing summary
    ├── help.c/h           # Help text
    ├── tinycrypto.c/h     # Self-contained crypto + startup self-test
    ├── browser/           # chromium / firefox / ie + shared crypto, sqlite, utils
    ├── rdp.c/h            # RDP credential recovery (largest module)
    ├── mobaxterm.c/h      # MobaXterm v24/v25/v26 formats
    ├── navicat.c/h  dbeaver.c/h  finalshell.c/h  xshell.c/h
    ├── winscp.c/h   filezilla.c/h  vnc.c/h  tortoisesvn.c/h
    ├── remotecontrol.c/h  # ToDesk (memory) + Sunlogin (config)
    ├── teamviewer.c/h     # TeamViewer GUI capture
    ├── wifi.c/h           # WLAN profiles
    └── search.c/h         # Sensitive search + key/cloud-cred discovery
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
2. **IE Vault items** — parsed via fixed struct offsets with `IsBadReadPtr`
   guards; undocumented layout that may shift across Windows builds.
3. **MobaXterm** — when the registry master-password hash is stale (password
   changed after the stored credentials were saved), entries are reported as
   unreadable; re-run with `-moba-master` or let MobaXterm refresh its stored
   hash.

## Acknowledgments

This project stands on the shoulders of the following open-source projects.
Algorithm-level credits:

- **[e0e1-config](https://github.com/eeeeeeeeee-code/e0e1-config)** — overall
  module layout (this codebase is the C port of that Go tool); WinSCP, Navicat,
  DBeaver, FinalShell, Xshell, FileZilla and sensitive-search workflows
- **[GhostWolf](https://github.com/SickleSec/GhostWolf)** — ToDesk
  live-memory extraction approach (CookieKatz lineage)
- **[HackBrowserData](https://github.com/moonD4rk/HackBrowserData)** —
  Chromium App-Bound Encryption handling, Firefox NSS PBE chain, browser data
  category model
- **[SharpWeb](https://github.com/StarfireLab/SharpWeb)** — Chromium v20
  cookie decryption and IE Vault parsing ideas
- **[SharpDecryptPwd](https://github.com/RowTeam/SharpDecryptPwd)** —
  Sunlogin, TeamViewer, TortoiseSVN, RDCMan, WinSCP and Xmanager credential
  decryption approaches

Also thanks to the authors of
[doki-byte/read_sun_todesk](https://github.com/doki-byte/read_sun_todesk),
[lele8/SharpDBeaver](https://github.com/lele8/SharpDBeaver),
[AabyssZG/NavicatPwn](https://github.com/AabyssZG/NavicatPwn),
[sf197/GetPwd](https://github.com/sf197/GetPwd),
[ShuYeJang/ToDeskSunDump](https://github.com/ShuYeJang/ToDeskSunDump) and
[Naturehi666/searchall](https://github.com/Naturehi666/searchall) whose public
write-ups informed individual modules.

## License

Same as the original clientcheck project. Use at your own risk.
