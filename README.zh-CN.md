# clientcheck

纯 C 编写的 Windows 后渗透凭据恢复工具集。
单一自包含二进制，**无需 OpenSSL、无任何外部运行时依赖**。

> [English README](README.md)

## ⚠️ 免责声明

本工具**仅面向合法授权的企业安全建设行为**，包括：安全研究、已获书面授权的
渗透测试、以及对自有或明确授权资产的数字取证。目标用户为红队人员、安全研究
者与应急响应人员。

使用本工具即表示您同意：

1. 仅对**已获得明确书面授权**的系统使用本工具（自有靶机环境、已签署交战规则
   的授权项目、或经批准的取证调取）。
2. 您有责任遵守所有适用的法律法规。未经授权访问计算机系统在大多数司法辖区
   均属犯罪行为（如中国《刑法》第 285/286 条、美国 CFAA 等）。
3. 作者与贡献者**不承担**因使用或滥用本工具导致的任何损害、数据丢失或法律
   后果的任何责任。

如您需要测试本工具的可用性，请自行搭建靶机环境。
**请勿对非授权目标进行扫描和攻击。如您在使用本工具的过程中存在任何非法行为，
您需自行承担相应后果。**

## 功能

1. **Chromium 内核浏览器** — Chrome、Edge、Brave、QQ、Opera/GX、360、Vivaldi、
   CocCoc、Yandex、搜狗（新旧）、Arc、DuckDuckGo 等
   浏览记录（含搜索词）、下载记录、Cookie、书签、保存的密码、信用卡、扩展、
   LocalStorage / SessionStorage（LevelDB 碎片恢复）。
   Chromium App-Bound 加密（v20）通过 IElevator 反射注入处理（浏览器派生
   payload、用户态、无需管理员）。
2. **Firefox** — 浏览记录、Cookie、书签、下载记录、登录凭据（key4.db 完整
   NSS PBE 链，旧版 3DES 与 Firefox 144+ AES-256-CBC 凭据块）、扩展、LocalStorage
3. **IE** — Vault 凭据、TypedURLs 历史、收藏夹
4. **RDP** — 凭据管理器（`TERMSRV/*`）、`Microsoft\Credentials` 文件 DPAPI
   恢复（含用户会话 token 模拟 / 辅助进程回退）、Windows Vault、终端服务器
   客户端历史（离线 hive 加载）、`.rdp` / `.rdg` 文件，另含可选的
   **25 项扩展生态检测清单**（`-rdp-extended`）：其他 RDP 客户端
   （mRemoteNG、Remmina、Royal TS、RDM、Devolutions）、VNC 服务端、会话痕迹。
   无法解密的凭据文件会报告 masterkey GUID 供带外恢复（mimikatz
   `sekurlsa::dpapi` + `dpapi::cred /masterkey:`）
5. **Navicat** — 注册表（递归）+ `.ncx` 文件；v12 AES 与 v11 Blowfish 解密
6. **DBeaver** — credentials-config.json（AES）+ data-sources.json、JDBC URL
7. **FinalShell** — 连接 JSON 文件，Java `Random` LCG + DES 密码解密
8. **Xshell / Xftp / Xmanager** — NetSarang 会话文件，版本差异化 RC4 解密
9. **FileZilla** — XML 站点管理器（base64 / 明文密码）
10. **WinSCP** — 注册表 + INI，经典十六进制密码解密，另含 **PuTTY 保存的
    会话**枚举（主机/端口/协议/用户/私钥路径，会话名 URL 解码）
11. **VNC** — RealVNC / TightVNC / TigerVNC / ORL 注册表树（全部用户）+
    UltraVNC ini，经典 d3des 固定密钥解密
12. **ToDesk** — 从运行中的 ToDesk.exe 进程实时内存提取：设备代码、临时密码、
    安全密码、已保存设备列表及密码
13. **向日葵（Sunlogin）** — 从注册表 + 客户端/服务配置 INI 提取配置
    （fastcode / encry_pwd / sunlogincode）
14. **TeamViewer** — 通过运行中主窗口捕获 ID/密码
15. **TortoiseSVN** — `%APPDATA%\Subversion\auth\svn.simple` 缓存凭据，
    DPAPI 解密
16. **RDCMan** — 通过 RDCMan.settings 发现 `.rdg` 文件，DPAPI 解密
17. **MobaXterm** — 安装版注册表（`HKCU\Software\Mobatek\MobaXterm`）与便携版
    `MobaXterm.ini` 双源合并；每条目自动选择三种解密路径之一：无主密码定制
    nibble 密码、旧版 ≤v24 主密码格式、v25+/v26 随机 IV 格式（`_@` 前缀）。
    注册表主密码哈希过期时可用 `-moba-master <密码>` 显式提供。空密码与
    不可读条目均有明确报告。
18. **WiFi** — 已保存配置及密钥、网卡枚举、配置 XML 中 802.1X 域账号提取
19. **敏感文件搜索** — 配置扫描 + 降噪（`-sensitive-mode normal|strict`），
    另含**私钥/密码库探测**（.kdbx/.ppk/.pem/.key/id_rsa/...，标注是否有
    passphrase）与**云/SCM 凭据文件**（.aws/credentials、.kube/config、
    .git-credentials、.npmrc、unattend.xml）

## 构建

要求：**Windows**、**CMake 3.15+**、MSVC 或 MinGW-w64。
SQLite3 amalgamation 已内置于 `external/`。无需 OpenSSL — 全部密码学
（AES-GCM/CBC/CFB8、3DES、DES、Blowfish、SHA1/256/512、MD5、PBKDF2、RC4、
Base64、d3des）实现于 `src/tinycrypto.c`，启动时自检。

```powershell
# MinGW
cmake -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build

# 或 MSVC
cmake -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

## 使用

```
clientcheck -all -output "result.txt"
clientcheck -only <m1,m2,...> -output "result.txt"
clientcheck -all -no-vnc -no-teamviewer -output "result.txt"
clientcheck -only rdp -rdp-extended -output "result.txt"
clientcheck -only mobaxterm -moba-master "password" -output "result.txt"
```

| 参数 | 作用 |
|--------|--------|
| `-all` | 执行所有模块（默认） |
| `-output <file>` | UTF-8 结果文件（必填） |
| `-only <m1,m2,...>` | 仅运行列出的模块/分组（逗号分隔） |
| `-no-<module>` | 排除某个模块或分组（可重复） |
| `-sensitive-mode <normal\|strict>` | 搜索强度（默认 normal） |
| `-browser-format <csv\|json>` | 浏览器数据同时导出到 `out\` |
| `-rdp-extended` | 开启 25 项 RDP 生态检测（默认关） |
| `-moba-master <password>` | 显式提供 MobaXterm 主密码 |
| `-modules` | 列出可用模块与分组 |
| `-help` | 显示帮助 |

模块：`todesk, sunlogin, dbeaver, finalshell, xshell, xftp, xmanager,
filezilla, navicat, rdp, winscp, vnc, tortoisesvn, teamviewer, chromium,
firefox, ie, sensitive, mobaxterm, wifi`

分组（可用于 `-only` 与 `-no-`）：`browser`（= chromium,firefox,ie）、
`rdp`、`sensitive`、`remote`（= todesk,sunlogin,teamviewer）。

同一可执行文件还兼作内部 DPAPI 辅助进程：
`clientcheck --rdp-dpapi-unprotect <blob_file> <out_file>` — RDP 模块用
`CreateProcessWithTokenW` 在目标用户登录会话内解密时调用；非面向用户的文档化模式。

## 项目结构

```
clientcheck/
├── CMakeLists.txt
├── external/
│   ├── sqlite3.c          # SQLite amalgamation（内置）
│   └── sqlite3.h
└── src/
    ├── main.c             # CLI 入口、模块调度、计时汇总
    ├── help.c/h           # 帮助文本
    ├── tinycrypto.c/h     # 自包含密码学 + 启动自检
    ├── browser/           # chromium / firefox / ie + 共享 crypto、sqlite、utils
    ├── rdp.c/h            # RDP 凭据恢复（最大模块）
    ├── mobaxterm.c/h      # MobaXterm v24/v25/v26 格式
    ├── navicat.c/h  dbeaver.c/h  finalshell.c/h  xshell.c/h
    ├── winscp.c/h   filezilla.c/h  vnc.c/h  tortoisesvn.c/h
    ├── remotecontrol.c/h  # ToDesk（内存）+ 向日葵（配置）
    ├── teamviewer.c/h     # TeamViewer 窗口捕获
    ├── wifi.c/h           # WLAN 配置
    └── search.c/h         # 敏感搜索 + 私钥/云凭据探测
```

## 依赖

| 库 | 用途 | 说明 |
|---------|-------|-------|
| Windows SDK | DPAPI、Vault、CredMan、WTS、注册表、进程 token | 系统内置 |
| crypt32.dll | DPAPI | 系统内置 |
| vaultcli.dll | Windows Vault（动态加载） | 系统内置 |
| SQLite3 | 浏览器配置数据库 | 内置 amalgamation |

## 已知限制

1. **WinSCP** — 仅支持经典十六进制密码格式（5.x 之前的注册表/INI 条目）；
   不支持新版 AES 加密的 WinSCP 配置。
2. **IE Vault 条目** — 按固定结构体偏移解析并带 `IsBadReadPtr` 防护；
   未文档化布局，可能随 Windows 版本变化。
3. **MobaXterm** — 注册表主密码哈希过期时（保存凭据后修改过主密码），相关
   条目报告为不可读；用 `-moba-master` 重跑或让 MobaXterm 刷新存储的哈希。

## 致谢（参考项目）

本项目站在以下开源项目的肩膀上。算法级致谢：

- **[e0e1-config](https://github.com/eeeeeeeeee-code/e0e1-config)** — 整体
  模块布局（本项目即该 Go 工具的 C 移植版）；WinSCP、Navicat、DBeaver、
  FinalShell、Xshell、FileZilla 与敏感搜索工作流
- **[GhostWolf](https://github.com/SickleSec/GhostWolf)** — ToDesk 实时内存
  提取思路（CookieKatz 谱系）
- **[HackBrowserData](https://github.com/moonD4rk/HackBrowserData)** —
  Chromium App-Bound 加密处理、Firefox NSS PBE 链、浏览器数据类别模型
- **[SharpWeb](https://github.com/StarfireLab/SharpWeb)** — Chromium v20
  Cookie 解密与 IE Vault 解析思路
- **[SharpDecryptPwd](https://github.com/RowTeam/SharpDecryptPwd)** — 向日葵、
  TeamViewer、TortoiseSVN、RDCMan、WinSCP、Xmanager 凭据解密思路

同时感谢
[doki-byte/read_sun_todesk](https://github.com/doki-byte/read_sun_todesk)、
[lele8/SharpDBeaver](https://github.com/lele8/SharpDBeaver)、
[AabyssZG/NavicatPwn](https://github.com/AabyssZG/NavicatPwn)、
[sf197/GetPwd](https://github.com/sf197/GetPwd)、
[ShuYeJang/ToDeskSunDump](https://github.com/ShuYeJang/ToDeskSunDump)、
[Naturehi666/searchall](https://github.com/Naturehi666/searchall)
的公开资料对本项目各模块的启发。

## 许可证

与原 clientcheck 项目一致。使用风险自负。
