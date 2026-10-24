#include "browser/utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <windows.h>
#include <tlhelp32.h>

/* ========== Global State ========== */
char  g_browser_name[256]  = {0};
char  g_browser_limit[32]  = "2000";
char* g_system_key         = NULL;
int   g_system_key_len     = 0;
char  g_format[16]         = {0};
bool  g_print_out          = true;
char  g_output_dir[512]    = "out";

/* ========== Setters ========== */
void browser_set_format(const char* format) {
    if (format && *format) {
        strncpy(g_format, format, sizeof(g_format) - 1);
        g_print_out = false;
    }
}

void browser_set_output_dir(const char* dir) {
    if (dir && *dir) {
        strncpy(g_output_dir, dir, sizeof(g_output_dir) - 1);
    }
}

void browser_set_limit(const char* limit) {
    if (limit && *limit) {
        strncpy(g_browser_limit, limit, sizeof(g_browser_limit) - 1);
    }
}

void browser_set_browser_name(const char* name) {
    if (name && *name) {
        strncpy(g_browser_name, name, sizeof(g_browser_name) - 1);
    }
}

/* ========== Time Conversion ========== */
/* Windows epoch offset: 11644473600 seconds * 1000000 for microseconds */
#define WINDOWS_EPOCH_OFFSET_MICROS 11644473600000000LL

time_t time_epoch(int64_t timestamp) {
    int64_t unix_micro = timestamp - WINDOWS_EPOCH_OFFSET_MICROS;
    if (unix_micro < 0) return (time_t)0;
    return (time_t)(unix_micro / 1000000);
}

int time_epoch_str(int64_t timestamp, char* out, int out_size) {
    time_t t = time_epoch(timestamp);
    if (t == 0) {
        if (out_size > 0) out[0] = '\0';
        return -1;
    }
    struct tm tm_buf;
    if (localtime_s(&tm_buf, &t) != 0) {
        if (out_size > 0) out[0] = '\0';
        return -1;
    }
    strftime(out, out_size, "%Y-%m-%d %H:%M:%S", &tm_buf);
    return 0;
}

/* ========== File Operations ========== */

/* NT API declarations for handle enumeration */
#ifndef STATUS_INFO_LENGTH_MISMATCH
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004L
#endif
#ifndef SystemExtendedHandleInformation
#define SystemExtendedHandleInformation 64
#endif

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX {
    PVOID Object;
    ULONG_PTR UniqueProcessId;
    ULONG_PTR HandleValue;
    ULONG GrantedAccess;
    USHORT CreatorBackTraceIndex;
    USHORT ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
} SYSTEM_HANDLE_INFORMATION_EX;

typedef long (WINAPI *PNtQSI)(unsigned long, void*, unsigned long, unsigned long*);

/* Get PIDs of known browser processes */
static int find_browser_pids(DWORD* pids, int max_pids) {
    const char* names[] = {"chrome.exe","msedge.exe","brave.exe","opera.exe",
                           "360chrome.exe","qqbrowser.exe",NULL};
    int count = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    if (Process32First(snap, &pe)) {
        do {
            for (int i = 0; names[i] && count < max_pids; i++) {
                if (_stricmp(pe.szExeFile, names[i]) == 0) {
                    pids[count++] = pe.th32ProcessID;
                    break;
                }
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return count;
}

static int ascii_tolower_char(int ch) {
    if (ch >= 'A' && ch <= 'Z') return ch + ('a' - 'A');
    return ch;
}

static void normalize_path_lower(const char* src, char* out, size_t out_size) {
    size_t oi = 0;
    if (!out || out_size == 0) return;
    out[0] = '\0';
    if (!src) return;

    if (strncmp(src, "\\\\?\\", 4) == 0) src += 4;
    for (; *src && oi + 1 < out_size; src++) {
        char ch = *src == '/' ? '\\' : *src;
        out[oi++] = (char)ascii_tolower_char((unsigned char)ch);
    }
    out[oi] = '\0';
}

static void extract_stable_suffix(const char* src, char* out, size_t out_size) {
    char normalized[MAX_PATH * 4];
    const char* marker = NULL;
    normalize_path_lower(src, normalized, sizeof(normalized));

    marker = strstr(normalized, "appdata\\local\\");
    if (marker) {
        strncpy(out, marker + strlen("appdata\\local\\"), out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }
    marker = strstr(normalized, "appdata\\roaming\\");
    if (marker) {
        strncpy(out, marker + strlen("appdata\\roaming\\"), out_size - 1);
        out[out_size - 1] = '\0';
        return;
    }

    {
        const char* parts[3] = {normalized, normalized, normalized};
        for (const char* p = normalized; *p; p++) {
            if (*p == '\\') {
                parts[0] = parts[1];
                parts[1] = parts[2];
                parts[2] = p + 1;
            }
        }
        strncpy(out, parts[0], out_size - 1);
        out[out_size - 1] = '\0';
    }
}

static int ends_with_ci(const char* text, const char* suffix) {
    size_t tl, sl;
    if (!text || !suffix) return 0;
    tl = strlen(text);
    sl = strlen(suffix);
    if (sl == 0 || tl < sl) return 0;
    return strcmp(text + tl - sl, suffix) == 0;
}

static int write_handle_to_file(HANDLE src, const char* dst) {
    LARGE_INTEGER li_size;
    HANDLE hMap = NULL;
    HANDLE hDst = INVALID_HANDLE_VALUE;
    void* view = NULL;
    int ok = -1;

    if (!GetFileSizeEx(src, &li_size) || li_size.QuadPart <= 0 || li_size.QuadPart > 0x7fffffffLL) {
        return -1;
    }

    hMap = CreateFileMappingA(src, NULL, PAGE_READONLY, 0, 0, NULL);
    if (hMap) {
        view = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
        if (view) {
            hDst = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDst != INVALID_HANDLE_VALUE) {
                DWORD bw = 0;
                if (WriteFile(hDst, view, (DWORD)li_size.QuadPart, &bw, NULL) && bw == (DWORD)li_size.QuadPart) {
                    ok = 0;
                }
                CloseHandle(hDst);
                hDst = INVALID_HANDLE_VALUE;
            }
            UnmapViewOfFile(view);
            view = NULL;
        }
        CloseHandle(hMap);
        hMap = NULL;
    }
    if (ok == 0) return 0;

    if (SetFilePointer(src, 0, NULL, FILE_BEGIN) == INVALID_SET_FILE_POINTER && GetLastError() != NO_ERROR) {
        return -1;
    }

    {
        char* buf = (char*)malloc((size_t)li_size.QuadPart);
        if (!buf) return -1;
        {
            DWORD br = 0;
            if (!ReadFile(src, buf, (DWORD)li_size.QuadPart, &br, NULL) || br != (DWORD)li_size.QuadPart) {
                free(buf);
                return -1;
            }
            hDst = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hDst != INVALID_HANDLE_VALUE) {
                DWORD bw = 0;
                if (WriteFile(hDst, buf, br, &bw, NULL) && bw == br) ok = 0;
                CloseHandle(hDst);
            }
        }
        free(buf);
    }
    return ok;
}

static int copy_locked_file(const char* src, const char* dst) {
    /* 1. Try CreateFile with full sharing first (works for most browser files) */
    HANDLE h = CreateFileA(src, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        DWORD sz = GetFileSize(h, NULL);
        if (sz != INVALID_FILE_SIZE && sz > 0) {
            char* buf = (char*)malloc(sz);
            if (buf) {
                DWORD br;
                BOOL ok = ReadFile(h, buf, sz, &br, NULL) && br == sz;
                CloseHandle(h);
                if (ok) {
                    HANDLE hDst = CreateFileA(dst, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
                    if (hDst != INVALID_HANDLE_VALUE) {
                        DWORD bw; WriteFile(hDst, buf, sz, &bw, NULL);
                        CloseHandle(hDst);
                        free(buf);
                        if (bw == sz) return 0;
                    }
                }
                free(buf);
            }
        } else { CloseHandle(h); }
    }

    /* 2. Try CopyFileA */
    if (CopyFileA(src, dst, FALSE)) return 0;

    /* 3. DuplicateHandle from browser processes (HackBrowserData approach)
     *    Only check browser PIDs — NOT all system handles! */
    DWORD bpids[32];
    int nbpids = find_browser_pids(bpids, 32);
    if (nbpids == 0) return -1;

    /* Extract stable path suffix for matching */
    char target_suffix[MAX_PATH * 4];
    extract_stable_suffix(src, target_suffix, sizeof(target_suffix));

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return -1;
    PNtQSI NtQSI = (PNtQSI)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!NtQSI) return -1;

    /* Allocate buffer for system handles with retry */
    unsigned long bufSize = 8 * 1024 * 1024; /* Start 8MB */
    void* buf = NULL;
    unsigned long retLen = 0;
    long status;
    for (int retry = 0; retry < 4; retry++) {
        void* newbuf = realloc(buf, bufSize);
        if (!newbuf) { free(buf); return -1; }
        buf = newbuf;
        status = NtQSI(SystemExtendedHandleInformation, buf, bufSize, &retLen);
        if (status != STATUS_INFO_LENGTH_MISMATCH) break;
        bufSize *= 2; /* 8→16→32→64 MB */
    }
    if (status != 0) { free(buf); return -1; }

    SYSTEM_HANDLE_INFORMATION_EX* info = (SYSTEM_HANDLE_INFORMATION_EX*)buf;
    HANDLE curProc = GetCurrentProcess();
    int found = 0;
    int checked_handles = 0;
    ULONGLONG started_at = GetTickCount64();
    const int max_checked_handles = 20000;
    const ULONGLONG max_scan_ms = 10000;

    for (ULONG_PTR i = 0; i < info->NumberOfHandles && !found; i++) {
        if (checked_handles >= max_checked_handles) break;
        if (GetTickCount64() - started_at > max_scan_ms) break;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX* e = &info->Handles[i];
        DWORD pid = (DWORD)e->UniqueProcessId;

        /* Only check browser PIDs */
        int is_browser = 0;
        for (int j = 0; j < nbpids; j++) {
            if (bpids[j] == pid) { is_browser = 1; break; }
        }
        if (!is_browser) continue;

        HANDLE proc = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (!proc) continue;

        HANDLE dup = NULL;
        if (DuplicateHandle(proc, (HANDLE)e->HandleValue,
                            curProc, &dup, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            checked_handles++;
            if (GetFileType(dup) != FILE_TYPE_DISK) {
                CloseHandle(dup);
                CloseHandle(proc);
                continue;
            }
            char nameBuf[MAX_PATH * 4];
            char normalized_name[MAX_PATH * 4];
            DWORD nameLen = GetFinalPathNameByHandleA(dup, nameBuf, sizeof(nameBuf)-1, FILE_NAME_NORMALIZED);
            if (nameLen > 0 && nameLen < sizeof(nameBuf)) {
                nameBuf[nameLen] = '\0';
                normalize_path_lower(nameBuf, normalized_name, sizeof(normalized_name));
                if (ends_with_ci(normalized_name, target_suffix)) {
                    if (write_handle_to_file(dup, dst) == 0) found = 1;
                }
            }
            CloseHandle(dup);
        }
        CloseHandle(proc);
    }

    free(buf);
    return found ? 0 : -1;
}

int create_tmp_file(const char* src_path, char* out_path, int out_size) {
    if (!src_path || !out_path || out_size <= 0) return -1;

    char tmp_path[MAX_PATH], tmp_name[MAX_PATH];
    if (!GetTempPathA(sizeof(tmp_path), tmp_path)) return -1;
    if (!GetTempFileNameA(tmp_path, "brow", 0, tmp_name)) return -1;

    if (copy_locked_file(src_path, tmp_name) != 0) {
        DeleteFileA(tmp_name);
        return -1;
    }

    /* Also copy WAL and SHM files if they exist */
    char wal_path[MAX_PATH], shm_path[MAX_PATH];
    snprintf(wal_path, sizeof(wal_path), "%s-wal", src_path);
    snprintf(shm_path, sizeof(shm_path), "%s-shm", src_path);

    if (path_exists(wal_path)) {
        char wal_tmp[MAX_PATH];
        snprintf(wal_tmp, sizeof(wal_tmp), "%s-wal", tmp_name);
        CopyFileA(wal_path, wal_tmp, FALSE);
    }
    if (path_exists(shm_path)) {
        char shm_tmp[MAX_PATH];
        snprintf(shm_tmp, sizeof(shm_tmp), "%s-shm", tmp_name);
        CopyFileA(shm_path, shm_tmp, FALSE);
    }

    strncpy(out_path, tmp_name, out_size - 1);
    out_path[out_size - 1] = '\0';
    return 0;
}

int remove_file(const char* path) {
    if (!path_exists(path)) return 0;
    return DeleteFileA(path) ? 0 : -1;
}

bool path_exists(const char* path) {
    if (!path) return false;
    DWORD attrs = GetFileAttributesA(path);
    return attrs != INVALID_FILE_ATTRIBUTES;
}

bool process_exists(const char* exe_name) {
    if (!exe_name || !exe_name[0]) return false;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return false;
    PROCESSENTRY32 pe = { .dwSize = sizeof(PROCESSENTRY32) };
    bool found = false;
    if (Process32First(snapshot, &pe)) {
        do {
            if (_stricmp(pe.szExeFile, exe_name) == 0) {
                found = true;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }
    CloseHandle(snapshot);
    return found;
}

int file_exists(const char** paths, int count, char*** out_existing, int* out_count) {
    *out_existing = NULL;
    *out_count = 0;

    /* First pass: count existing */
    for (int i = 0; i < count; i++) {
        if (path_exists(paths[i])) (*out_count)++;
    }

    if (*out_count == 0) return 0;

    *out_existing = (char**)malloc(sizeof(char*) * (*out_count));
    if (!*out_existing) {
        *out_count = 0;
        return -1;
    }

    int idx = 0;
    for (int i = 0; i < count; i++) {
        if (path_exists(paths[i])) {
            (*out_existing)[idx] = _strdup(paths[i]);
            if (!(*out_existing)[idx]) {
                /* Cleanup on failure */
                for (int j = 0; j < idx; j++) free((*out_existing)[j]);
                free(*out_existing);
                *out_existing = NULL;
                *out_count = 0;
                return -1;
            }
            idx++;
        }
    }
    return 0;
}

void file_exists_free(char** existing, int count) {
    if (existing) {
        for (int i = 0; i < count; i++) free(existing[i]);
        free(existing);
    }
}

int copy_file(const char* src, const char* dst) {
    return CopyFileA(src, dst, FALSE) ? 0 : -1;
}

/* ========== Output Formatting ========== */
void write_csv(const char** header, int header_count,
               const char*** data, int data_rows, int data_cols,
               const char* filename) {
    /* Ensure output directory exists */
    char dir[MAX_PATH];
    strncpy(dir, filename, sizeof(dir) - 1);
    char* last_sep = strrchr(dir, '\\');
    if (last_sep) {
        *last_sep = '\0';
        /* Create directory recursively */
        for (char* p = dir; *p; p++) {
            if (*p == '\\') {
                *p = '\0';
                CreateDirectoryA(dir, NULL);
                *p = '\\';
            }
        }
        CreateDirectoryA(dir, NULL);
    }

    char csv_path[MAX_PATH];
    snprintf(csv_path, sizeof(csv_path), "%s.csv", filename);

    FILE* f = fopen(csv_path, "w");
    if (!f) return;

    /* Write BOM for UTF-8 */
    fputs("\xEF\xBB\xBF", f);

    /* Write header */
    for (int i = 0; i < header_count; i++) {
        if (i > 0) fputc(',', f);
        /* CSV escape: wrap in quotes */
        fprintf(f, "\"%s\"", header[i] ? header[i] : "");
    }
    fputc('\n', f);

    /* Write data rows */
    for (int r = 0; r < data_rows; r++) {
        for (int c = 0; c < data_cols; c++) {
            if (c > 0) fputc(',', f);
            const char* val = data[r][c];
            if (val) {
                /* Escape internal quotes */
                fprintf(f, "\"");
                for (const char* p = val; *p; p++) {
                    if (*p == '"') fputs("\"\"", f);
                    else fputc(*p, f);
                }
                fprintf(f, "\"");
            }
        }
        fputc('\n', f);
    }
    fclose(f);
}

void write_json(const char** header, int header_count,
                const char*** data, int data_rows, int data_cols,
                const char* filename) {
    /* Ensure output directory exists */
    char dir[MAX_PATH];
    strncpy(dir, filename, sizeof(dir) - 1);
    char* last_sep = strrchr(dir, '\\');
    if (last_sep) {
        *last_sep = '\0';
        for (char* p = dir; *p; p++) {
            if (*p == '\\') { *p = '\0'; CreateDirectoryA(dir, NULL); *p = '\\'; }
        }
        CreateDirectoryA(dir, NULL);
    }

    char json_path[MAX_PATH];
    snprintf(json_path, sizeof(json_path), "%s.json", filename);

    FILE* f = fopen(json_path, "w");
    if (!f) return;

    fprintf(f, "[\n");
    for (int r = 0; r < data_rows; r++) {
        fprintf(f, "  {\n");
        for (int c = 0; c < data_cols && c < header_count; c++) {
            const char* key = header[c];
            const char* val = data[r][c] ? data[r][c] : "";
            fprintf(f, "    \"%s\": \"", key);
            /* Escape JSON string */
            for (const char* p = val; *p; p++) {
                switch (*p) {
                    case '"':  fputs("\\\"", f); break;
                    case '\\': fputs("\\\\", f); break;
                    case '\n': fputs("\\n", f); break;
                    case '\r': fputs("\\r", f); break;
                    case '\t': fputs("\\t", f); break;
                    default:   fputc(*p, f); break;
                }
            }
            fprintf(f, "\"%s\n", (c < data_cols - 1) ? "," : "");
        }
        fprintf(f, "  }%s\n", (r < data_rows - 1) ? "," : "");
    }
    fprintf(f, "]\n");
    fclose(f);
}

/* ========== Print Helpers ========== */
void print_normal(const char* msg) {
    if (g_print_out) puts(msg);
}

void print_success(const char* msg, int indent) {
    if (!g_print_out) return;
    for (int i = 0; i < indent; i++) printf("  ");
    printf("[+] %s\n", msg);
}

void print_fail(const char* msg, int indent) {
    if (!g_print_out) return;
    for (int i = 0; i < indent; i++) printf("  ");
    printf("[-] %s\n", msg);
}

void print_verbose(const char* msg) {
    printf("[*] %s\n", msg);
}

void print_browser_progress(const char* browser, const char* profile, const char* stage, const char* detail) {
    (void)browser;
    (void)profile;
    (void)stage;
    (void)detail;
}

/* ========== String Helpers ========== */
bool is_true_false(const char* value) {
    return (value && strcmp(value, "1") == 0);
}

const char* try_parse_same_site(const char* value) {
    if (!value) return "no_restriction";
    if (strcmp(value, "0") == 0) return "no_restriction";
    if (strcmp(value, "1") == 0) return "lax";
    if (strcmp(value, "2") == 0) return "strict";
    return "no_restriction";
}

bool is_high_integrity(void) {
    HANDLE h = CreateFileA(
        "C:\\Windows\\System32\\config\\system",
        GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL
    );
    if (h != INVALID_HANDLE_VALUE) {
        CloseHandle(h);
        return true;
    }
    return false;
}

/* ========== Dynamic String Builder ========== */
void sb_init(StrBuilder* sb) {
    /* Safe on reused statics: free the previous buffer so repeated
     * sb_init() calls don't leak the old allocation. Zero-initialized
     * (fresh/stack) structs pass NULL to free, which is a no-op. */
    free(sb->buf);
    sb->cap = 4096;
    sb->buf = (char*)malloc(sb->cap);
    if (sb->buf) sb->buf[0] = '\0';
    sb->len = 0;
}

/* Returns 1 if `extra` more bytes fit, 0 on allocation failure.
 * Callers MUST check: on 0 the buffer is untouched (no overflow). */
static int sb_ensure(StrBuilder* sb, size_t extra) {
    size_t new_cap;
    char* new_buf;
    if (sb->len + extra + 1 < sb->cap) return 1;
    new_cap = sb->cap ? sb->cap : 4096;
    while (new_cap < sb->len + extra + 1) new_cap *= 2;
    new_buf = (char*)realloc(sb->buf, new_cap);
    if (!new_buf) return 0;
    sb->buf = new_buf;
    sb->cap = new_cap;
    return 1;
}

void sb_write(StrBuilder* sb, const char* str) {
    size_t slen;
    if (!str) return;
    slen = strlen(str);
    if (!sb_ensure(sb, slen)) return;
    memcpy(sb->buf + sb->len, str, slen);
    sb->len += slen;
    sb->buf[sb->len] = '\0';
}

void sb_write_char(StrBuilder* sb, char c) {
    if (!sb_ensure(sb, 1)) return;
    sb->buf[sb->len++] = c;
    sb->buf[sb->len] = '\0';
}

void sb_write_int(StrBuilder* sb, int64_t val) {
    char tmp[32];
    snprintf(tmp, sizeof(tmp), "%lld", (long long)val);
    sb_write(sb, tmp);
}

void sb_printf(StrBuilder* sb, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    /* Determine length needed */
    {
        va_list args_copy;
        int needed;
        va_copy(args_copy, args);
        needed = vsnprintf(NULL, 0, fmt, args_copy);
        va_end(args_copy);
        if (needed <= 0) { va_end(args); return; }
        if (!sb_ensure(sb, (size_t)needed)) { va_end(args); return; }
        vsnprintf(sb->buf + sb->len, (size_t)needed + 1, fmt, args);
        sb->len += (size_t)needed;
    }
    va_end(args);
}

const char* sb_str(StrBuilder* sb) {
    return sb->buf ? sb->buf : "";
}

void sb_free(StrBuilder* sb) {
    free(sb->buf);
    sb->buf = NULL;
    sb->len = 0;
    sb->cap = 0;
}

/* ========== Recursive wildcard file/directory search ========== */
static int wildcard_match_ci(const char* pattern, const char* text) {
    while (*pattern) {
        if (*pattern == '*') {
            pattern++;
            if (!*pattern) return 1;
            while (*text) {
                if (wildcard_match_ci(pattern, text)) return 1;
                text++;
            }
            return 0;
        }
        if (*pattern == '?') {
            if (!*text) return 0;
        } else if (tolower((unsigned char)*pattern) != tolower((unsigned char)*text)) {
            return 0;
        }
        pattern++;
        text++;
    }
    return *text == '\0';
}

char* find_file_recursive(const char* base_dir, const char* filename, int max_depth) {
    if (!base_dir || !filename || max_depth < 0) return NULL;
    if (!path_exists(base_dir)) return NULL;

    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", base_dir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return NULL;

    char* result = NULL;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", base_dir, fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (max_depth > 0) {
                result = find_file_recursive(full_path, filename, max_depth - 1);
                if (result) break;
            }
        } else {
            if (wildcard_match_ci(filename, fd.cFileName)) {
                result = _strdup(full_path);
                break;
            }
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return result;
}

char* find_dir_recursive(const char* base_dir, const char* dirname, int max_depth) {
    if (!base_dir || !dirname || max_depth < 0) return NULL;
    if (!path_exists(base_dir)) return NULL;

    char search[MAX_PATH];
    snprintf(search, sizeof(search), "%s\\*", base_dir);
    WIN32_FIND_DATAA fd;
    HANDLE hFind = FindFirstFileA(search, &fd);
    if (hFind == INVALID_HANDLE_VALUE) return NULL;

    char* result = NULL;
    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0) continue;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;

        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s\\%s", base_dir, fd.cFileName);

        if (wildcard_match_ci(dirname, fd.cFileName)) {
            result = _strdup(full_path);
            break;
        }
        if (max_depth > 0) {
            result = find_dir_recursive(full_path, dirname, max_depth - 1);
            if (result) break;
        }
    } while (FindNextFileA(hFind, &fd));
    FindClose(hFind);
    return result;
}
