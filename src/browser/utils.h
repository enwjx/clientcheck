#ifndef BROWSER_UTILS_H
#define BROWSER_UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

/* Global state (mirrors Go package-level vars) */
extern char  g_browser_name[256];
extern char  g_browser_limit[32];
extern char* g_system_key;
extern int   g_system_key_len;
extern char  g_format[16];
extern bool  g_print_out;
extern char  g_output_dir[512];

/* Setters (equivalent to Go's SetFormat/SetOutputDir/SetLimit) */
void browser_set_format(const char* format);
void browser_set_output_dir(const char* dir);
void browser_set_limit(const char* limit);
void browser_set_browser_name(const char* name);

/* Time conversion: Windows epoch (1601) to Unix epoch */
time_t time_epoch(int64_t timestamp);
int   time_epoch_str(int64_t timestamp, char* out, int out_size);

/* File operations */
int  create_tmp_file(const char* src_path, char* out_path, int out_size);
int  remove_file(const char* path);
bool path_exists(const char* path);
bool process_exists(const char* exe_name);
int  file_exists(const char** paths, int count, char*** out_existing, int* out_count);
void file_exists_free(char** existing, int count);
int  copy_file(const char* src, const char* dst);

/* Output formatting */
void write_csv(const char** header, int header_count, const char*** data, int data_rows, int data_cols, const char* filename);
void write_json(const char** header, int header_count, const char*** data, int data_rows, int data_cols, const char* filename);

/* Print helpers */
void print_normal(const char* msg);
void print_success(const char* msg, int indent);
void print_fail(const char* msg, int indent);
void print_verbose(const char* msg);
void print_browser_progress(const char* browser, const char* profile, const char* stage, const char* detail);

/* String helpers */
bool  is_true_false(const char* value);
const char* try_parse_same_site(const char* value);
bool  is_high_integrity(void);

/* Dynamic string builder (replaces Go's strings.Builder) */
typedef struct {
    char*  buf;
    size_t len;
    size_t cap;
} StrBuilder;

void sb_init(StrBuilder* sb);
void sb_write(StrBuilder* sb, const char* str);
void sb_write_char(StrBuilder* sb, char c);
void sb_write_int(StrBuilder* sb, int64_t val);
void sb_printf(StrBuilder* sb, const char* fmt, ...);
const char* sb_str(StrBuilder* sb);
void sb_free(StrBuilder* sb);

/* Recursive file/directory search (returns allocated path or NULL) */
char* find_file_recursive(const char* base_dir, const char* filename, int max_depth);
char* find_dir_recursive(const char* base_dir, const char* dirname, int max_depth);

#endif /* BROWSER_UTILS_H */
