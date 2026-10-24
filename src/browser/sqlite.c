/*
 * SQLite3 Wrapper — mirrors Go's SQLiteHandler from browser/sqlite.go
 * Wraps sqlite3 operations into a simple row-major string-based API.
 */
#include "browser/sqlite.h"
#include "browser/utils.h"
#include "sqlite3.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "tinycrypto.h"

/* ====================================================================
 * Internal structure
 * ==================================================================== */
struct SQLiteHandler {
    sqlite3*     db;
    char*        table_name;
    char**       field_names;
    int          field_count;
    char***      rows;       /* rows[row][col] */
    int          row_count;
    int          row_capacity;
    char**       columns;    /* column name array from data query */
    int          col_count;
};

/* ====================================================================
 * Base64 encode for binary columns (matches Go's behavior)
 * ==================================================================== */
static char* encode_base64(const void* data, int len) {
    if (!data || len <= 0) return _strdup("");
    int b64_len = ((len + 2) / 3) * 4 + 1;
    char* b64 = (char*)malloc(b64_len);
    if (!b64) return _strdup("");
    tc_base64_encode((const uint8_t*)data, len, b64);
    return b64;
}

/* ====================================================================
 * Create / Destroy
 * ==================================================================== */
SQLiteHandler* sqlite_open(const char* file_path) {
    sqlite3* raw_db = NULL;
    int rc = sqlite3_open_v2(file_path, &raw_db,
                              SQLITE_OPEN_READONLY, NULL);
    if (rc != SQLITE_OK) {
        if (raw_db) sqlite3_close(raw_db);
        fprintf(stderr, "[-] Failed to open SQLite DB: %s\n", file_path);
        return NULL;
    }

    SQLiteHandler* h = (SQLiteHandler*)calloc(1, sizeof(SQLiteHandler));
    if (!h) {
        sqlite3_close(raw_db);
        return NULL;
    }
    h->db = raw_db;
    h->table_name = NULL;
    h->field_names = NULL;
    h->field_count = 0;
    h->rows = NULL;
    h->row_count = 0;
    h->row_capacity = 0;
    h->columns = NULL;
    h->col_count = 0;
    return h;
}

void sqlite_close(SQLiteHandler* h) {
    if (!h) return;
    if (h->db) sqlite3_close(h->db);
    free(h->table_name);
    if (h->field_names) {
        for (int i = 0; i < h->field_count; i++) free(h->field_names[i]);
        free(h->field_names);
    }
    if (h->rows) {
        for (int r = 0; r < h->row_count; r++) {
            for (int c = 0; c < h->col_count; c++) free(h->rows[r][c]);
            free(h->rows[r]);
        }
        free(h->rows);
    }
    if (h->columns) {
        for (int c = 0; c < h->col_count; c++) free(h->columns[c]);
        free(h->columns);
    }
    free(h);
}

/* ====================================================================
 * Table operations
 * ==================================================================== */
bool sqlite_read_table(SQLiteHandler* h, const char* table_name) {
    if (!h || !table_name) return false;

    /* Free previous data */
    free(h->table_name);
    if (h->field_names) {
        for (int i = 0; i < h->field_count; i++) free(h->field_names[i]);
        free(h->field_names);
        h->field_names = NULL;
        h->field_count = 0;
    }
    if (h->rows) {
        for (int r = 0; r < h->row_count; r++) {
            for (int c = 0; c < h->col_count; c++) free(h->rows[r][c]);
            free(h->rows[r]);
        }
        free(h->rows);
        h->rows = NULL;
        h->row_count = 0;
        h->row_capacity = 0;
    }
    if (h->columns) {
        for (int c = 0; c < h->col_count; c++) free(h->columns[c]);
        free(h->columns);
        h->columns = NULL;
        h->col_count = 0;
    }

    h->table_name = _strdup(table_name);

    /* Check if table exists */
    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(h->db,
        "SELECT count(*) FROM sqlite_master WHERE type='table' AND name=?",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;
    sqlite3_bind_text(stmt, 1, table_name, -1, SQLITE_STATIC);
    rc = sqlite3_step(stmt);
    int exists = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
    sqlite3_finalize(stmt);
    if (!exists) {
        printf("[-] Table '%s' not found\n", table_name);
        return false;
    }

    /* Get table schema via PRAGMA */
    char pragma_sql[512];
    snprintf(pragma_sql, sizeof(pragma_sql), "PRAGMA table_info(%s)", table_name);
    rc = sqlite3_prepare_v2(h->db, pragma_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    /* Count columns first */
    int col_count = 0;
    while (sqlite3_step(stmt) == SQLITE_ROW) col_count++;
    sqlite3_finalize(stmt);

    if (col_count == 0) return false;

    h->field_count = col_count;
    h->field_names = (char**)calloc(col_count, sizeof(char*));

    /* Re-query to get names */
    rc = sqlite3_prepare_v2(h->db, pragma_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) {
        free(h->field_names);
        h->field_names = NULL;
        h->field_count = 0;
        return false;
    }
    for (int i = 0; i < col_count; i++) {
        sqlite3_step(stmt);
        const char* name = (const char*)sqlite3_column_text(stmt, 1); /* name column */
        h->field_names[i] = name ? _strdup(name) : _strdup("");
    }
    sqlite3_finalize(stmt);

    /* Query data — use LIMIT from global config */
    char query_sql[1024];
    snprintf(query_sql, sizeof(query_sql), "SELECT * FROM %s LIMIT %s",
             table_name, g_browser_limit[0] ? g_browser_limit : "2000");
    rc = sqlite3_prepare_v2(h->db, query_sql, -1, &stmt, NULL);
    if (rc != SQLITE_OK) return false;

    /* Get actual column names and count from result */
    h->col_count = sqlite3_column_count(stmt);
    h->columns = (char**)calloc(h->col_count, sizeof(char*));
    for (int i = 0; i < h->col_count; i++) {
        const char* col_name = sqlite3_column_name(stmt, i);
        h->columns[i] = col_name ? _strdup(col_name) : _strdup("");
    }

    /* Pre-allocate rows */
    h->row_capacity = 256;
    h->row_count = 0;
    h->rows = (char***)malloc(sizeof(char**) * h->row_capacity);

    while (sqlite3_step(stmt) == SQLITE_ROW) {
        /* Resize if needed */
        if (h->row_count >= h->row_capacity) {
            h->row_capacity *= 2;
            char*** new_rows = (char***)realloc(h->rows, sizeof(char**) * h->row_capacity);
            if (!new_rows) break;
            h->rows = new_rows;
        }

        char** row = (char**)calloc(h->col_count, sizeof(char*));
        for (int c = 0; c < h->col_count; c++) {
            int col_type = sqlite3_column_type(stmt, c);
            switch (col_type) {
                case SQLITE_BLOB: {
                    const void* blob = sqlite3_column_blob(stmt, c);
                    int blob_len = sqlite3_column_bytes(stmt, c);
                    row[c] = encode_base64(blob, blob_len);
                    break;
                }
                case SQLITE_NULL:
                    row[c] = _strdup("");
                    break;
                case SQLITE_INTEGER: {
                    sqlite3_int64 val = sqlite3_column_int64(stmt, c);
                    char buf[32];
                    snprintf(buf, sizeof(buf), "%lld", (long long)val);
                    row[c] = _strdup(buf);
                    break;
                }
                case SQLITE_FLOAT: {
                    double val = sqlite3_column_double(stmt, c);
                    char buf[64];
                    snprintf(buf, sizeof(buf), "%g", val);
                    row[c] = _strdup(buf);
                    break;
                }
                case SQLITE_TEXT:
                default: {
                    const unsigned char* text = sqlite3_column_text(stmt, c);
                    row[c] = text ? _strdup((const char*)text) : _strdup("");
                    break;
                }
            }
        }
        h->rows[h->row_count++] = row;
    }
    sqlite3_finalize(stmt);

    return h->row_count > 0;
}

/* ====================================================================
 * Data access
 * ==================================================================== */
int sqlite_get_row_count(SQLiteHandler* h) {
    return h ? h->row_count : 0;
}

int sqlite_get_field_count(SQLiteHandler* h) {
    return h ? h->field_count : 0;
}

const char* sqlite_get_field_name(SQLiteHandler* h, int col_idx) {
    if (!h || col_idx < 0 || col_idx >= h->field_count) return "";
    return h->field_names[col_idx] ? h->field_names[col_idx] : "";
}

const char* sqlite_get_value(SQLiteHandler* h, int row_idx, const char* column_name) {
    if (!h || !column_name || row_idx < 0 || row_idx >= h->row_count) return "";
    /* Find column index */
    for (int c = 0; c < h->col_count; c++) {
        if (h->columns[c] && strcmp(h->columns[c], column_name) == 0) {
            return h->rows[row_idx][c] ? h->rows[row_idx][c] : "";
        }
    }
    return "";
}

const char* sqlite_get_value_by_index(SQLiteHandler* h, int row_idx, int col_idx) {
    if (!h || row_idx < 0 || row_idx >= h->row_count) return "";
    if (col_idx < 0 || col_idx >= h->col_count) return "";
    return h->rows[row_idx][col_idx] ? h->rows[row_idx][col_idx] : "";
}

const char* sqlite_get_table_name(SQLiteHandler* h) {
    return h ? (h->table_name ? h->table_name : "") : "";
}

char** sqlite_get_table_names(SQLiteHandler* h, int* count) {
    *count = 0;
    if (!h) return NULL;

    sqlite3_stmt* stmt = NULL;
    int rc = sqlite3_prepare_v2(h->db,
        "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name",
        -1, &stmt, NULL);
    if (rc != SQLITE_OK) return NULL;

    int cap = 32;
    char** tables = (char**)malloc(sizeof(char*) * cap);
    if (!tables) { sqlite3_finalize(stmt); return NULL; }
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        const char* name = (const char*)sqlite3_column_text(stmt, 0);
        if (name) {
            if (*count >= cap) {
                cap *= 2;
                char** grown = (char**)realloc(tables, sizeof(char*) * cap);
                if (!grown) { sqlite3_finalize(stmt); return tables; /* partial list */ }
                tables = grown;
            }
            tables[(*count)++] = _strdup(name);
        }
    }
    sqlite3_finalize(stmt);
    return tables;
}
