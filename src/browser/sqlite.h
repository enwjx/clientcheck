#ifndef BROWSER_SQLITE_H
#define BROWSER_SQLITE_H

#include <stdbool.h>

typedef struct SQLiteHandler SQLiteHandler;

SQLiteHandler* sqlite_open(const char* file_path);
void           sqlite_close(SQLiteHandler* h);

/* Returns table names (caller must free each string and the array) */
char** sqlite_get_table_names(SQLiteHandler* h, int* count);

/* Read a table into memory. Returns true if table has rows. */
bool sqlite_read_table(SQLiteHandler* h, const char* table_name);

int         sqlite_get_row_count(SQLiteHandler* h);
int         sqlite_get_field_count(SQLiteHandler* h);
const char* sqlite_get_field_name(SQLiteHandler* h, int col_idx);
const char* sqlite_get_value(SQLiteHandler* h, int row_idx, const char* column_name);
const char* sqlite_get_value_by_index(SQLiteHandler* h, int row_idx, int col_idx);

/* Get the current table name */
const char* sqlite_get_table_name(SQLiteHandler* h);

#endif /* BROWSER_SQLITE_H */
