#ifndef SEARCH_H
#define SEARCH_H
#include <stdint.h>
#include <stdbool.h>

typedef struct {
    const char* path;
    const char* user_regex_list;  /* comma-separated */
    bool        user_only;
    const char* custom_file_types;
    bool        exten_only;
    int64_t     size_limit;
    int         char_limit;
    int         max_matches_per_file;
    int         mode;
} SearchArgs;

SearchArgs search_args(const char* path, const char* user_regex, bool user_only,
                       const char* file_types, bool exten_only,
                       int64_t size_limit, int char_limit, int max_matches_per_file, int mode);
const char* search_config(SearchArgs args);
#endif
