#ifndef BROWSER_CHROMIUM_H
#define BROWSER_CHROMIUM_H

const char* chromium_kernel(void);
const char* chromium_specify_path(const char* browser_name, const char* path);
const char* chromium_history(const char* chrome_path, const char* browser_name);
const char* chromium_download(const char* chrome_path, const char* browser_name);
const char* chromium_cookies(const char* cookie_path, const char* state_file, const char* browser_name);
const char* chromium_bookmark(const char* bookmark_path);
const char* chromium_logins(const char* login_path, const char* state_file, const char* browser_name);
const char* chromium_creditcards(const char* web_data_path, const char* state_file, const char* browser_name);
const char* chromium_extensions(const char* secure_preferences_path, const char* browser_name);
const char* chromium_local_storage(const char* local_storage_dir, const char* browser_name);
const char* chromium_session_storage(const char* session_storage_dir, const char* browser_name);

#endif /* BROWSER_CHROMIUM_H */
