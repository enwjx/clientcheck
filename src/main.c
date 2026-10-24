#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <io.h>
#include <windows.h>

#include "tinycrypto.h"
#include "help.h"
#include "browser/utils.h"
#include "browser/sqlite.h"
#include "browser/crypto.h"
#include "browser/chromium.h"
#include "browser/firefox.h"
#include "browser/ie.h"
#include "dbeaver.h"
#include "filezilla.h"
#include "finalshell.h"
#include "navicat.h"
#include "rdp.h"
#include "remotecontrol.h"
#include "search.h"
#include "vnc.h"
#include "winscp.h"
#include "xshell.h"
#include "tortoisesvn.h"
#include "teamviewer.h"
#include "mobaxterm.h"
#include "wifi.h"

/* ================================================================
 * Module registry
 *
 * Every functional module is one entry. CLI surface:
 *   -all                 run everything (default set)
 *   -only <m1,m2,...>    run ONLY the listed modules/groups
 *   -no-<module>         exclude one module (works with -all and -only)
 *   -no-rdp/-no-browser/-no-sensitive   group toggles (compat)
 * Groups: "browser" -> chromium,firefox,ie ; "rdp" ; "sensitive"
 * ================================================================ */

typedef struct {
    const char* name;               /* CLI name */
    const char* label;              /* report section label */
    const char* (*run)(void);       /* module entry point */
    bool enabled;
    bool explicitly_disabled;       /* via -no-<module> / group toggle */
} Module;

/* Thin adapters so every entry shares one signature. */
static const char* run_todesk(void)      { return remotecontrol_scan("todesk"); }
static const char* run_sunlogin(void)    { return remotecontrol_scan("sunlogin"); }
static const char* run_dbeaver(void)     { return dbeaver_scan(NULL, NULL); }
static const char* run_finalshell(void)  { return finalshell_scan(NULL); }
static const char* run_xshell(void)      { return xshell_scan(NULL); }
static const char* run_xftp(void)        { return xftp_scan(NULL); }
static const char* run_xmanager(void)    { return xmanager_scan(NULL); }
static const char* run_filezilla(void)   { return filezilla_scan(NULL); }
static const char* run_navicat(void)     { return navicat_scan(NULL, true, 12); }
static const char* run_rdp(void)         { return rdp_scan(); }
static const char* run_winscp(void)      { return winscp_scan(NULL); }
static const char* run_vnc(void)         { return vnc_scan(); }
static const char* run_tortoisesvn(void) { return tortoisesvn_scan(); }
static const char* run_teamviewer(void)  { return teamviewer_scan(); }
static const char* run_chromium(void)    { return chromium_kernel(); }
static const char* run_firefox(void)     { return firefox_get(); }
static const char* run_ie(void)          { return ie_get(); }
static const char* run_moba(void)        { return mobaxterm_scan(); }
static const char* run_wifi(void)        { return wifi_scan(); }

static Module g_modules[] = {
    { "todesk",      "ToDesk",            run_todesk },
    { "sunlogin",    "Sunlogin",          run_sunlogin },
    { "dbeaver",     "DBeaver",           run_dbeaver },
    { "finalshell",  "FinalShell",        run_finalshell },
    { "xshell",      "Xshell",            run_xshell },
    { "xftp",        "Xftp",              run_xftp },
    { "xmanager",    "Xmanager",          run_xmanager },
    { "filezilla",   "FileZilla",         run_filezilla },
    { "navicat",     "Navicat",           run_navicat },
    { "rdp",         "RDP",               run_rdp },
    { "winscp",      "WinSCP",            run_winscp },
    { "vnc",         "VNC",               run_vnc },
    { "tortoisesvn", "TortoiseSVN",       run_tortoisesvn },
    { "teamviewer",  "TeamViewer",        run_teamviewer },
    { "chromium",    "Chromium Browsers", run_chromium },
    { "firefox",     "Firefox",           run_firefox },
    { "ie",          "IE",                run_ie },
    { "mobaxterm",   "MobaXterm",         run_moba },
    { "wifi",        "WiFi Passwords",    run_wifi },
    { "sensitive",   "Search",            NULL },  /* needs args; special-cased */
};
#define MODULE_COUNT (int)(sizeof(g_modules) / sizeof(g_modules[0]))

static Module* find_module(const char* name) {
    for (int i = 0; i < MODULE_COUNT; i++)
        if (_stricmp(g_modules[i].name, name) == 0) return &g_modules[i];
    return NULL;
}

/* Does a query token (module name or group) match a module? */
static bool module_in_group(Module* m, const char* q) {
    if (_stricmp(m->name, q) == 0) return true;
    if (_stricmp(q, "browser") == 0 || _stricmp(q, "browsers") == 0)
        return strcmp(m->name, "chromium") == 0 ||
               strcmp(m->name, "firefox") == 0 ||
               strcmp(m->name, "ie") == 0;
    if (_stricmp(q, "rdp") == 0)       return strcmp(m->name, "rdp") == 0;
    if (_stricmp(q, "sensitive") == 0) return strcmp(m->name, "sensitive") == 0;
    if (_stricmp(q, "remote") == 0)
        return strcmp(m->name, "todesk") == 0 ||
               strcmp(m->name, "sunlogin") == 0 ||
               strcmp(m->name, "teamviewer") == 0;
    return false;
}

typedef struct {
    bool help;
    bool all;
    bool only_mode;
    char only_list[512];
    bool sensitive_mode;
    char browser_format[16];
    char output[512];
} CLIArgs;

static void init_args(CLIArgs* a) {
    memset(a, 0, sizeof(CLIArgs));
    a->all = true;
}

static void print_module_names(void) {
    fprintf(stderr, "Modules:");
    for (int m = 0; m < MODULE_COUNT; m++)
        fprintf(stderr, "%s %s", m ? "," : "", g_modules[m].name);
    fprintf(stderr, "\nGroups:  browser (= chromium,firefox,ie), rdp, sensitive, remote\n");
}

static bool parse_args(int argc, char** argv, CLIArgs* a) {
    init_args(a);
    /* default: every module enabled unless -no-* / -only says otherwise */
    for (int m = 0; m < MODULE_COUNT; m++) {
        g_modules[m].enabled = true;
        g_modules[m].explicitly_disabled = false;
    }
    for (int i = 1; i < argc; i++) {
        const char* arg = argv[i];
        if (strcmp(arg, "-all") == 0) {
            a->all = true;
        } else if (strcmp(arg, "-only") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "ERROR: -only requires a comma-separated module list.\n\n");
                print_module_names();
                return false;
            }
            a->only_mode = true;
            strncpy(a->only_list, argv[++i], sizeof(a->only_list) - 1);
        } else if (strcmp(arg, "-moba-master") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "ERROR: -moba-master requires the MobaXterm master password.\n\n");
                return false;
            }
            moba_set_master_password(argv[++i]);
        } else if (strcmp(arg, "-rdp-extended") == 0) {
            rdp_set_extended(1);
        } else if (strncmp(arg, "-no-", 4) == 0) {
            const char* what = arg + 4;
            if (!what[0]) {
                fprintf(stderr, "ERROR: -no- requires a module name.\n\n");
                print_module_names();
                return false;
            }
            bool matched = false;
            for (int m = 0; m < MODULE_COUNT; m++) {
                if (module_in_group(&g_modules[m], what)) {
                    g_modules[m].enabled = false;
                    g_modules[m].explicitly_disabled = true;
                    matched = true;
                }
            }
            if (!matched) {
                fprintf(stderr, "ERROR: Unknown module in %s.\n\n", arg);
                print_module_names();
                return false;
            }
        } else if (strcmp(arg, "-rdp") == 0 || strcmp(arg, "-browser") == 0 ||
                   strcmp(arg, "-sensitive") == 0) {
            /* enable-only group flags kept for compatibility; modules default on */
        } else if (strcmp(arg, "-sensitive-mode") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "ERROR: -sensitive-mode requires normal or strict.\n\n");
                return false;
            }
            i++;
            if (_stricmp(argv[i], "normal") == 0) a->sensitive_mode = 0;
            else if (_stricmp(argv[i], "strict") == 0) a->sensitive_mode = 1;
            else {
                fprintf(stderr, "ERROR: Unsupported sensitive mode: %s\n\n", argv[i]);
                return false;
            }
        } else if (strcmp(arg, "-browser-format") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "ERROR: -browser-format requires csv or json.\n\n");
                return false;
            }
            i++;
            if (_stricmp(argv[i], "csv") == 0 || _stricmp(argv[i], "json") == 0) {
                strncpy(a->browser_format, argv[i], sizeof(a->browser_format) - 1);
            } else {
                fprintf(stderr, "ERROR: Unsupported browser format: %s (use csv or json)\n\n", argv[i]);
                return false;
            }
        } else if (strcmp(arg, "-modules") == 0) {
            fprintf(stderr, "Available modules and groups:\n");
            print_module_names();
            exit(0);
        } else if (strcmp(arg, "-help") == 0 || strcmp(arg, "--help") == 0 || strcmp(arg, "-h") == 0) {
            a->help = true;
        } else if (strcmp(arg, "-output") == 0) {
            if (i + 1 >= argc || argv[i + 1][0] == '-') {
                fprintf(stderr, "ERROR: -output requires a file path.\n\n");
                return false;
            }
            strncpy(a->output, argv[++i], sizeof(a->output) - 1);
        } else {
            fprintf(stderr, "ERROR: Unsupported option: %s\n\n", arg);
            print_module_names();
            return false;
        }
    }

    /* resolve -only: enable exactly the listed modules/groups */
    if (a->only_mode) {
        for (int m = 0; m < MODULE_COUNT; m++) g_modules[m].enabled = false;
        char list[512];
        strncpy(list, a->only_list, sizeof(list) - 1);
        list[sizeof(list) - 1] = 0;
        char* ctx = NULL;
        char* tok = strtok_s(list, ",", &ctx);
        bool any = false;
        while (tok) {
            bool matched = false;
            for (int m = 0; m < MODULE_COUNT; m++) {
                if (module_in_group(&g_modules[m], tok)) {
                    if (!g_modules[m].explicitly_disabled) g_modules[m].enabled = true;
                    matched = true;
                    any = true;
                }
            }
            if (!matched) {
                fprintf(stderr, "ERROR: Unknown module in -only: %s\n\n", tok);
                print_module_names();
                return false;
            }
            tok = strtok_s(NULL, ",", &ctx);
        }
        if (!any) {
            fprintf(stderr, "ERROR: -only produced an empty module set.\n\n");
            return false;
        }
    }
    return true;
}

static bool validate_args(const CLIArgs* a) {
    if (a->help) return true;
    if (!a->output[0]) {
        fprintf(stderr, "ERROR: -output <file> is required.\n\n");
        return false;
    }
    int enabled = 0;
    for (int m = 0; m < MODULE_COUNT; m++)
        if (g_modules[m].enabled) enabled++;
    if (!enabled) {
        fprintf(stderr, "ERROR: No modules selected (use -all, or -only <list>, or drop -no-*).\n\n");
        return false;
    }
    return true;
}

static const char* run_sensitive_module(const CLIArgs* a) {
    char search_path[512] = {0};
    GetEnvironmentVariableA("USERPROFILE", search_path, sizeof(search_path) - 1);
    if (!search_path[0]) strcpy(search_path, "C:");
    return search_config(search_args(search_path, "", false, "", false,
                                     a->sensitive_mode ? (10 * 1024 * 1024) : (2 * 1024 * 1024),
                                     a->sensitive_mode ? 1000 : 500,
                                     a->sensitive_mode ? 20 : 8,
                                     a->sensitive_mode));
}

int main(int argc, char** argv) {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    /* RDP DPAPI helper must run before CLI validation / self-tests that may alter context. */
    {
        int helper_rc = rdp_try_internal_helper(argc, argv);
        if (helper_rc >= 0) return helper_rc;
    }

    if (tc_self_test() != 0) {
        fprintf(stderr, "FATAL: Crypto self-test failed!\n");
        return 1;
    }

    setbuf(stdout, NULL);

    CLIArgs a;
    if (!parse_args(argc, argv, &a) || !validate_args(&a)) {
        show_help();
        return 1;
    }
    if (a.help) {
        show_help();
        return 0;
    }

    FILE* outfile_ptr = fopen(a.output, "wb");
    if (!outfile_ptr) {
        fprintf(stderr, "ERROR: Cannot create %s\n", a.output);
        return 1;
    }
    setbuf(outfile_ptr, NULL);
    {
        unsigned char bom[] = { 0xEF, 0xBB, 0xBF };
        fwrite(bom, 1, 3, outfile_ptr);
    }

    fflush(stdout);
    int stdout_backup = _dup(_fileno(stdout));
    if (stdout_backup < 0 || _dup2(_fileno(outfile_ptr), _fileno(stdout)) != 0) {
        if (stdout_backup >= 0) _close(stdout_backup);
        fclose(outfile_ptr);
        fprintf(stderr, "ERROR: Cannot redirect output to %s\n", a.output);
        return 1;
    }
    g_print_out = false;

    /* browser export options apply whenever the chromium module runs;
     * export dir defaults next to the -output file so a read-only CWD
     * never silently drops the CSV/JSON exports */
    {
        Module* ch = find_module("chromium");
        if (ch && ch->enabled) {
            char export_dir[512];
            strncpy(export_dir, a.output, sizeof(export_dir) - 5);
            export_dir[sizeof(export_dir) - 5] = 0;
            char* slash = max(strrchr(export_dir, '\\'), strrchr(export_dir, '/'));
            if (slash) *slash = 0;
            else strcpy(export_dir, ".");
            strncat(export_dir, "\\out", sizeof(export_dir) - strlen(export_dir) - 1);
            browser_set_format(a.browser_format[0] ? a.browser_format : NULL);
            browser_set_output_dir(export_dir);
            browser_set_limit("2000");
        }
    }

    printf("Modules enabled:");
    for (int m = 0; m < MODULE_COUNT; m++)
        if (g_modules[m].enabled) printf(" %s", g_modules[m].name);
    printf("\n\n");

    /* per-module runtime stats for the tail summary */
    struct ModStat { char name[64]; unsigned long ms; int findings; };
    static struct ModStat stats[32];
    int stat_n = 0;
    const ULONGLONG run_start = GetTickCount64();

    for (int m = 0; m < MODULE_COUNT; m++) {
        Module* mod = &g_modules[m];
        if (!mod->enabled && !mod->explicitly_disabled)
            continue;  /* filtered by -only: no output noise */

        printf(">>> %s\n", mod->label);
        if (mod->explicitly_disabled) {
            printf("  Skipped by option: -no-%s\n\n", mod->name);
            continue;
        }
        ULONGLONG t0 = GetTickCount64();
        const char* r = (strcmp(mod->name, "sensitive") == 0)
            ? run_sensitive_module(&a)
            : mod->run();
        ULONGLONG dt = GetTickCount64() - t0;

        int findings = 0;
        if (r && *r) {
            for (const char* p = r; (p = strstr(p, "[+]")) != NULL; p += 3) findings++;
            printf("===== %s =====\n%s\n\n", mod->label, r);
        } else {
            printf("  (none)\n");
        }
        if (stat_n < 32) {
            snprintf(stats[stat_n].name, sizeof(stats[stat_n].name), "%s", mod->name);
            stats[stat_n].ms = (unsigned long)dt;
            stats[stat_n].findings = findings;
            stat_n++;
        }
    }

    printf("\n===== Summary =====\n");
    printf("  %-14s %10s  %s\n", "Module", "Time (ms)", "Findings");
    for (int i = 0; i < stat_n; i++)
        printf("  %-14s %10lu  %d\n", stats[i].name, stats[i].ms, stats[i].findings);
    printf("  %-14s %10lu\n", "Total", (unsigned long)(GetTickCount64() - run_start));

    fflush(stdout);
    _dup2(stdout_backup, _fileno(stdout));
    _close(stdout_backup);
    fclose(outfile_ptr);

    {
        long sz = 0;
        FILE* f2 = fopen(a.output, "rb");
        if (f2) { fseek(f2, 0, SEEK_END); sz = ftell(f2); fclose(f2); }
        fprintf(stderr, "OK: %s (%ld bytes UTF-8)\n", a.output, sz);
    }

    return 0;
}
