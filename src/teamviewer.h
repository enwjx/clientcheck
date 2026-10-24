/*
 * TeamViewer — reads ID / password shown in the main window via
 * FindWindow + EnumChildWindows + WM_GETTEXT (SharpDecryptPwd approach).
 * TeamViewer must be running with its main window open.
 */
#ifndef TEAMVIEWER_H
#define TEAMVIEWER_H
const char* teamviewer_scan(void);
#endif
