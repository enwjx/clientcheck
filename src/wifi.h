#ifndef WIFI_H
#define WIFI_H

/* Saved WiFi profiles with plaintext passwords via the Windows WLAN service
 * (wlanapi.dll loaded dynamically; WlanGetProfile with
 * WLAN_PROFILE_GET_PLAINTEXT_KEY). */
const char* wifi_scan(void);

#endif
