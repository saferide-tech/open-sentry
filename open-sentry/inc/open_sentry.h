#ifndef OPEN_SENTRY_H
#define OPEN_SENTRY_H

#define STR_MAX_SIZE            512

#ifndef MIN
#define MIN(a,b)        (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b)        (((a)>(b))?(a):(b))
#endif

#ifndef ARRAYSIZE
#define ARRAYSIZE(arr)  (sizeof(arr) / sizeof(arr[0]))
#endif

/* logging defs*/
#define MAX_LOG_FILE_NUM    11 /* allways one more than we actually need */
#define MAX_LOG_FILE_SIZE   0x100000
#define LOG_FILES_DIR       "/var/log"
#define LOG_FILE            "sentry.log"

/* some CEF msg defines */
#define CEF_VER             0
#define DEVICE_VENDOR       "SafeRide"
#define DEVICE_PRODUCT      "OpenSentry"
#define DEVICE_VERSION      "1.0"
#define DEMO_VIN            "OpenSentryDEMO123"

/* logger functions and defs */
void log_event(char* event);

#endif /* OPEN_SENTRY_H */
