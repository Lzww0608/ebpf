#ifndef __RM_MONITOR_FORMAT_H
#define __RM_MONITOR_FORMAT_H

#include <stddef.h>
#include <stdio.h>

static inline const char *rm_monitor_status(long ret) {
    return ret == 0 ? "OK" : "FAIL";
}

static inline int rm_monitor_errno(long ret) {
    return ret < 0 ? (int)-ret : 0;
}

static inline void rm_monitor_format_cmdline(
    char *dst,
    size_t dst_len,
    const char *cmdline,
    unsigned int cmdline_len,
    const char *fallback
) {
    size_t out = 0;

    if (!dst_len)
        return;

    dst[0] = '\0';

    if (!cmdline || cmdline_len == 0) {
        snprintf(dst, dst_len, "%s", fallback ? fallback : "");
        return;
    }

    for (unsigned int i = 0; i < cmdline_len && out + 1 < dst_len; i++) {
        unsigned char ch = (unsigned char)cmdline[i];

        if (ch == '\0') {
            if (out > 0 && dst[out - 1] != ' ')
                dst[out++] = ' ';
            continue;
        }

        dst[out++] = (ch < ' ' || ch == 0x7f) ? '?' : (char)ch;
    }

    while (out > 0 && dst[out - 1] == ' ')
        out--;

    if (out == 0) {
        snprintf(dst, dst_len, "%s", fallback ? fallback : "");
        return;
    }

    dst[out] = '\0';
}

#endif
