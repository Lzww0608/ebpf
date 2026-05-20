#include <assert.h>
#include <string.h>

#include "rm_monitor_format.h"

static void test_formats_nul_separated_cmdline(void) {
    const char cmdline[] = {
        'r', 'm', '\0',
        '-', 'r', 'f', '\0',
        't', 'm', 'p', '/', 'a', ' ', 'b', '\0',
    };
    char out[64];

    rm_monitor_format_cmdline(out, sizeof(out), cmdline, sizeof(cmdline), "rm");

    assert(strcmp(out, "rm -rf tmp/a b") == 0);
}

static void test_falls_back_to_comm_when_cmdline_is_empty(void) {
    char out[64];

    rm_monitor_format_cmdline(out, sizeof(out), "", 0, "rm");

    assert(strcmp(out, "rm") == 0);
}

static void test_formats_ret_as_status_and_errno(void) {
    assert(strcmp(rm_monitor_status(0), "OK") == 0);
    assert(rm_monitor_errno(0) == 0);

    assert(strcmp(rm_monitor_status(-2), "FAIL") == 0);
    assert(rm_monitor_errno(-2) == 2);
}

int main(void) {
    test_formats_nul_separated_cmdline();
    test_falls_back_to_comm_when_cmdline_is_empty();
    test_formats_ret_as_status_and_errno();
    return 0;
}
