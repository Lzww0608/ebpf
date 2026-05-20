#include <assert.h>
#include <string.h>

#include "rm_monitor_format.h"
#include "rm_monitor.h"

static void test_formats_resolved_path_from_lsm_dir_and_name(void) {
    struct event e = {};
    char out[RM_MONITOR_RESOLVED_PATH_LEN + RM_MONITOR_NAME_LEN + 2];

    e.event_flags = EVENT_F_PATH_RESOLVED;
    strcpy(e.resolved_path, "/tmp");
    strcpy(e.target_name, "victim");

    rm_monitor_format_resolved_path(out, sizeof(out), &e);

    assert(strcmp(out, "/tmp/victim") == 0);
}

static void test_formats_root_resolved_path_without_double_slash(void) {
    struct event e = {};
    char out[RM_MONITOR_RESOLVED_PATH_LEN + RM_MONITOR_NAME_LEN + 2];

    e.event_flags = EVENT_F_PATH_RESOLVED;
    strcpy(e.resolved_path, "/");
    strcpy(e.target_name, "victim");

    rm_monitor_format_resolved_path(out, sizeof(out), &e);

    assert(strcmp(out, "/victim") == 0);
}

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
    test_formats_resolved_path_from_lsm_dir_and_name();
    test_formats_root_resolved_path_without_double_slash();
    test_formats_nul_separated_cmdline();
    test_falls_back_to_comm_when_cmdline_is_empty();
    test_formats_ret_as_status_and_errno();
    return 0;
}
