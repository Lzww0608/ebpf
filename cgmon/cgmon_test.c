#include <assert.h>
#include <string.h>

#ifndef CGMON_UNIT_TEST
#define CGMON_UNIT_TEST
#endif
#include "cgmon.c"

static void test_extracts_short_docker_scope_name(void)
{
    char out[MAX_NAME_LEN];

    cgmon_extract_name("/sys/fs/cgroup/system.slice/docker-1234567890abcdef.scope",
                       out, sizeof(out));

    assert(strcmp(out, "1234567890ab") == 0);
}

static void test_recognizes_kubepods_container_scope(void)
{
    assert(cgmon_looks_like_container_cgroup(
        "/sys/fs/cgroup/kubepods.slice/pod123/cri-containerd-abcdef1234567890.scope"));
}

static void test_rejects_short_non_container_path(void)
{
    assert(!cgmon_looks_like_container_cgroup("/sys/fs/cgroup/system.slice/ssh.service"));
}

static void test_parses_io_stat_line_bytes(void)
{
    unsigned long long rbytes = 0;
    unsigned long long wbytes = 0;

    cgmon_parse_io_stat_line("8:0 rbytes=1048576 wbytes=2097152 rios=2 wios=3",
                             &rbytes, &wbytes);

    assert(rbytes == 1048576);
    assert(wbytes == 2097152);
}

static void test_parse_io_stat_line_accumulates(void)
{
    unsigned long long rbytes = 5;
    unsigned long long wbytes = 7;

    cgmon_parse_io_stat_line("259:0 rios=1 rbytes=10 wios=2 wbytes=20",
                             &rbytes, &wbytes);

    assert(rbytes == 15);
    assert(wbytes == 27);
}

int main(void)
{
    test_extracts_short_docker_scope_name();
    test_recognizes_kubepods_container_scope();
    test_rejects_short_non_container_path();
    test_parses_io_stat_line_bytes();
    test_parse_io_stat_line_accumulates();
    return 0;
}
