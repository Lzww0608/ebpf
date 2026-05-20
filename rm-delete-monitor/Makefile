BPF_CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc

APP = rm_monitor
BPF_OBJ = rm_monitor.bpf.o
SKEL = rm_monitor.skel.h
TEST_APP = rm_monitor_format_test

LIBBPF_PKGCONFIG := /usr/lib64/pkgconfig
LIBBPF_CFLAGS := $(shell PKG_CONFIG_PATH=$(LIBBPF_PKGCONFIG) pkg-config --cflags libbpf)
LIBBPF_SO := /usr/lib64/libbpf.so

.PHONY: all clean test

all: vmlinux.h $(APP)

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_OBJ): rm_monitor.bpf.c rm_monitor.h vmlinux.h
	$(BPF_CLANG) -g -O2 -target bpf -c rm_monitor.bpf.c -o $(BPF_OBJ)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

$(APP): rm_monitor.c rm_monitor.h rm_monitor_format.h $(SKEL)
	$(CC) -g -O2 -Wall $(LIBBPF_CFLAGS) rm_monitor.c -o $(APP) $(LIBBPF_SO) -lelf -lz -Wl,-rpath,/usr/lib64

$(TEST_APP): rm_monitor_format_test.c rm_monitor_format.h
	$(CC) -g -O2 -Wall -Wextra -I. rm_monitor_format_test.c -o $(TEST_APP)

test: $(TEST_APP)
	./$(TEST_APP)

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL) $(TEST_APP) vmlinux.h
