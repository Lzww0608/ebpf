BPF_CLANG ?= clang
BPFTOOL ?= bpftool
CC ?= gcc
PKG_CONFIG ?= pkg-config
ARCH ?= x86

APP = cgmon
BPF_OBJ = $(APP).bpf.o
SKEL = $(APP).skel.h
TEST_APP = $(APP)_test

LIBBPF_CFLAGS := $(shell $(PKG_CONFIG) --cflags libbpf)
LIBBPF_LIBS := $(shell $(PKG_CONFIG) --libs libbpf)

.PHONY: all clean check-libbpf unit-test test

all: vmlinux.h $(APP)

check-libbpf:
	@echo "libbpf version:"
	@$(PKG_CONFIG) --modversion libbpf
	@echo "libbpf libs:"
	@$(PKG_CONFIG) --libs libbpf

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

$(BPF_OBJ): $(APP).bpf.c $(APP).h vmlinux.h
	$(BPF_CLANG) -g -O2 -target bpf -D__TARGET_ARCH_$(ARCH) -c $(APP).bpf.c -o $(BPF_OBJ)

$(SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $(BPF_OBJ) > $(SKEL)

$(APP): $(APP).c $(APP).h $(SKEL)
	$(CC) -g -O2 -Wall $(LIBBPF_CFLAGS) $(APP).c -o $(APP) $(LIBBPF_LIBS) -lelf -lz

$(TEST_APP): $(APP)_test.c $(APP).c
	$(CC) -g -O2 -Wall -Wextra -DCGMON_UNIT_TEST -I. $(APP)_test.c -o $(TEST_APP)

unit-test: $(TEST_APP)
	./$(TEST_APP)

test: unit-test

clean:
	rm -f $(APP) $(BPF_OBJ) $(SKEL) $(TEST_APP) vmlinux.h
