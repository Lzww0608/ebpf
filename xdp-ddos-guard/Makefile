BINARY ?= xdp-ddos-guard
BPFTOOL ?= bpftool
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go
ARCH ?= x86

.PHONY: all generate build run test clean

all: build

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

generate: bpf/vmlinux.h
	cd cmd/xdp-ddos-guard && $(BPF2GO) -go-package main -target bpfel -type config -type ipv4_lpm_key -type rate_state bpf ../../bpf/xdp_ddos.bpf.c -- -I../../bpf -D__TARGET_ARCH_$(ARCH)

build: generate
	go build -o $(BINARY) ./cmd/xdp-ddos-guard

run: build
	sudo ./$(BINARY) --iface $(IFACE)

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -f cmd/xdp-ddos-guard/bpf_bpfel.go cmd/xdp-ddos-guard/bpf_bpfeb.go
	rm -f cmd/xdp-ddos-guard/bpf_bpfel.o cmd/xdp-ddos-guard/bpf_bpfeb.o
	rm -f bpf/vmlinux.h
