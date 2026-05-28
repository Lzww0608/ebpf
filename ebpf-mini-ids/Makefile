BINARY ?= mini-ids
BPFTOOL ?= bpftool
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go
ARCH ?= x86

.PHONY: all generate build run test clean

all: build

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

generate: bpf/vmlinux.h
	cd cmd/mini-ids && $(BPF2GO) -go-package main -target bpfel -type event bpf ../../bpf/ids.bpf.c -- -I../../bpf -D__TARGET_ARCH_$(ARCH)

build: generate
	go build -o $(BINARY) ./cmd/mini-ids

run: build
	sudo ./$(BINARY) --listen :2113

test:
	go test ./...

clean:
	rm -f $(BINARY)
	rm -f cmd/mini-ids/bpf_bpfel.go cmd/mini-ids/bpf_bpfeb.go
	rm -f cmd/mini-ids/bpf_bpfel.o cmd/mini-ids/bpf_bpfeb.o
	rm -f bpf/vmlinux.h
