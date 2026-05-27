BINARY ?= ebpf-apm
DEMO_BINARY ?= demo-http
BPFTOOL ?= bpftool
BPF2GO ?= go run github.com/cilium/ebpf/cmd/bpf2go
ARCH ?= x86

.PHONY: all generate build demo run test clean

all: build

bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

generate: bpf/vmlinux.h
	cd cmd/apm && $(BPF2GO) -target bpfel -type event_t bpf ../../bpf/http_apm.bpf.c -- -I../../bpf -D__TARGET_ARCH_$(ARCH)

build: generate
	go build -o $(BINARY) ./cmd/apm

demo:
	go build -o $(DEMO_BINARY) ./cmd/demo

run: build
	sudo ./$(BINARY) --pid $(PID) --listen :2112

test:
	go test ./internal/...

clean:
	rm -f $(BINARY) $(DEMO_BINARY)
	rm -f cmd/apm/bpf_bpfel.go cmd/apm/bpf_bpfeb.go
	rm -f cmd/apm/bpf_bpfel.o cmd/apm/bpf_bpfeb.o
	rm -f bpf/vmlinux.h
