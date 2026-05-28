//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"time"

	"ebpf-mini-ids/internal/bpfstring"
	"ebpf-mini-ids/internal/rules"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -target bpfel -type event bpf ../../bpf/ids.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

var (
	eventTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mini_ids_events_total",
			Help: "Total IDS events observed from eBPF.",
		},
		[]string{"type"},
	)

	alertTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "mini_ids_alerts_total",
			Help: "Total IDS alerts emitted after rule evaluation.",
		},
		[]string{"type", "severity"},
	)

	ringbufReadErrors = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "mini_ids_ringbuf_read_errors_total",
			Help: "Total ring buffer read or decode errors.",
		},
	)
)

func init() {
	prometheus.MustRegister(eventTotal, alertTotal, ringbufReadErrors)
}

func main() {
	listen := flag.String("listen", ":2113", "Prometheus metrics listen address")
	targetPID := flag.Uint("pid", 0, "target process PID; 0 monitors all processes")
	dedupeWindow := flag.Duration("dedupe-window", time.Minute, "suppress duplicate alerts for this duration; 0 disables dedupe")
	flag.Parse()

	if uint64(*targetPID) > 1<<32-1 {
		log.Fatalf("target PID %d overflows uint32", *targetPID)
	}

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("remove memlock: %v", err)
	}

	spec, err := loadBpf()
	if err != nil {
		log.Fatalf("load bpf spec: %v", err)
	}

	if *targetPID != 0 {
		if err := spec.RewriteConstants(map[string]interface{}{
			"target_tgid": uint32(*targetPID),
		}); err != nil {
			log.Fatalf("rewrite target_tgid: %v", err)
		}
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		log.Fatalf("load and assign bpf objects: %v", err)
	}
	defer objs.Close()

	attached, err := attachTracepoints(&objs)
	if err != nil {
		log.Fatal(err)
	}
	defer closeLinks(attached)

	reader, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("create ringbuf reader: %v", err)
	}
	defer reader.Close()

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	server := &http.Server{
		Addr:    *listen,
		Handler: mux,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	go consumeEvents(reader, rules.NewDeduper(*dedupeWindow))

	go func() {
		log.Printf("metrics listening on %s/metrics", *listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	<-ctx.Done()
	_ = reader.Close()
	_ = server.Shutdown(context.Background())
	log.Println("shutdown")
}

func attachTracepoints(objs *bpfObjects) ([]link.Link, error) {
	tracepoints := []struct {
		category string
		name     string
		program  *ebpf.Program
	}{
		{"syscalls", "sys_enter_openat", objs.TraceOpenat},
		{"syscalls", "sys_enter_openat2", objs.TraceOpenat2},
		{"syscalls", "sys_enter_execve", objs.TraceExecve},
		{"syscalls", "sys_enter_execveat", objs.TraceExecveat},
		{"syscalls", "sys_enter_ptrace", objs.TracePtrace},
		{"syscalls", "sys_enter_bpf", objs.TraceBpf},
		{"syscalls", "sys_enter_perf_event_open", objs.TracePerfEventOpen},
		{"syscalls", "sys_enter_mount", objs.TraceMount},
		{"syscalls", "sys_enter_umount2", objs.TraceUmount2},
		{"syscalls", "sys_enter_pivot_root", objs.TracePivotRoot},
		{"syscalls", "sys_enter_setns", objs.TraceSetns},
		{"syscalls", "sys_enter_unshare", objs.TraceUnshare},
		{"syscalls", "sys_enter_init_module", objs.TraceInitModule},
		{"syscalls", "sys_enter_finit_module", objs.TraceFinitModule},
		{"syscalls", "sys_enter_delete_module", objs.TraceDeleteModule},
		{"syscalls", "sys_enter_kexec_load", objs.TraceKexecLoad},
		{"syscalls", "sys_enter_capset", objs.TraceCapset},
		{"syscalls", "sys_enter_setuid", objs.TraceEnterSetuid},
		{"syscalls", "sys_exit_setuid", objs.TraceExitSetuid},
		{"syscalls", "sys_enter_setgid", objs.TraceEnterSetgid},
		{"syscalls", "sys_exit_setgid", objs.TraceExitSetgid},
		{"syscalls", "sys_enter_setresuid", objs.TraceEnterSetresuid},
		{"syscalls", "sys_exit_setresuid", objs.TraceExitSetresuid},
		{"syscalls", "sys_enter_setresgid", objs.TraceEnterSetresgid},
		{"syscalls", "sys_exit_setresgid", objs.TraceExitSetresgid},
	}

	links := make([]link.Link, 0, len(tracepoints))
	for _, tp := range tracepoints {
		l, err := link.Tracepoint(tp.category, tp.name, tp.program, nil)
		if err != nil {
			log.Printf("skip tracepoint %s/%s: %v", tp.category, tp.name, err)
			continue
		}
		links = append(links, l)
	}

	if len(links) == 0 {
		return nil, errors.New("no tracepoints attached")
	}

	log.Printf("attached %d tracepoints", len(links))
	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func consumeEvents(reader *ringbuf.Reader, deduper *rules.Deduper) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			ringbufReadErrors.Inc()
			log.Printf("read ringbuf: %v", err)
			continue
		}

		var raw bpfEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &raw); err != nil {
			ringbufReadErrors.Inc()
			log.Printf("decode event: %v", err)
			continue
		}

		handleEvent(raw, deduper)
	}
}

func handleEvent(raw bpfEvent, deduper *rules.Deduper) {
	event := rules.Event{
		Type:      raw.Type,
		Severity:  raw.Severity,
		TGID:      raw.Tgid,
		PID:       raw.Pid,
		UID:       raw.Uid,
		GID:       raw.Gid,
		SyscallID: raw.SyscallId,
		Ret:       raw.Ret,
		Arg0:      raw.Arg0,
		Arg1:      raw.Arg1,
		Arg2:      raw.Arg2,
		Comm:      bpfstring.CString(raw.Comm[:]),
		Path:      bpfstring.CString(raw.Path[:]),
	}

	eventTotal.WithLabelValues(rules.EventTypeName(event.Type)).Inc()

	alert, ok := rules.Evaluate(event)
	if !ok {
		return
	}

	now := time.Now()
	if !deduper.Allow(alert, now) {
		return
	}

	alert.Time = now.Format(time.RFC3339)
	alertTotal.WithLabelValues(alert.Type, alert.Severity).Inc()

	data, err := json.Marshal(alert)
	if err != nil {
		log.Printf("marshal alert: %v", err)
		return
	}

	fmt.Fprintln(os.Stdout, string(data))
}
