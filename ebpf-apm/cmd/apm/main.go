//go:build linux

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"

	"ebpf-apm/internal/bpfstring"
	"ebpf-apm/internal/route"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -type event_t bpf ../../bpf/http_apm.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

var (
	requestTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total HTTP requests observed by eBPF APM.",
		},
		[]string{"method", "route", "status"},
	)

	errorTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "http_errors_total",
			Help: "Total HTTP 5xx responses observed by eBPF APM.",
		},
		[]string{"method", "route"},
	)

	duration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "HTTP request latency observed by eBPF APM.",
			Buckets: []float64{0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5},
		},
		[]string{"method", "route"},
	)
)

func init() {
	prometheus.MustRegister(requestTotal, errorTotal, duration)
}

func main() {
	targetPID := flag.Uint("pid", 0, "target process PID; 0 means all processes")
	listen := flag.String("listen", ":2112", "Prometheus metrics listen address")
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
			log.Fatalf("rewrite constants: %v", err)
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

	go consumeEvents(reader)

	go func() {
		log.Printf("metrics listening on %s/metrics", *listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("metrics server: %v", err)
		}
	}()

	<-ctx.Done()
	_ = reader.Close()
	_ = server.Shutdown(context.Background())
	log.Println("shutting down")
}

func attachTracepoints(objs *bpfObjects) ([]link.Link, error) {
	links := make([]link.Link, 0, 3)

	attach := func(category, name string, program *ebpf.Program) error {
		tp, err := link.Tracepoint(category, name, program, nil)
		if err != nil {
			return err
		}
		links = append(links, tp)
		return nil
	}

	if err := attach("syscalls", "sys_enter_read", objs.HandleEnterRead); err != nil {
		closeLinks(links)
		return nil, err
	}
	if err := attach("syscalls", "sys_exit_read", objs.HandleExitRead); err != nil {
		closeLinks(links)
		return nil, err
	}
	if err := attach("syscalls", "sys_enter_write", objs.HandleEnterWrite); err != nil {
		closeLinks(links)
		return nil, err
	}

	return links, nil
}

func closeLinks(links []link.Link) {
	for _, l := range links {
		_ = l.Close()
	}
}

func consumeEvents(reader *ringbuf.Reader) {
	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("read ringbuf: %v", err)
			continue
		}

		var event bpfEventT
		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}

		method := bpfstring.CString(event.Method[:])
		path := bpfstring.CString(event.Path[:])
		normalizedRoute := route.Normalize(path)
		status := strconv.Itoa(int(event.Status))
		latencySeconds := float64(event.LatencyNs) / 1e9

		requestTotal.WithLabelValues(method, normalizedRoute, status).Inc()
		duration.WithLabelValues(method, normalizedRoute).Observe(latencySeconds)

		if event.Status >= 500 {
			errorTotal.WithLabelValues(method, normalizedRoute).Inc()
		}
	}
}
