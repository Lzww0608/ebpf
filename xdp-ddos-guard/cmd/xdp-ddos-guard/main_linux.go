//go:build linux

package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"time"

	"xdp-ddos-guard/internal/rules"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -go-package main -target bpfel -type config -type ipv4_lpm_key -type rate_state bpf ../../bpf/xdp_ddos.bpf.c -- -I../../bpf -D__TARGET_ARCH_x86

const (
	statTotal         uint32 = 0
	statPass          uint32 = 1
	statDropBlacklist uint32 = 2
	statDropRateLimit uint32 = 3
	statPassWhitelist uint32 = 4
	statNonIPv4       uint32 = 5
)

type guardConfig struct {
	PPSLimit    uint64
	BPSLimit    uint64
	BlockNS     uint64
	ProtectPort uint16
	Enabled     uint8
	Pad         [5]byte
}

type cidrRequest struct {
	CIDR string `json:"cidr"`
}

var packetMetric = prometheus.NewCounterVec(
	prometheus.CounterOpts{
		Name: "xdp_ddos_packets_total",
		Help: "XDP DDoS guard packet counters.",
	},
	[]string{"action"},
)

var metricState = struct {
	sync.Mutex
	last map[string]uint64
}{
	last: make(map[string]uint64),
}

func init() {
	prometheus.MustRegister(packetMetric)
}

func main() {
	ifaceName := flag.String("iface", "", "network interface name, for example eth0")
	pps := flag.Uint64("pps", 5000, "per-source-IP packets per second limit")
	bps := flag.Uint64("bps", 50*1024*1024, "per-source-IP bytes per second limit")
	blockSeconds := flag.Uint64("block-seconds", 10, "temporary block duration in seconds")
	protectPort := flag.Uint("port", 0, "optional protected TCP/UDP destination port; 0 means all ports")
	listen := flag.String("listen", ":2114", "HTTP listen address")
	blacklist := flag.String("blacklist", "", "comma-separated IPv4 CIDRs to blacklist")
	whitelist := flag.String("whitelist", "", "comma-separated IPv4 CIDRs to whitelist")
	flag.Parse()

	if *ifaceName == "" {
		log.Fatal("--iface is required")
	}

	if *protectPort > 65535 {
		log.Fatal("--port must be in range 0..65535")
	}

	if err := run(*ifaceName, *pps, *bps, *blockSeconds, uint16(*protectPort), *listen, *blacklist, *whitelist); err != nil {
		log.Fatal(err)
	}
}

func run(ifaceName string, pps, bps, blockSeconds uint64, protectPort uint16, listen, blacklist, whitelist string) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}

	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return fmt.Errorf("find interface %s: %w", ifaceName, err)
	}

	var objs bpfObjects
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("load bpf objects: %w", err)
	}
	defer objs.Close()

	cfg := guardConfig{
		PPSLimit:    pps,
		BPSLimit:    bps,
		BlockNS:     blockSeconds * uint64(time.Second),
		ProtectPort: protectPort,
		Enabled:     1,
	}

	var cfgKey uint32
	if err := objs.ConfigMap.Update(cfgKey, cfg, ebpf.UpdateAny); err != nil {
		return fmt.Errorf("update config map: %w", err)
	}

	if err := addCIDRList(objs.BlacklistV4, blacklist); err != nil {
		return fmt.Errorf("load blacklist: %w", err)
	}

	if err := addCIDRList(objs.WhitelistV4, whitelist); err != nil {
		return fmt.Errorf("load whitelist: %w", err)
	}

	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpDdosGuard,
		Interface: iface.Index,
	})
	if err != nil {
		return fmt.Errorf("attach XDP to %s: %w", ifaceName, err)
	}
	defer xdpLink.Close()

	server := newHTTPServer(listen, &objs)
	serverErr := make(chan error, 1)
	go func() {
		log.Printf("HTTP listening on %s", listen)
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErr <- err
			return
		}
		serverErr <- nil
	}()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	log.Printf("xdp-ddos-guard attached to %s", ifaceName)
	log.Printf("pps=%d bps=%d block=%ds port=%d", pps, bps, blockSeconds, protectPort)

	for {
		select {
		case <-ticker.C:
			updateMetrics(&objs)
		case err := <-serverErr:
			if err != nil {
				return fmt.Errorf("http server: %w", err)
			}
			return nil
		case <-ctx.Done():
			log.Println("detaching XDP and exiting")
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			return server.Shutdown(shutdownCtx)
		}
	}
}

func newHTTPServer(addr string, objs *bpfObjects) *http.Server {
	mux := http.NewServeMux()

	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/blacklist", func(w http.ResponseWriter, r *http.Request) {
		handleCIDRUpdate(w, r, objs.BlacklistV4)
	})
	mux.HandleFunc("/whitelist", func(w http.ResponseWriter, r *http.Request) {
		handleCIDRUpdate(w, r, objs.WhitelistV4)
	})
	mux.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(readStats(objs))
	})

	return &http.Server{
		Addr:    addr,
		Handler: mux,
	}
}

func handleCIDRUpdate(w http.ResponseWriter, r *http.Request, m *ebpf.Map) {
	switch r.Method {
	case http.MethodPost:
		var req cidrRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := addCIDR(m, req.CIDR); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	case http.MethodDelete:
		cidr := r.URL.Query().Get("cidr")
		if cidr == "" {
			http.Error(w, "missing cidr query parameter", http.StatusBadRequest)
			return
		}

		key, err := rules.ParseIPv4CIDRKey(cidr)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		if err := m.Delete(key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func addCIDRList(m *ebpf.Map, raw string) error {
	keys, err := rules.ParseIPv4CIDRList(raw)
	if err != nil {
		return err
	}

	for _, key := range keys {
		if err := updateCIDR(m, key); err != nil {
			return err
		}
	}

	return nil
}

func addCIDR(m *ebpf.Map, cidr string) error {
	key, err := rules.ParseIPv4CIDRKey(cidr)
	if err != nil {
		return err
	}
	return updateCIDR(m, key)
}

func updateCIDR(m *ebpf.Map, key rules.IPv4LPMKey) error {
	var value uint8 = 1
	return m.Update(key, value, ebpf.UpdateAny)
}

func updateMetrics(objs *bpfObjects) {
	metricState.Lock()
	defer metricState.Unlock()

	for action, value := range readStats(objs) {
		last := metricState.last[action]
		if value >= last {
			packetMetric.WithLabelValues(action).Add(float64(value - last))
		} else {
			packetMetric.WithLabelValues(action).Add(float64(value))
		}
		metricState.last[action] = value
	}
}

func readStats(objs *bpfObjects) map[string]uint64 {
	return map[string]uint64{
		"total":          readPerCPUCounter(objs.StatsMap, statTotal),
		"pass":           readPerCPUCounter(objs.StatsMap, statPass),
		"drop_blacklist": readPerCPUCounter(objs.StatsMap, statDropBlacklist),
		"drop_ratelimit": readPerCPUCounter(objs.StatsMap, statDropRateLimit),
		"pass_whitelist": readPerCPUCounter(objs.StatsMap, statPassWhitelist),
		"non_ipv4":       readPerCPUCounter(objs.StatsMap, statNonIPv4),
	}
}

func readPerCPUCounter(m *ebpf.Map, key uint32) uint64 {
	var values []uint64
	if err := m.Lookup(key, &values); err != nil {
		log.Printf("lookup stats key %d: %v", key, err)
		return 0
	}

	var total uint64
	for _, value := range values {
		total += value
	}
	return total
}
