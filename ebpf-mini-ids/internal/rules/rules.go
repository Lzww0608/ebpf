package rules

import (
	"fmt"
	"strings"
	"time"
)

const (
	EvtExec    = 1
	EvtFile    = 2
	EvtSyscall = 3
	EvtPriv    = 4

	SevLow      = 1
	SevMedium   = 2
	SevHigh     = 3
	SevCritical = 4

	OpenWriteOnly  = 0x1
	OpenReadWrite  = 0x2
	OpenCreate     = 0x40
	OpenTruncate   = 0x200
	OpenAccessMode = 0x3

	SysPtrace        = 101
	SysBpf           = 321
	SysOpenat        = 257
	SysExecve        = 59
	SysSetuid        = 105
	SysSetgid        = 106
	SysSetresuid     = 117
	SysSetresgid     = 119
	SysCapset        = 126
	SysPerfEventOpen = 298
	SysMount         = 165
	SysUmount2       = 166
	SysPivotRoot     = 155
	SysSetns         = 308
	SysUnshare       = 272
	SysInitModule    = 175
	SysFinitModule   = 313
	SysDeleteModule  = 176
	SysKexecLoad     = 246
)

type Event struct {
	Type      uint32
	Severity  uint32
	TGID      uint32
	PID       uint32
	UID       uint32
	GID       uint32
	SyscallID int32
	Ret       int32
	Arg0      uint64
	Arg1      uint64
	Arg2      uint64
	Comm      string
	Path      string
}

type Alert struct {
	Time     string `json:"time,omitempty"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Score    int    `json:"score"`

	PID  uint32 `json:"pid"`
	TGID uint32 `json:"tgid"`
	UID  uint32 `json:"uid"`
	GID  uint32 `json:"gid"`

	Comm string `json:"comm"`
	Path string `json:"path,omitempty"`

	Syscall string  `json:"syscall,omitempty"`
	Action  string  `json:"action,omitempty"`
	OldUID  *uint32 `json:"old_uid,omitempty"`
	NewUID  *uint32 `json:"new_uid,omitempty"`
	OldGID  *uint32 `json:"old_gid,omitempty"`
	NewGID  *uint32 `json:"new_gid,omitempty"`
	Reason  string  `json:"reason"`
}

func Evaluate(e Event) (Alert, bool) {
	base := Alert{
		Type: EventTypeName(e.Type),
		PID:  e.PID,
		TGID: e.TGID,
		UID:  e.UID,
		GID:  e.GID,
		Comm: e.Comm,
		Path: e.Path,
	}

	switch e.Type {
	case EvtFile:
		return evaluateFile(e, base)
	case EvtExec:
		return evaluateExec(base)
	case EvtSyscall:
		return evaluateSyscall(e, base)
	case EvtPriv:
		return evaluatePrivilege(e, base)
	default:
		return Alert{}, false
	}
}

func evaluateFile(e Event, a Alert) (Alert, bool) {
	write := isWriteLikeOpen(e.Arg0)

	switch {
	case e.Path == "/etc/shadow":
		a.Severity = "critical"
		a.Score = 95
		a.Reason = "accessed /etc/shadow"
	case e.Path == "/etc/sudoers":
		a.Severity = "critical"
		a.Score = 95
		a.Reason = "accessed /etc/sudoers"
	case e.Path == "/etc/passwd":
		if write {
			a.Severity = "critical"
			a.Score = 90
			a.Reason = "opened /etc/passwd for write"
		} else {
			a.Severity = "medium"
			a.Score = 55
			a.Reason = "read /etc/passwd"
		}
	case strings.HasPrefix(e.Path, "/root/.ssh"):
		a.Severity = "critical"
		a.Score = 90
		a.Reason = "accessed root ssh material"
	case isHomeSSHPath(e.Path):
		a.Severity = "high"
		a.Score = 80
		a.Reason = "accessed user ssh material"
	case strings.HasPrefix(e.Path, "/proc/kcore"):
		a.Severity = "critical"
		a.Score = 95
		a.Reason = "accessed /proc/kcore"
	case strings.HasPrefix(e.Path, "/proc/sys/kernel"):
		a.Severity = "high"
		a.Score = 75
		a.Reason = "accessed kernel sysctl path"
	case e.Path == "/var/log/auth.log" || e.Path == "/var/log/secure":
		a.Severity = "medium"
		a.Score = 55
		a.Reason = "accessed authentication log"
	default:
		return Alert{}, false
	}

	if write && a.Score < 90 {
		a.Score += 15
		a.Reason += " with write-like flags"
		if a.Severity == "medium" {
			a.Severity = "high"
		}
	}

	return a, true
}

func evaluateExec(a Alert) (Alert, bool) {
	privTools := []string{
		"/usr/bin/sudo",
		"/bin/su",
		"/usr/bin/su",
		"/usr/bin/pkexec",
		"/usr/bin/doas",
	}
	for _, path := range privTools {
		if a.Path == path {
			a.Severity = "high"
			a.Score = 80
			a.Reason = "executed privilege-management binary"
			return a, true
		}
	}

	dangerousShells := []string{
		"/bin/sh",
		"/bin/bash",
		"/usr/bin/bash",
		"/bin/dash",
		"/usr/bin/zsh",
	}
	for _, path := range dangerousShells {
		if a.Path == path && isServiceLike(a.Comm) {
			a.Severity = "high"
			a.Score = 85
			a.Reason = "service-like process executed shell"
			return a, true
		}
	}

	return Alert{}, false
}

func evaluateSyscall(e Event, a Alert) (Alert, bool) {
	a.Syscall = syscallName(e.SyscallID)

	switch e.SyscallID {
	case SysPtrace:
		if allowComm(e.Comm, []string{"gdb", "strace", "lldb"}) {
			return Alert{}, false
		}
		a.Severity = "high"
		a.Score = 80
		a.Reason = "ptrace syscall by non-whitelisted process"
		return a, true
	case SysBpf:
		if allowComm(e.Comm, []string{"mini-ids", "bpftool", "bpftrace", "bcc"}) {
			return Alert{}, false
		}
		a.Severity = "high"
		a.Score = 85
		a.Reason = "bpf syscall by non-whitelisted process"
		return a, true
	case SysPerfEventOpen:
		if allowComm(e.Comm, []string{"perf", "bcc", "bpftrace"}) {
			return Alert{}, false
		}
		a.Severity = "medium"
		a.Score = 65
		a.Reason = "perf_event_open syscall by non-whitelisted process"
		return a, true
	case SysMount, SysUmount2, SysPivotRoot:
		if e.UID == 0 {
			return Alert{}, false
		}
		a.Severity = "high"
		a.Score = 85
		a.Reason = "filesystem namespace syscall by non-root process"
		return a, true
	case SysSetns:
		if allowComm(e.Comm, []string{"containerd", "runc", "dockerd", "crio"}) {
			return Alert{}, false
		}
		a.Severity = "high"
		a.Score = 80
		a.Reason = "setns syscall by non-whitelisted process"
		return a, true
	case SysUnshare:
		a.Severity = "medium"
		a.Score = 65
		a.Reason = "unshare syscall observed"
		return a, true
	case SysInitModule, SysFinitModule, SysDeleteModule, SysKexecLoad:
		a.Severity = "critical"
		a.Score = 95
		a.Reason = "kernel module or kexec syscall observed"
		return a, true
	default:
		return Alert{}, false
	}
}

func evaluatePrivilege(e Event, a Alert) (Alert, bool) {
	switch e.SyscallID {
	case 0, SysSetuid, SysSetresuid:
		oldUID := uint32(e.Arg0)
		newUID := uint32(e.Arg1)
		a.Action = syscallNameOrDefault(e.SyscallID, "setuid")
		a.Syscall = a.Action
		a.OldUID = ptr(oldUID)
		a.NewUID = ptr(newUID)

		if oldUID != 0 && newUID == 0 {
			a.Severity = "critical"
			a.Score = 98
			a.Reason = "process changed uid from non-root to root"
			return a, true
		}
		if oldUID != newUID {
			a.Severity = "high"
			a.Score = 75
			a.Reason = "process changed uid"
			return a, true
		}
	case SysSetgid, SysSetresgid:
		oldGID := uint32(e.Arg0)
		newGID := uint32(e.Arg1)
		a.Action = syscallName(e.SyscallID)
		a.Syscall = a.Action
		a.OldGID = ptr(oldGID)
		a.NewGID = ptr(newGID)

		if oldGID != 0 && newGID == 0 {
			a.Severity = "critical"
			a.Score = 95
			a.Reason = "process changed gid from non-root to root"
			return a, true
		}
		if oldGID != newGID {
			a.Severity = "high"
			a.Score = 75
			a.Reason = "process changed gid"
			return a, true
		}
	case SysCapset:
		a.Action = "capset"
		a.Syscall = "capset"
		a.Severity = "critical"
		a.Score = 90
		a.Reason = "process called capset"
		return a, true
	}

	return Alert{}, false
}

func isWriteLikeOpen(flags uint64) bool {
	return flags&OpenAccessMode != 0 || flags&OpenCreate != 0 || flags&OpenTruncate != 0
}

func isHomeSSHPath(path string) bool {
	if !strings.HasPrefix(path, "/home/") {
		return false
	}
	return strings.Contains(path, "/.ssh/") || strings.HasSuffix(path, "/.ssh")
}

func isServiceLike(comm string) bool {
	for _, name := range []string{"nginx", "apache2", "httpd", "node", "python", "python3", "gunicorn", "uwsgi", "java", "php-fpm"} {
		if strings.Contains(comm, name) {
			return true
		}
	}
	return false
}

func allowComm(comm string, allowed []string) bool {
	for _, value := range allowed {
		if comm == value {
			return true
		}
	}
	return false
}

func EventTypeName(t uint32) string {
	switch t {
	case EvtExec:
		return "exec"
	case EvtFile:
		return "sensitive_file_access"
	case EvtSyscall:
		return "suspicious_syscall"
	case EvtPriv:
		return "privilege_change"
	default:
		return "unknown"
	}
}

func syscallName(id int32) string {
	switch id {
	case SysPtrace:
		return "ptrace"
	case SysBpf:
		return "bpf"
	case SysOpenat:
		return "openat"
	case SysExecve:
		return "execve"
	case SysSetuid:
		return "setuid"
	case SysSetgid:
		return "setgid"
	case SysSetresuid:
		return "setresuid"
	case SysSetresgid:
		return "setresgid"
	case SysCapset:
		return "capset"
	case SysPerfEventOpen:
		return "perf_event_open"
	case SysMount:
		return "mount"
	case SysUmount2:
		return "umount2"
	case SysPivotRoot:
		return "pivot_root"
	case SysSetns:
		return "setns"
	case SysUnshare:
		return "unshare"
	case SysInitModule:
		return "init_module"
	case SysFinitModule:
		return "finit_module"
	case SysDeleteModule:
		return "delete_module"
	case SysKexecLoad:
		return "kexec_load"
	default:
		return "unknown"
	}
}

func syscallNameOrDefault(id int32, fallback string) string {
	if id == 0 {
		return fallback
	}
	return syscallName(id)
}

func ptr[T any](value T) *T {
	return &value
}

type Deduper struct {
	window time.Duration
	seen   map[string]time.Time
}

func NewDeduper(window time.Duration) *Deduper {
	return &Deduper{
		window: window,
		seen:   make(map[string]time.Time),
	}
}

func (d *Deduper) Allow(alert Alert, now time.Time) bool {
	if d == nil || d.window <= 0 {
		return true
	}

	key := dedupeKey(alert)
	last, ok := d.seen[key]
	if ok && now.Sub(last) < d.window {
		return false
	}

	d.seen[key] = now
	d.prune(now)
	return true
}

func (d *Deduper) prune(now time.Time) {
	for key, last := range d.seen {
		if now.Sub(last) >= d.window {
			delete(d.seen, key)
		}
	}
}

func dedupeKey(alert Alert) string {
	return fmt.Sprintf("%s|%d|%d|%s|%s|%s", alert.Type, alert.PID, alert.UID, alert.Comm, alert.Path, alert.Syscall)
}
