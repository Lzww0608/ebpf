package rules

import (
	"testing"
	"time"
)

func TestEvaluateFileClassifiesSensitivePathsAndWriteEscalation(t *testing.T) {
	tests := []struct {
		name     string
		path     string
		flags    uint64
		severity string
		score    int
		reason   string
	}{
		{
			name:     "read passwd",
			path:     "/etc/passwd",
			severity: "medium",
			score:    55,
			reason:   "read /etc/passwd",
		},
		{
			name:     "write passwd",
			path:     "/etc/passwd",
			flags:    OpenWriteOnly,
			severity: "critical",
			score:    90,
			reason:   "opened /etc/passwd for write",
		},
		{
			name:     "root ssh material",
			path:     "/root/.ssh/id_rsa",
			severity: "critical",
			score:    90,
			reason:   "accessed root ssh material",
		},
		{
			name:     "home ssh material",
			path:     "/home/alice/.ssh/config",
			severity: "high",
			score:    80,
			reason:   "accessed user ssh material",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alert, ok := Evaluate(Event{
				Type: EvtFile,
				PID:  42,
				UID:  1000,
				Comm: "cat",
				Path: tt.path,
				Arg0: tt.flags,
			})
			if !ok {
				t.Fatalf("Evaluate() returned no alert")
			}
			if alert.Type != "sensitive_file_access" {
				t.Fatalf("alert.Type = %q, want sensitive_file_access", alert.Type)
			}
			if alert.Severity != tt.severity || alert.Score != tt.score || alert.Reason != tt.reason {
				t.Fatalf("alert = severity %q score %d reason %q, want severity %q score %d reason %q",
					alert.Severity, alert.Score, alert.Reason, tt.severity, tt.score, tt.reason)
			}
		})
	}
}

func TestEvaluateSyscallHonorsAllowlist(t *testing.T) {
	alert, ok := Evaluate(Event{
		Type:      EvtSyscall,
		SyscallID: SysPtrace,
		Comm:      "python3",
		PID:       99,
		UID:       1000,
	})
	if !ok {
		t.Fatalf("Evaluate() returned no ptrace alert")
	}
	if alert.Syscall != "ptrace" || alert.Severity != "high" || alert.Score != 80 {
		t.Fatalf("ptrace alert = syscall %q severity %q score %d", alert.Syscall, alert.Severity, alert.Score)
	}

	_, ok = Evaluate(Event{
		Type:      EvtSyscall,
		SyscallID: SysPtrace,
		Comm:      "strace",
	})
	if ok {
		t.Fatalf("allowlisted strace ptrace call produced an alert")
	}

	_, ok = Evaluate(Event{
		Type:      EvtSyscall,
		SyscallID: SysBpf,
		Comm:      "bpftool",
	})
	if ok {
		t.Fatalf("allowlisted bpftool bpf call produced an alert")
	}
}

func TestEvaluateFileDoesNotTreatSSHLikePrefixAsSSHDirectory(t *testing.T) {
	_, ok := Evaluate(Event{
		Type: EvtFile,
		Comm: "cat",
		Path: "/home/alice/.ssh2/config",
	})
	if ok {
		t.Fatalf(".ssh2 path produced an ssh material alert")
	}
}

func TestEvaluateExecDetectsPrivilegedToolsAndServiceShells(t *testing.T) {
	tests := []struct {
		name     string
		comm     string
		path     string
		score    int
		reason   string
		severity string
	}{
		{
			name:     "sudo",
			comm:     "bash",
			path:     "/usr/bin/sudo",
			score:    80,
			reason:   "executed privilege-management binary",
			severity: "high",
		},
		{
			name:     "service shell",
			comm:     "nginx",
			path:     "/bin/sh",
			score:    85,
			reason:   "service-like process executed shell",
			severity: "high",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alert, ok := Evaluate(Event{
				Type: EvtExec,
				Comm: tt.comm,
				Path: tt.path,
			})
			if !ok {
				t.Fatalf("Evaluate() returned no exec alert")
			}
			if alert.Type != "exec" || alert.Severity != tt.severity || alert.Score != tt.score || alert.Reason != tt.reason {
				t.Fatalf("alert = type %q severity %q score %d reason %q",
					alert.Type, alert.Severity, alert.Score, alert.Reason)
			}
		})
	}
}

func TestEvaluatePrivilegeEscalation(t *testing.T) {
	alert, ok := Evaluate(Event{
		Type: EvtPriv,
		Comm: "helper",
		Arg0: 1000,
		Arg1: 0,
	})
	if !ok {
		t.Fatalf("Evaluate() returned no privilege alert")
	}
	if alert.Type != "privilege_change" || alert.Severity != "critical" || alert.Score != 98 {
		t.Fatalf("alert = type %q severity %q score %d", alert.Type, alert.Severity, alert.Score)
	}
	if alert.Reason != "process changed uid from non-root to root" {
		t.Fatalf("alert.Reason = %q", alert.Reason)
	}
}

func TestDeduperSuppressesRepeatedAlertsWithinWindow(t *testing.T) {
	d := NewDeduper(time.Minute)
	alert := Alert{
		Type:    "sensitive_file_access",
		PID:     42,
		UID:     1000,
		Comm:    "cat",
		Path:    "/etc/shadow",
		Syscall: "openat",
	}
	now := time.Unix(100, 0)

	if !d.Allow(alert, now) {
		t.Fatalf("first alert was suppressed")
	}
	if d.Allow(alert, now.Add(30*time.Second)) {
		t.Fatalf("duplicate alert inside window was allowed")
	}
	if !d.Allow(alert, now.Add(61*time.Second)) {
		t.Fatalf("alert after window was suppressed")
	}
}
