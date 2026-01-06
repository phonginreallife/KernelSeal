package types

import (
	"testing"
)

func TestEventType_String(t *testing.T) {
	tests := []struct {
		name     string
		e        EventType
		expected string
	}{
		{"EventExec", EventExec, "EXEC"},
		{"EventExit", EventExit, "EXIT"},
		{"EventBlocked", EventBlocked, "BLOCKED"},
		{"EventAudit", EventAudit, "AUDIT"},
		{"Unknown", EventType(99), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.e.String(); got != tt.expected {
				t.Errorf("EventType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestAccessType_String(t *testing.T) {
	tests := []struct {
		name     string
		a        AccessType
		expected string
	}{
		{"AccessEnviron", AccessEnviron, "environ"},
		{"AccessMem", AccessMem, "mem"},
		{"AccessMaps", AccessMaps, "maps"},
		{"AccessPtrace", AccessPtrace, "ptrace"},
		{"Unknown", AccessType(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.a.String(); got != tt.expected {
				t.Errorf("AccessType.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestEnforceMode_String(t *testing.T) {
	tests := []struct {
		name     string
		m        EnforceMode
		expected string
	}{
		{"ModeDisabled", ModeDisabled, "disabled"},
		{"ModeAudit", ModeAudit, "audit"},
		{"ModeEnforce", ModeEnforce, "enforce"},
		{"Unknown", EnforceMode(99), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.m.String(); got != tt.expected {
				t.Errorf("EnforceMode.String() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecEvent_GetComm(t *testing.T) {
	tests := []struct {
		name     string
		comm     [16]byte
		expected string
	}{
		{
			name:     "Normal comm",
			comm:     [16]byte{'b', 'a', 's', 'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: "bash",
		},
		{
			name:     "Full length comm",
			comm:     [16]byte{'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p'},
			expected: "abcdefghijklmnop",
		},
		{
			name:     "Empty comm",
			comm:     [16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ExecEvent{Comm: tt.comm}
			if got := e.GetComm(); got != tt.expected {
				t.Errorf("ExecEvent.GetComm() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestExecEvent_GetFilename(t *testing.T) {
	tests := []struct {
		name     string
		filename [256]byte
		expected string
	}{
		{
			name: "Normal filename",
			filename: func() [256]byte {
				var f [256]byte
				copy(f[:], "/usr/bin/bash")
				return f
			}(),
			expected: "/usr/bin/bash",
		},
		{
			name:     "Empty filename",
			filename: [256]byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &ExecEvent{Filename: tt.filename}
			if got := e.GetFilename(); got != tt.expected {
				t.Errorf("ExecEvent.GetFilename() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestLSMEvent_GetComm(t *testing.T) {
	e := &LSMEvent{
		Comm: [16]byte{'c', 'a', 't', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
	}
	if got := e.GetComm(); got != "cat" {
		t.Errorf("LSMEvent.GetComm() = %v, want %v", got, "cat")
	}
}

func TestLSMEvent_GetPath(t *testing.T) {
	var path [256]byte
	copy(path[:], "/proc/1234/environ")
	e := &LSMEvent{Path: path}
	if got := e.GetPath(); got != "/proc/1234/environ" {
		t.Errorf("LSMEvent.GetPath() = %v, want %v", got, "/proc/1234/environ")
	}
}

func TestNewDefaultPolicy(t *testing.T) {
	policy := NewDefaultPolicy()

	if policy.EnforceMode != ModeEnforce {
		t.Errorf("Default EnforceMode = %v, want %v", policy.EnforceMode, ModeEnforce)
	}
	if policy.BlockEnviron != 1 {
		t.Errorf("Default BlockEnviron = %v, want %v", policy.BlockEnviron, 1)
	}
	if policy.BlockMem != 1 {
		t.Errorf("Default BlockMem = %v, want %v", policy.BlockMem, 1)
	}
	if policy.BlockMaps != 0 {
		t.Errorf("Default BlockMaps = %v, want %v", policy.BlockMaps, 0)
	}
	if policy.BlockPtrace != 1 {
		t.Errorf("Default BlockPtrace = %v, want %v", policy.BlockPtrace, 1)
	}
	if policy.AllowSelfRead != 1 {
		t.Errorf("Default AllowSelfRead = %v, want %v", policy.AllowSelfRead, 1)
	}
	if policy.AuditAll != 0 {
		t.Errorf("Default AuditAll = %v, want %v", policy.AuditAll, 0)
	}
}

func TestCStringToGo(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Normal string with null terminator",
			input:    []byte{'h', 'e', 'l', 'l', 'o', 0, 'w', 'o', 'r', 'l', 'd'},
			expected: "hello",
		},
		{
			name:     "String without null terminator",
			input:    []byte{'h', 'e', 'l', 'l', 'o'},
			expected: "hello",
		},
		{
			name:     "Empty string",
			input:    []byte{0},
			expected: "",
		},
		{
			name:     "Completely empty",
			input:    []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cStringToGo(tt.input); got != tt.expected {
				t.Errorf("cStringToGo() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPolicyConfig_StructLayout(t *testing.T) {
	policy := PolicyConfig{
		EnforceMode:   ModeEnforce,
		BlockEnviron:  1,
		BlockMem:      1,
		BlockMaps:     0,
		BlockPtrace:   1,
		AllowSelfRead: 1,
		AuditAll:      0,
		Reserved:      0,
	}

	// Verify all fields are set correctly
	if policy.EnforceMode != ModeEnforce {
		t.Error("EnforceMode not set correctly")
	}
	if policy.BlockEnviron != 1 {
		t.Error("BlockEnviron not set correctly")
	}
	if policy.BlockMem != 1 {
		t.Error("BlockMem not set correctly")
	}
	if policy.BlockMaps != 0 {
		t.Error("BlockMaps not set correctly")
	}
	if policy.BlockPtrace != 1 {
		t.Error("BlockPtrace not set correctly")
	}
	if policy.AllowSelfRead != 1 {
		t.Error("AllowSelfRead not set correctly")
	}
	if policy.AuditAll != 0 {
		t.Error("AuditAll not set correctly")
	}
	if policy.Reserved != 0 {
		t.Error("Reserved not set correctly")
	}
}

func TestEventType_Constants(t *testing.T) {
	if EventExec != 1 {
		t.Errorf("EventExec = %v, want 1", EventExec)
	}
	if EventExit != 2 {
		t.Errorf("EventExit = %v, want 2", EventExit)
	}
	if EventBlocked != 3 {
		t.Errorf("EventBlocked = %v, want 3", EventBlocked)
	}
	if EventAudit != 4 {
		t.Errorf("EventAudit = %v, want 4", EventAudit)
	}
}

func TestAccessType_Constants(t *testing.T) {
	if AccessEnviron != 0 {
		t.Errorf("AccessEnviron = %v, want 0", AccessEnviron)
	}
	if AccessMem != 1 {
		t.Errorf("AccessMem = %v, want 1", AccessMem)
	}
	if AccessMaps != 2 {
		t.Errorf("AccessMaps = %v, want 2", AccessMaps)
	}
	if AccessPtrace != 3 {
		t.Errorf("AccessPtrace = %v, want 3", AccessPtrace)
	}
}

func TestEnforceMode_Constants(t *testing.T) {
	if ModeDisabled != 0 {
		t.Errorf("ModeDisabled = %v, want 0", ModeDisabled)
	}
	if ModeAudit != 1 {
		t.Errorf("ModeAudit = %v, want 1", ModeAudit)
	}
	if ModeEnforce != 2 {
		t.Errorf("ModeEnforce = %v, want 2", ModeEnforce)
	}
}
