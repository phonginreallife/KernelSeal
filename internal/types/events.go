// Package types defines shared data structures for X00
package types

// EventType defines the type of BPF event
type EventType uint8

const (
	EventExec    EventType = 1 // Process executed
	EventExit    EventType = 2 // Process exited
	EventBlocked EventType = 3 // Access blocked by LSM
	EventAudit   EventType = 4 // Audit log (not blocked)
)

func (e EventType) String() string {
	switch e {
	case EventExec:
		return "EXEC"
	case EventExit:
		return "EXIT"
	case EventBlocked:
		return "BLOCKED"
	case EventAudit:
		return "AUDIT"
	default:
		return "UNKNOWN"
	}
}

// AccessType defines what resource was accessed
type AccessType uint8

const (
	AccessEnviron AccessType = 0 // /proc/*/environ
	AccessMem     AccessType = 1 // /proc/*/mem
	AccessMaps    AccessType = 2 // /proc/*/maps
	AccessPtrace  AccessType = 3 // ptrace syscall
)

func (a AccessType) String() string {
	switch a {
	case AccessEnviron:
		return "environ"
	case AccessMem:
		return "mem"
	case AccessMaps:
		return "maps"
	case AccessPtrace:
		return "ptrace"
	default:
		return "unknown"
	}
}

// EnforceMode defines the policy enforcement level
type EnforceMode uint8

const (
	ModeDisabled EnforceMode = 0 // Policy disabled
	ModeAudit    EnforceMode = 1 // Log only, don't block
	ModeEnforce  EnforceMode = 2 // Log and block
)

func (m EnforceMode) String() string {
	switch m {
	case ModeDisabled:
		return "disabled"
	case ModeAudit:
		return "audit"
	case ModeEnforce:
		return "enforce"
	default:
		return "unknown"
	}
}

// ExecEvent represents a process execution event from BPF
// Must match struct x00_exec_event in x00_common.h exactly
type ExecEvent struct {
	Timestamp uint64
	PID       uint32
	TGID      uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	Pad0      uint32 // padding to align CgroupID to 8 bytes
	CgroupID  uint64
	EventType EventType
	Pad1      [3]byte // padding after EventType
	Comm      [16]byte
	Filename  [256]byte
}

// GetComm returns the command name as a string
func (e *ExecEvent) GetComm() string {
	return cStringToGo(e.Comm[:])
}

// GetFilename returns the filename as a string
func (e *ExecEvent) GetFilename() string {
	return cStringToGo(e.Filename[:])
}

// LSMEvent represents an LSM audit/block event from BPF
type LSMEvent struct {
	Timestamp  uint64
	PID        uint32
	TGID       uint32
	UID        uint32
	TargetPID  uint32
	EventType  EventType
	AccessType AccessType
	_          [2]byte // padding
	Comm       [16]byte
	Path       [256]byte
}

// GetComm returns the command name as a string
func (e *LSMEvent) GetComm() string {
	return cStringToGo(e.Comm[:])
}

// GetPath returns the path as a string
func (e *LSMEvent) GetPath() string {
	return cStringToGo(e.Path[:])
}

// PolicyConfig represents the BPF policy configuration
type PolicyConfig struct {
	EnforceMode   EnforceMode
	BlockEnviron  uint8
	BlockMem      uint8
	BlockMaps     uint8
	BlockPtrace   uint8
	AllowSelfRead uint8
	AuditAll      uint8
	Reserved      uint8
}

// NewDefaultPolicy creates a default policy configuration
func NewDefaultPolicy() PolicyConfig {
	return PolicyConfig{
		EnforceMode:   ModeEnforce,
		BlockEnviron:  1,
		BlockMem:      1,
		BlockMaps:     0,
		BlockPtrace:   1,
		AllowSelfRead: 1,
		AuditAll:      0,
	}
}

// cStringToGo converts a null-terminated C string to Go string
func cStringToGo(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}
