// Package bpf handles loading and managing eBPF programs for KernelSeal
package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"kernelseal/internal/types"
)

// Manager handles all BPF program loading and event processing
type Manager struct {
	execObjs   execObjects
	lsmObjs    lsmObjects
	execLinks  []link.Link
	lsmLinks   []link.Link
	execReader *ringbuf.Reader
	lsmReader  *ringbuf.Reader

	execHandler func(*types.ExecEvent)
	lsmHandler  func(*types.LSMEvent)

	stopCh chan struct{}
	wg     sync.WaitGroup
	mu     sync.RWMutex
}

// execObjects holds the exec monitor BPF objects
type execObjects struct {
	HandleSysEnterExecve *ebpf.Program `ebpf:"handle_sys_enter_execve"`
	HandleSchedProcExec  *ebpf.Program `ebpf:"handle_sched_process_exec"`
	HandleSchedProcExit  *ebpf.Program `ebpf:"handle_sched_process_exit"`
	ExecEvents           *ebpf.Map     `ebpf:"exec_events"`
	SeenPids             *ebpf.Map     `ebpf:"seen_pids"`
	TargetCgroups        *ebpf.Map     `ebpf:"target_cgroups"`
	CgroupFilterEnabled  *ebpf.Map     `ebpf:"cgroup_filter_enabled"`
	TargetBinaries       *ebpf.Map     `ebpf:"target_binaries"`
	BinaryFilterEnabled  *ebpf.Map     `ebpf:"binary_filter_enabled"`
}

// lsmObjects holds the LSM BPF objects
type lsmObjects struct {
	KernelSealFileOpen          *ebpf.Program `ebpf:"kernelseal_file_open"`
	KernelSealPtraceAccessCheck *ebpf.Program `ebpf:"kernelseal_ptrace_access_check"`
	Events               *ebpf.Map     `ebpf:"events"`
	KernelSealAllowedPids       *ebpf.Map     `ebpf:"kernelseal_allowed_pids"`
	ProtectedPids        *ebpf.Map     `ebpf:"protected_pids"`
	PolicyConfig         *ebpf.Map     `ebpf:"policy_config"`
}

// NewManager creates a new BPF manager
func NewManager() *Manager {
	return &Manager{
		stopCh: make(chan struct{}),
	}
}

// SetExecHandler sets the handler for exec events
func (m *Manager) SetExecHandler(handler func(*types.ExecEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.execHandler = handler
}

// SetLSMHandler sets the handler for LSM events
func (m *Manager) SetLSMHandler(handler func(*types.LSMEvent)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lsmHandler = handler
}

// LoadExecMonitor loads the exec monitor BPF program
func (m *Manager) LoadExecMonitor(objectPath string) error {
	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("failed to load exec monitor spec: %w", err)
	}

	if loadErr := spec.LoadAndAssign(&m.execObjs, nil); loadErr != nil {
		return fmt.Errorf("failed to load exec monitor objects: %w", loadErr)
	}

	// Attach to sys_enter_execve tracepoint (used when binary filter is disabled)
	tpExec, err := link.Tracepoint("syscalls", "sys_enter_execve", m.execObjs.HandleSysEnterExecve, nil)
	if err != nil {
		return fmt.Errorf("failed to attach execve tracepoint: %w", err)
	}
	m.execLinks = append(m.execLinks, tpExec)

	// Attach to sched_process_exec tracepoint (used when binary filter is enabled)
	tpSchedExec, err := link.Tracepoint("sched", "sched_process_exec", m.execObjs.HandleSchedProcExec, nil)
	if err != nil {
		return fmt.Errorf("failed to attach sched_process_exec tracepoint: %w", err)
	}
	m.execLinks = append(m.execLinks, tpSchedExec)

	// Attach to sched_process_exit tracepoint
	tpExit, err := link.Tracepoint("sched", "sched_process_exit", m.execObjs.HandleSchedProcExit, nil)
	if err != nil {
		return fmt.Errorf("failed to attach exit tracepoint: %w", err)
	}
	m.execLinks = append(m.execLinks, tpExit)

	// Create ring buffer reader
	m.execReader, err = ringbuf.NewReader(m.execObjs.ExecEvents)
	if err != nil {
		return fmt.Errorf("failed to create exec ring buffer reader: %w", err)
	}

	log.Println("[OK] Exec monitor BPF programs loaded and attached")
	return nil
}

// LoadLSM loads the LSM BPF program for file protection
func (m *Manager) LoadLSM(objectPath string) error {
	// Check if BPF LSM is available
	if !isLSMAvailable() {
		log.Println("[WARN] BPF-LSM not available, running in audit-only mode")
		return nil
	}

	spec, err := ebpf.LoadCollectionSpec(objectPath)
	if err != nil {
		return fmt.Errorf("failed to load LSM spec: %w", err)
	}

	if loadErr := spec.LoadAndAssign(&m.lsmObjs, nil); loadErr != nil {
		// LSM programs may fail to load if BPF_LSM is not enabled
		log.Printf("[WARN] LSM programs not loaded (BPF-LSM may not be enabled): %v", loadErr)
		return nil
	}

	// Attach LSM hooks
	if m.lsmObjs.KernelSealFileOpen != nil {
		fileOpenLink, attachErr := link.AttachLSM(link.LSMOptions{
			Program: m.lsmObjs.KernelSealFileOpen,
		})
		if attachErr != nil {
			log.Printf("[WARN] Failed to attach file_open LSM: %v", attachErr)
		} else {
			m.lsmLinks = append(m.lsmLinks, fileOpenLink)
		}
	}

	if m.lsmObjs.KernelSealPtraceAccessCheck != nil {
		ptraceLink, attachErr := link.AttachLSM(link.LSMOptions{
			Program: m.lsmObjs.KernelSealPtraceAccessCheck,
		})
		if attachErr != nil {
			log.Printf("[WARN] Failed to attach ptrace LSM: %v", attachErr)
		} else {
			m.lsmLinks = append(m.lsmLinks, ptraceLink)
		}
	}

	// Create ring buffer reader for LSM events
	if m.lsmObjs.Events != nil {
		m.lsmReader, err = ringbuf.NewReader(m.lsmObjs.Events)
		if err != nil {
			return fmt.Errorf("failed to create LSM ring buffer reader: %w", err)
		}
	}

	log.Println("[OK] LSM BPF programs loaded and attached")
	return nil
}

// ConfigurePolicy configures the LSM policy
func (m *Manager) ConfigurePolicy(policy types.PolicyConfig) error {
	if m.lsmObjs.PolicyConfig == nil {
		return errors.New("LSM not loaded")
	}

	key := uint32(0)
	if err := m.lsmObjs.PolicyConfig.Put(key, policy); err != nil {
		return fmt.Errorf("failed to update policy config: %w", err)
	}

	log.Printf("[CONFIG] Policy configured: mode=%s, environ=%v, mem=%v, ptrace=%v",
		policy.EnforceMode, policy.BlockEnviron == 1, policy.BlockMem == 1, policy.BlockPtrace == 1)
	return nil
}

// AllowPID adds a PID to the allowed list (KernelSeal sidecar processes)
func (m *Manager) AllowPID(pid uint32) error {
	if m.lsmObjs.KernelSealAllowedPids == nil {
		return nil // LSM not loaded
	}

	value := uint8(1)
	if err := m.lsmObjs.KernelSealAllowedPids.Put(pid, value); err != nil {
		return fmt.Errorf("failed to add allowed PID %d: %w", pid, err)
	}

	log.Printf("[ALLOW] PID %d added to allowed list", pid)
	return nil
}

// ProtectPID marks a PID as protected (secrets injected)
func (m *Manager) ProtectPID(pid uint32) error {
	if m.lsmObjs.ProtectedPids == nil {
		return nil // LSM not loaded
	}

	value := uint8(1)
	if err := m.lsmObjs.ProtectedPids.Put(pid, value); err != nil {
		return fmt.Errorf("failed to protect PID %d: %w", pid, err)
	}

	log.Printf("[PROTECT] PID %d marked as protected", pid)
	return nil
}

// UnprotectPID removes a PID from the protected list
func (m *Manager) UnprotectPID(pid uint32) error {
	if m.lsmObjs.ProtectedPids == nil {
		return nil
	}

	if err := m.lsmObjs.ProtectedPids.Delete(pid); err != nil {
		return fmt.Errorf("failed to unprotect PID %d: %w", pid, err)
	}

	return nil
}

// AddTargetCgroup adds a cgroup ID to the monitoring list
func (m *Manager) AddTargetCgroup(cgroupID uint64) error {
	if m.execObjs.TargetCgroups == nil {
		return errors.New("exec monitor not loaded")
	}

	value := uint8(1)
	if err := m.execObjs.TargetCgroups.Put(cgroupID, value); err != nil {
		return fmt.Errorf("failed to add target cgroup %d: %w", cgroupID, err)
	}

	return nil
}

// EnableCgroupFilter enables cgroup-based filtering
func (m *Manager) EnableCgroupFilter(enabled bool) error {
	if m.execObjs.CgroupFilterEnabled == nil {
		return errors.New("exec monitor not loaded")
	}

	key := uint32(0)
	value := uint8(0)
	if enabled {
		value = 1
	}

	if err := m.execObjs.CgroupFilterEnabled.Put(key, value); err != nil {
		return fmt.Errorf("failed to set cgroup filter: %w", err)
	}

	return nil
}

// AddTargetBinary adds a binary name to the kernel-side filter list
// When binary filtering is enabled, only these binaries will be monitored
func (m *Manager) AddTargetBinary(binaryName string) error {
	if m.execObjs.TargetBinaries == nil {
		return errors.New("exec monitor not loaded")
	}

	// Create a fixed-size key (16 bytes, matching BPF map key size)
	key := make([]byte, 16)
	copy(key, binaryName)

	value := uint8(1)
	if err := m.execObjs.TargetBinaries.Put(key, value); err != nil {
		return fmt.Errorf("failed to add target binary %s: %w", binaryName, err)
	}

	log.Printf("[FILTER] Added target binary for kernel filtering: %s", binaryName)
	return nil
}

// RemoveTargetBinary removes a binary name from the kernel-side filter list
func (m *Manager) RemoveTargetBinary(binaryName string) error {
	if m.execObjs.TargetBinaries == nil {
		return errors.New("exec monitor not loaded")
	}

	key := make([]byte, 16)
	copy(key, binaryName)

	if err := m.execObjs.TargetBinaries.Delete(key); err != nil {
		return fmt.Errorf("failed to remove target binary %s: %w", binaryName, err)
	}

	return nil
}

// EnableBinaryFilter enables kernel-side binary filtering
// When enabled, only processes matching target_binaries will generate events
func (m *Manager) EnableBinaryFilter(enabled bool) error {
	if m.execObjs.BinaryFilterEnabled == nil {
		return errors.New("exec monitor not loaded")
	}

	key := uint32(0)
	value := uint8(0)
	if enabled {
		value = 1
	}

	if err := m.execObjs.BinaryFilterEnabled.Put(key, value); err != nil {
		return fmt.Errorf("failed to set binary filter: %w", err)
	}

	if enabled {
		log.Println("[FILTER] Kernel-side binary filtering ENABLED - only configured binaries will be monitored")
	} else {
		log.Println("[FILTER] Kernel-side binary filtering DISABLED - all processes will be monitored")
	}

	return nil
}

// GetTargetBinaryCount returns the number of target binaries configured
func (m *Manager) GetTargetBinaryCount() int {
	if m.execObjs.TargetBinaries == nil {
		return 0
	}

	count := 0
	iter := m.execObjs.TargetBinaries.Iterate()
	var key [16]byte
	var value uint8
	for iter.Next(&key, &value) {
		count++
	}
	return count
}

// Start begins processing BPF events
func (m *Manager) Start() {
	m.wg.Add(1)
	go m.processExecEvents()

	if m.lsmReader != nil {
		m.wg.Add(1)
		go m.processLSMEvents()
	}
}

// Stop stops all BPF event processing and cleans up
func (m *Manager) Stop() {
	close(m.stopCh)
	m.wg.Wait()

	// Close readers
	if m.execReader != nil {
		m.execReader.Close()
	}
	if m.lsmReader != nil {
		m.lsmReader.Close()
	}

	// Close links
	for _, l := range m.execLinks {
		l.Close()
	}
	for _, l := range m.lsmLinks {
		l.Close()
	}

	log.Println("[STOP] BPF manager stopped")
}

func (m *Manager) processExecEvents() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		record, err := m.execReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading exec event: %v", err)
			continue
		}

		var event types.ExecEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Error parsing exec event: %v", err)
			continue
		}

		m.mu.RLock()
		handler := m.execHandler
		m.mu.RUnlock()

		if handler != nil {
			handler(&event)
		}
	}
}

func (m *Manager) processLSMEvents() {
	defer m.wg.Done()

	for {
		select {
		case <-m.stopCh:
			return
		default:
		}

		record, err := m.lsmReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			log.Printf("Error reading LSM event: %v", err)
			continue
		}

		var event types.LSMEvent
		if err := binary.Read(bytes.NewReader(record.RawSample), binary.LittleEndian, &event); err != nil {
			log.Printf("Error parsing LSM event: %v", err)
			continue
		}

		m.mu.RLock()
		handler := m.lsmHandler
		m.mu.RUnlock()

		if handler != nil {
			handler(&event)
		}
	}
}

// isLSMAvailable checks if BPF LSM is available on the system
func isLSMAvailable() bool {
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		return false
	}
	return bytes.Contains(data, []byte("bpf"))
}
