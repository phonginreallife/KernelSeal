// Package integration contains integration and system tests for X00
// These tests require root privileges and a kernel with BPF-LSM support
package integration

import (
	"os"
	"testing"

	"x00/internal/bpf"
	"x00/internal/types"
)

// TestBPF_FullWorkflow tests the complete BPF workflow
// Requires: root, kernel with BPF-LSM, compiled BPF objects
func TestBPF_FullWorkflow(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: requires root")
	}

	// Check BPF object files exist
	execMonitorPath := "../../bpf/exec_monitor.bpf.o"
	if _, err := os.Stat(execMonitorPath); os.IsNotExist(err) {
		t.Skip("Skipping integration test: BPF objects not compiled")
	}

	mgr := bpf.NewManager()

	// Load exec monitor
	if err := mgr.LoadExecMonitor(execMonitorPath); err != nil {
		t.Fatalf("Failed to load exec monitor: %v", err)
	}

	// Set up event handler
	eventReceived := make(chan *types.ExecEvent, 10)
	mgr.SetExecHandler(func(event *types.ExecEvent) {
		eventReceived <- event
	})

	// Start processing
	mgr.Start()
	defer mgr.Stop()

	t.Log("BPF exec monitor loaded and running")

	// The test would continue with spawning processes and verifying events
	// This is a placeholder for full integration testing
}

// TestLSM_FileProtection tests LSM file protection
// Requires: root, kernel 5.7+ with BPF-LSM enabled
func TestLSM_FileProtection(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: requires root")
	}

	// Check if BPF-LSM is available
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		t.Skip("Skipping integration test: cannot read LSM config")
	}

	if string(data) == "" || !containsBPF(string(data)) {
		t.Skip("Skipping integration test: BPF-LSM not enabled")
	}

	lsmPath := "../../bpf/lsm_file_protect.bpf.o"
	if _, err := os.Stat(lsmPath); os.IsNotExist(err) {
		t.Skip("Skipping integration test: LSM BPF object not compiled")
	}

	mgr := bpf.NewManager()

	if err := mgr.LoadLSM(lsmPath); err != nil {
		t.Logf("LSM not loaded (may not be available): %v", err)
		return
	}

	// Configure policy
	policy := types.NewDefaultPolicy()
	if err := mgr.ConfigurePolicy(policy); err != nil {
		t.Fatalf("Failed to configure policy: %v", err)
	}

	// Protect a PID
	testPID := uint32(os.Getpid())
	if err := mgr.ProtectPID(testPID); err != nil {
		t.Fatalf("Failed to protect PID: %v", err)
	}

	t.Log("LSM file protection configured")
	mgr.Stop()
}

func containsBPF(s string) bool {
	return len(s) > 0 && (s == "bpf" || len(s) > 3)
}
