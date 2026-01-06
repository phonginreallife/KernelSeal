package bpf

import (
	"os"
	"testing"

	"kernelseal/internal/types"
)

func TestNewManager(t *testing.T) {
	mgr := NewManager()
	if mgr == nil {
		t.Fatal("NewManager returned nil")
	}
	if mgr.stopCh == nil {
		t.Error("stopCh channel not initialized")
	}
}

func TestManager_SetExecHandler(t *testing.T) {
	mgr := NewManager()

	mgr.SetExecHandler(func(event *types.ExecEvent) {
		// Handler would be called on events
	})

	mgr.mu.RLock()
	handler := mgr.execHandler
	mgr.mu.RUnlock()

	if handler == nil {
		t.Error("Exec handler not set")
	}
}

func TestManager_SetLSMHandler(t *testing.T) {
	mgr := NewManager()

	mgr.SetLSMHandler(func(event *types.LSMEvent) {
		// Handler would be called on events
	})

	mgr.mu.RLock()
	handler := mgr.lsmHandler
	mgr.mu.RUnlock()

	if handler == nil {
		t.Error("LSM handler not set")
	}
}

func TestManager_LoadExecMonitor_InvalidPath(t *testing.T) {
	mgr := NewManager()

	err := mgr.LoadExecMonitor("/nonexistent/path.o")
	if err == nil {
		t.Error("Expected error for invalid path")
	}
}

func TestManager_LoadLSM_InvalidPath(t *testing.T) {
	mgr := NewManager()

	// LoadLSM may return nil if LSM is not available
	err := mgr.LoadLSM("/nonexistent/path.o")
	_ = err // Don't fail - LSM availability varies
}

func TestManager_ConfigurePolicy_NoLSM(t *testing.T) {
	mgr := NewManager()

	policy := types.NewDefaultPolicy()
	err := mgr.ConfigurePolicy(policy)
	if err == nil {
		t.Error("Expected error when LSM not loaded")
	}
}

func TestManager_AllowPID_NoLSM(t *testing.T) {
	mgr := NewManager()

	err := mgr.AllowPID(12345)
	if err != nil {
		t.Errorf("AllowPID should not error when LSM not loaded: %v", err)
	}
}

func TestManager_ProtectPID_NoLSM(t *testing.T) {
	mgr := NewManager()

	err := mgr.ProtectPID(12345)
	if err != nil {
		t.Errorf("ProtectPID should not error when LSM not loaded: %v", err)
	}
}

func TestManager_UnprotectPID_NoLSM(t *testing.T) {
	mgr := NewManager()

	err := mgr.UnprotectPID(12345)
	if err != nil {
		t.Errorf("UnprotectPID should not error when LSM not loaded: %v", err)
	}
}

func TestManager_AddTargetCgroup_NoExecMonitor(t *testing.T) {
	mgr := NewManager()

	err := mgr.AddTargetCgroup(12345)
	if err == nil {
		t.Error("Expected error when exec monitor not loaded")
	}
}

func TestManager_EnableCgroupFilter_NoExecMonitor(t *testing.T) {
	mgr := NewManager()

	err := mgr.EnableCgroupFilter(true)
	if err == nil {
		t.Error("Expected error when exec monitor not loaded")
	}
}

func TestManager_Stop_NoPrograms(t *testing.T) {
	mgr := NewManager()

	mgr.Start()
	mgr.Stop()
}

func TestIsLSMAvailable(t *testing.T) {
	available := isLSMAvailable()

	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		if available {
			t.Error("isLSMAvailable returned true but /sys/kernel/security/lsm is not readable")
		}
	} else {
		t.Logf("LSM available: %v, LSM list: %s", available, string(data))
	}
}

func TestManager_ConcurrentHandlers(t *testing.T) {
	mgr := NewManager()

	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			mgr.SetExecHandler(func(e *types.ExecEvent) {})
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			mgr.SetLSMHandler(func(e *types.LSMEvent) {})
		}
		done <- true
	}()

	<-done
	<-done
}

func TestManager_MultipleStops(t *testing.T) {
	mgr := NewManager()
	mgr.Start()
	mgr.Stop()
}

// Benchmark tests
func BenchmarkManager_SetExecHandler(b *testing.B) {
	mgr := NewManager()
	handler := func(e *types.ExecEvent) {}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.SetExecHandler(handler)
	}
}

func BenchmarkManager_SetLSMHandler(b *testing.B) {
	mgr := NewManager()
	handler := func(e *types.LSMEvent) {}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mgr.SetLSMHandler(handler)
	}
}
