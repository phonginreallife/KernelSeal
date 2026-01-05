// X00 - Kubernetes Sidecar for Secret Protection using eBPF and BPF-LSM
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"x00/internal"
	"x00/internal/bpf"
	"x00/internal/secrets"
	"x00/internal/types"
)

const (
	defaultExecMonitorPath = "bpf/exec_monitor.bpf.o"
	defaultLSMPath         = "bpf/lsm_file_protect.bpf.o"
	defaultConfigPath      = "/etc/x00/config.yaml"
)

func main() {
	// Parse command line flags
	configPath := flag.String("config", defaultConfigPath, "Path to X00 configuration file")
	execMonitorPath := flag.String("exec-monitor", defaultExecMonitorPath, "Path to exec monitor BPF object")
	lsmPath := flag.String("lsm", defaultLSMPath, "Path to LSM BPF object")
	flag.Parse()

	log.Println("🚀 Starting X00 Sidecar - Secret Protection System")
	log.Printf("   Version: 0.1.0")
	log.Printf("   Config: %s", *configPath)

	// Initialize components
	secretInjector := secrets.NewInjector()
	policyManager := internal.NewPolicyManager(secretInjector)
	bpfManager := bpf.NewManager()

	// Load configuration if it exists
	if _, err := os.Stat(*configPath); err == nil {
		if err := policyManager.LoadConfig(*configPath); err != nil {
			log.Printf("⚠️  Failed to load config: %v (using defaults)", err)
		}
	} else {
		log.Printf("📋 Config file not found, using defaults")
	}

	// Set up BPF policy update callback
	policyManager.SetPolicyUpdateCallback(func(policy types.PolicyConfig) {
		if err := bpfManager.ConfigurePolicy(policy); err != nil {
			log.Printf("⚠️  Failed to update BPF policy: %v", err)
		}
	})

	// Set up secret injection callback
	secretInjector.SetInjectedCallback(func(pid uint32) {
		if err := bpfManager.ProtectPID(pid); err != nil {
			log.Printf("⚠️  Failed to protect PID %d: %v", pid, err)
		}
	})

	// Load BPF programs
	if err := bpfManager.LoadExecMonitor(*execMonitorPath); err != nil {
		log.Fatalf("❌ Failed to load exec monitor: %v", err)
	}

	// Configure kernel-side binary filtering
	// This ensures we only process events for configured binaries
	targetBinaries := policyManager.GetTargetBinaries()
	kernelFilterEnabled := policyManager.IsKernelBinaryFilterEnabled()

	if kernelFilterEnabled && len(targetBinaries) > 0 {
		for _, binary := range targetBinaries {
			if err := bpfManager.AddTargetBinary(binary); err != nil {
				log.Printf("⚠️  Failed to add target binary %s: %v", binary, err)
			}
		}
		// Enable kernel-side filtering
		if err := bpfManager.EnableBinaryFilter(true); err != nil {
			log.Printf("⚠️  Failed to enable binary filter: %v", err)
		}
		log.Printf("🎯 Kernel-side filtering enabled for %d binaries: %v", len(targetBinaries), targetBinaries)
	} else if !kernelFilterEnabled {
		log.Println("🔍 Kernel-side binary filtering DISABLED by config - monitoring all processes")
	} else {
		log.Println("⚠️  No target binaries configured - monitoring all processes (not recommended for production)")
	}

	// Try to load LSM (may not be available on all kernels)
	if err := bpfManager.LoadLSM(*lsmPath); err != nil {
		log.Printf("⚠️  LSM not loaded: %v", err)
	}

	// Allow our own PID to access protected files
	// #nosec G115 - PID is always positive and fits in uint32
	ownPID := uint32(os.Getpid()) //nolint:gosec
	if err := bpfManager.AllowPID(ownPID); err != nil {
		log.Printf("⚠️  Failed to allow own PID: %v", err)
	}

	// Configure initial policy
	policy := policyManager.GetBPFPolicy()
	if err := bpfManager.ConfigurePolicy(policy); err != nil {
		log.Printf("⚠️  Failed to configure policy: %v", err)
	}

	// Set up event handlers
	bpfManager.SetExecHandler(func(event *types.ExecEvent) {
		handleExecEvent(event, policyManager, secretInjector, bpfManager)
	})

	bpfManager.SetLSMHandler(func(event *types.LSMEvent) {
		handleLSMEvent(event)
	})

	// Start processing events
	bpfManager.Start()

	log.Println("✅ X00 Sidecar running - monitoring for process execution")
	log.Println("   Press Ctrl+C to stop")

	// Wait for shutdown signal
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	<-sigs

	log.Println("🛑 Shutting down X00...")
	bpfManager.Stop()
	log.Println("👋 X00 stopped")
}

// handleExecEvent processes exec events from BPF
func handleExecEvent(event *types.ExecEvent, pm *internal.PolicyManager,
	injector *secrets.Injector, bpfMgr *bpf.Manager) {

	switch event.EventType {
	case types.EventExec:
		comm := event.GetComm()
		filename := event.GetFilename()

		// Extract binary name from filename (e.g., "/usr/bin/cat" -> "cat")
		binaryName := filename
		if idx := strings.LastIndex(filename, "/"); idx >= 0 {
			binaryName = filename[idx+1:]
		}

		log.Printf("📍 EXEC: PID=%d PPID=%d Comm=%s File=%s Binary=%s CgroupID=%d",
			event.PID, event.PPID, comm, filename, binaryName, event.CgroupID)

		// Check if we should inject secrets into this process (match on binary name)
		secretsList := pm.ShouldInjectSecrets(binaryName, event.CgroupID)
		if len(secretsList) > 0 {
			result := injector.InjectSecrets(event.PID, secretsList)
			if result.Success {
				log.Printf("💉 Secrets injected into PID %d: %v", event.PID, result.Secrets)
			} else {
				log.Printf("❌ Failed to inject secrets into PID %d: %v", event.PID, result.Error)
			}
		}

	case types.EventExit:
		log.Printf("📍 EXIT: PID=%d Comm=%s", event.PID, event.GetComm())

		// Clean up secrets for exited process
		if err := injector.CleanupSecrets(event.PID); err != nil {
			log.Printf("⚠️  Cleanup error: %v", err)
		}

		// Remove from protected list
		if err := bpfMgr.UnprotectPID(event.PID); err != nil {
			log.Printf("⚠️  Failed to unprotect PID %d: %v", event.PID, err)
		}
	}
}

// handleLSMEvent processes LSM events from BPF
func handleLSMEvent(event *types.LSMEvent) {
	eventStr := "AUDIT"
	if event.EventType == types.EventBlocked {
		eventStr = "BLOCKED"
	}

	accessStr := event.AccessType.String()

	log.Printf("🛡️  LSM %s: PID=%d attempted %s access to PID=%d (%s)",
		eventStr, event.PID, accessStr, event.TargetPID, event.GetComm())
}
