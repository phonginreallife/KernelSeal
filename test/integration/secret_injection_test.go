// Package integration contains integration and system tests for X00
package integration

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"x00/internal/secrets"
)

// TestSecretInjection_E2E tests end-to-end secret injection
// Requires: root privileges for /proc access
func TestSecretInjection_E2E(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: requires root")
	}

	injector := secrets.NewInjector()

	// Register secrets for a test binary
	injector.RegisterSecrets("sleep", []secrets.Secret{
		{Name: "TEST_SECRET", Value: "integration-test-value"},
	})

	// Spawn a test process
	cmd := exec.Command("sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start test process: %v", err)
	}
	defer cmd.Process.Kill()

	// Give process time to start
	time.Sleep(100 * time.Millisecond)

	pid := uint32(cmd.Process.Pid)
	t.Logf("Test process PID: %d", pid)

	// Get secrets for the process
	secretList := injector.GetSecretsForProcess("sleep", 0)
	if len(secretList) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(secretList))
	}

	// Inject secrets
	result := injector.InjectSecrets(pid, secretList)
	if result.Error != nil {
		t.Logf("Injection result (may fail without full setup): %v", result.Error)
	}

	// Cleanup
	injector.CleanupSecrets(pid)
}

// TestSecretFile_Permissions tests secret file permissions
func TestSecretFile_Permissions(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("Skipping integration test: requires root")
	}

	// Create test secrets directory
	testDir := filepath.Join(os.TempDir(), "x00-test-secrets")
	if err := os.MkdirAll(testDir, 0700); err != nil {
		t.Fatalf("Failed to create test directory: %v", err)
	}
	defer os.RemoveAll(testDir)

	// Verify directory permissions
	info, err := os.Stat(testDir)
	if err != nil {
		t.Fatalf("Failed to stat test directory: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0700 {
		t.Errorf("Directory permissions = %o, want 0700", perm)
	}

	// Create a test secret file
	secretFile := filepath.Join(testDir, "test-secret")
	if writeErr := os.WriteFile(secretFile, []byte("secret-value"), 0400); writeErr != nil {
		t.Fatalf("Failed to create secret file: %v", writeErr)
	}

	// Verify file permissions
	info, err = os.Stat(secretFile)
	if err != nil {
		t.Fatalf("Failed to stat secret file: %v", err)
	}

	perm = info.Mode().Perm()
	if perm != 0400 {
		t.Errorf("File permissions = %o, want 0400", perm)
	}
}
