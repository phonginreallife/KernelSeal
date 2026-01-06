package secrets

import (
	"os"
	"testing"
)

func TestNewInjector(t *testing.T) {
	injector := NewInjector()
	if injector == nil {
		t.Fatal("NewInjector returned nil")
	}
	if injector.secretsByBinary == nil {
		t.Error("secretsByBinary map not initialized")
	}
	if injector.secretsByCgroup == nil {
		t.Error("secretsByCgroup map not initialized")
	}
}

func TestInjector_RegisterSecrets(t *testing.T) {
	injector := NewInjector()

	secrets := []Secret{
		{Name: "DB_PASSWORD", Value: "secret123"},
		{Name: "API_KEY", Value: "key456"},
	}

	injector.RegisterSecrets("myapp", secrets)

	result := injector.GetSecretsForProcess("myapp", 0)
	if len(result) != 2 {
		t.Fatalf("Expected 2 secrets, got %d", len(result))
	}
}

func TestInjector_RegisterSecretsForCgroup(t *testing.T) {
	injector := NewInjector()

	secrets := []Secret{
		{Name: "CGROUP_SECRET", Value: "cgvalue"},
	}

	injector.RegisterSecretsForCgroup(12345, secrets)

	result := injector.GetSecretsForProcess("unknown", 12345)
	if len(result) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(result))
	}
	if result[0].Name != "CGROUP_SECRET" {
		t.Errorf("Secret name = %v, want CGROUP_SECRET", result[0].Name)
	}
}

func TestInjector_GetSecretsForProcess_Combined(t *testing.T) {
	injector := NewInjector()

	injector.RegisterSecrets("myapp", []Secret{
		{Name: "BINARY_SECRET", Value: "binaryval"},
	})

	injector.RegisterSecretsForCgroup(12345, []Secret{
		{Name: "CGROUP_SECRET", Value: "cgroupval"},
	})

	// Should get both when both match
	result := injector.GetSecretsForProcess("myapp", 12345)
	if len(result) != 2 {
		t.Fatalf("Expected 2 secrets, got %d", len(result))
	}

	// Should get only binary secret when cgroup doesn't match
	result = injector.GetSecretsForProcess("myapp", 99999)
	if len(result) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(result))
	}
	if result[0].Name != "BINARY_SECRET" {
		t.Errorf("Secret name = %v, want BINARY_SECRET", result[0].Name)
	}

	// Should get only cgroup secret when binary doesn't match
	result = injector.GetSecretsForProcess("otherapp", 12345)
	if len(result) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(result))
	}
	if result[0].Name != "CGROUP_SECRET" {
		t.Errorf("Secret name = %v, want CGROUP_SECRET", result[0].Name)
	}

	// Should get nothing when neither matches
	result = injector.GetSecretsForProcess("otherapp", 99999)
	if len(result) != 0 {
		t.Fatalf("Expected 0 secrets, got %d", len(result))
	}
}

func TestInjector_SetInjectedCallback(t *testing.T) {
	injector := NewInjector()

	injector.SetInjectedCallback(func(pid uint32) {
		// Callback would be called after injection
	})

	if injector.onInjected == nil {
		t.Error("Callback not set")
	}
}

func TestInjector_InjectSecrets_NoSecrets(t *testing.T) {
	injector := NewInjector()

	result := injector.InjectSecrets(12345, nil)
	if !result.Success {
		t.Error("InjectSecrets with no secrets should succeed")
	}
	if result.PID != 12345 {
		t.Errorf("PID = %v, want 12345", result.PID)
	}
	if len(result.Secrets) != 0 {
		t.Errorf("Expected 0 secrets in result, got %d", len(result.Secrets))
	}
}

func TestInjector_InjectSecrets_EmptyList(t *testing.T) {
	injector := NewInjector()

	result := injector.InjectSecrets(12345, []Secret{})
	if !result.Success {
		t.Error("InjectSecrets with empty list should succeed")
	}
}

func TestInjector_CleanupSecrets_NonexistentPID(t *testing.T) {
	injector := NewInjector()

	err := injector.CleanupSecrets(99999999)
	if err != nil {
		t.Errorf("CleanupSecrets should not error for nonexistent PID: %v", err)
	}
}

func TestParseEnviron(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected map[string]string
	}{
		{
			name:  "Normal environ",
			input: []byte("PATH=/usr/bin\kernelsealHOME=/home/user\kernelsealSHELL=/bin/bash\kernelseal"),
			expected: map[string]string{
				"PATH":  "/usr/bin",
				"HOME":  "/home/user",
				"SHELL": "/bin/bash",
			},
		},
		{
			name:     "Empty environ",
			input:    []byte{},
			expected: map[string]string{},
		},
		{
			name:     "Single entry",
			input:    []byte("FOO=bar\kernelseal"),
			expected: map[string]string{"FOO": "bar"},
		},
		{
			name:  "Value with equals sign",
			input: []byte("CONN=host=localhost;port=5432\kernelseal"),
			expected: map[string]string{
				"CONN": "host=localhost;port=5432",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseEnviron(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("Length = %d, want %d", len(result), len(tt.expected))
			}
			for k, v := range tt.expected {
				if result[k] != v {
					t.Errorf("result[%s] = %s, want %s", k, result[k], v)
				}
			}
		})
	}
}

func TestGetProcessUIDGID(t *testing.T) {
	pid := os.Getpid()
	uid, gid, err := getProcessUIDGID(uint32(pid))
	if err != nil {
		t.Fatalf("getProcessUIDGID failed: %v", err)
	}

	expectedUID := os.Getuid()
	expectedGID := os.Getgid()

	if uid != expectedUID {
		t.Errorf("UID = %d, want %d", uid, expectedUID)
	}
	if gid != expectedGID {
		t.Errorf("GID = %d, want %d", gid, expectedGID)
	}
}

func TestGetProcessUIDGID_InvalidPID(t *testing.T) {
	_, _, err := getProcessUIDGID(9999999)
	if err == nil {
		t.Error("Expected error for invalid PID")
	}
}

func TestSecret_Struct(t *testing.T) {
	secret := Secret{
		Name:  "MY_SECRET",
		Value: "my_value",
	}

	if secret.Name != "MY_SECRET" {
		t.Errorf("Name = %v, want MY_SECRET", secret.Name)
	}
	if secret.Value != "my_value" {
		t.Errorf("Value = %v, want my_value", secret.Value)
	}
}

func TestInjectionResult_Struct(t *testing.T) {
	result := InjectionResult{
		PID:     12345,
		Success: true,
		Secrets: []string{"SECRET1", "SECRET2"},
		Error:   nil,
	}

	if result.PID != 12345 {
		t.Errorf("PID = %v, want 12345", result.PID)
	}
	if !result.Success {
		t.Error("Success should be true")
	}
	if len(result.Secrets) != 2 {
		t.Errorf("Secrets length = %d, want 2", len(result.Secrets))
	}
}

func TestInjector_ConcurrentAccess(t *testing.T) {
	injector := NewInjector()

	done := make(chan bool)

	go func() {
		for i := 0; i < 100; i++ {
			injector.RegisterSecrets("app1", []Secret{
				{Name: "SECRET", Value: "value"},
			})
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			_ = injector.GetSecretsForProcess("app1", 0)
		}
		done <- true
	}()

	<-done
	<-done
}

func TestInjector_RegisterSecrets_Overwrite(t *testing.T) {
	injector := NewInjector()

	injector.RegisterSecrets("myapp", []Secret{
		{Name: "OLD_SECRET", Value: "old_value"},
	})

	injector.RegisterSecrets("myapp", []Secret{
		{Name: "NEW_SECRET", Value: "new_value"},
	})

	result := injector.GetSecretsForProcess("myapp", 0)
	if len(result) != 1 {
		t.Fatalf("Expected 1 secret, got %d", len(result))
	}
	if result[0].Name != "NEW_SECRET" {
		t.Errorf("Secret name = %v, want NEW_SECRET", result[0].Name)
	}
}

func TestInjector_InjectSecretsCallback(t *testing.T) {
	injector := NewInjector()

	injector.SetInjectedCallback(func(pid uint32) {
		// Callback would be called after successful injection
	})

	result := injector.InjectSecrets(12345, []Secret{})
	if !result.Success {
		t.Error("InjectSecrets should succeed with empty secrets")
	}
}
