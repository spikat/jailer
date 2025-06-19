package main

import (
	"os"
	"testing"
	"time"
)

// TestDetectCgroupVersion tests cgroup version detection
func TestDetectCgroupVersion(t *testing.T) {
	version, basePath, err := detectCgroupVersion()
	if err != nil {
		t.Fatalf("Failed to detect cgroup version: %v", err)
	}

	if version != 1 && version != 2 {
		t.Errorf("Invalid cgroup version detected: %d", version)
	}

	if basePath == "" {
		t.Error("Base path should not be empty")
	}

	t.Logf("Detected cgroups v%d at %s", version, basePath)
}

// TestDetectFirewallTool tests firewall tool detection
func TestDetectFirewallTool(t *testing.T) {
	// Skip test if not running as root
	if os.Geteuid() != 0 {
		t.Skip("Skipping firewall detection test: requires root privileges")
	}

	tool, err := detectFirewallTool()
	if err != nil {
		t.Fatalf("Failed to detect firewall tool: %v", err)
	}

	if tool != "nftables" && tool != "iptables" {
		t.Errorf("Invalid firewall tool detected: %s", tool)
	}

	t.Logf("Detected firewall tool: %s", tool)
}

// TestProcessExists tests the process existence check function
func TestProcessExists(t *testing.T) {
	// Test with current process (must exist)
	currentPID := os.Getpid()
	if !processExists(currentPID) {
		t.Errorf("Current process %d should exist", currentPID)
	}

	// Test with non-existent PID (very unlikely to exist)
	if processExists(999999) {
		t.Log("Warning: PID 999999 exists, this is unexpected but not necessarily an error")
	}
}

// TestGetProcessName tests retrieving a process name
func TestGetProcessName(t *testing.T) {
	currentPID := os.Getpid()
	name := getProcessName(currentPID)

	if name == "" {
		t.Error("Process name should not be empty")
	}

	t.Logf("Current process name: %s", name)
}

// TestGetProcessCgroup tests retrieving a process cgroup
func TestGetProcessCgroup(t *testing.T) {
	currentPID := os.Getpid()
	cgroup, err := getProcessCgroup(currentPID)

	if err != nil {
		t.Fatalf("Failed to get cgroup for current process: %v", err)
	}

	if cgroup == "" {
		t.Error("Cgroup should not be empty")
	}

	t.Logf("Current process cgroup: %s", cgroup)
}

// TestJailerStateCreation tests jailer state creation
func TestJailerStateCreation(t *testing.T) {
	state := NewJailerState()

	if state == nil {
		t.Fatal("JailerState should not be nil")
	}

	if state.ActiveJails == nil {
		t.Error("ActiveJails map should be initialized")
	}

	if len(state.ActiveJails) != 0 {
		t.Error("ActiveJails should be empty initially")
	}

	// Test that cgroup paths are set after initialization
	if err := initializeCgroup(state); err != nil && os.Geteuid() == 0 {
		t.Errorf("Failed to initialize cgroups: %v", err)
	}

	if state.NetworkCgroupPath == "" && os.Geteuid() == 0 {
		t.Error("NetworkCgroupPath should be set after initialization")
	}
}

// TestValidateProcessAccess tests process access validation
func TestValidateProcessAccess(t *testing.T) {
	currentPID := os.Getpid()

	if err := validateProcessAccess(currentPID); err != nil {
		t.Errorf("Should be able to access current process: %v", err)
	}

	// Test with non-existent PID
	if err := validateProcessAccess(999999); err == nil {
		t.Log("Warning: PID 999999 seems to be accessible, this is unexpected")
	}
}

// TestCleanupDeadProcesses tests dead process cleanup
func TestCleanupDeadProcesses(t *testing.T) {
	state := NewJailerState()

	// Create fake jail with non-existent PID
	state.ActiveJails[999999] = &Jail{
		PID:            999999,
		OriginalCgroup: "/",
		JailTypes:      []string{"network"},
		Timestamp:      time.Now(),
		Children:       []int{999998},
	}

	// Cleanup should remove non-existent process
	cleanupDeadProcesses(state)

	if len(state.ActiveJails) != 0 {
		t.Error("Dead processes should have been cleaned up")
	}
}

// TestJailMethods tests the Jail struct methods
func TestJailMethods(t *testing.T) {
	jail := &Jail{
		PID:            1234,
		OriginalCgroup: "/",
		JailTypes:      []string{"network"},
		Timestamp:      time.Now(),
		Children:       []int{},
	}

	// Test HasJailType
	if !jail.HasJailType("network") {
		t.Error("Should have network jail type")
	}

	if jail.HasJailType("cpu") {
		t.Error("Should not have cpu jail type")
	}

	// Test AddJailType
	jail.AddJailType("cpu")
	if !jail.HasJailType("cpu") {
		t.Error("Should have cpu jail type after adding")
	}

	if len(jail.JailTypes) != 2 {
		t.Errorf("Should have 2 jail types, got %d", len(jail.JailTypes))
	}

	// Test GetJailTypesString
	jailTypesStr := jail.GetJailTypesString()
	if jailTypesStr != "network,cpu" && jailTypesStr != "cpu,network" {
		t.Errorf("Unexpected jail types string: %s", jailTypesStr)
	}

	// Test RemoveJailType
	jail.RemoveJailType("network")
	if jail.HasJailType("network") {
		t.Error("Should not have network jail type after removal")
	}

	if len(jail.JailTypes) != 1 {
		t.Errorf("Should have 1 jail type, got %d", len(jail.JailTypes))
	}
}

// TestMultipleJailTypes tests multiple jail type functionality
func TestMultipleJailTypes(t *testing.T) {
	jail := &Jail{
		PID:            1234,
		OriginalCgroup: "/",
		JailTypes:      []string{},
		Timestamp:      time.Now(),
		Children:       []int{},
	}

	// Test adding multiple jail types
	jail.AddJailType("network")
	jail.AddJailType("cpu")

	if len(jail.JailTypes) != 2 {
		t.Errorf("Should have 2 jail types, got %d", len(jail.JailTypes))
	}

	// Test that adding the same type twice doesn't duplicate
	jail.AddJailType("network")
	if len(jail.JailTypes) != 2 {
		t.Errorf("Should still have 2 jail types after duplicate add, got %d", len(jail.JailTypes))
	}

	// Test removing one type
	jail.RemoveJailType("cpu")
	if len(jail.JailTypes) != 1 {
		t.Errorf("Should have 1 jail type after removal, got %d", len(jail.JailTypes))
	}

	if !jail.HasJailType("network") {
		t.Error("Should still have network jail type")
	}

	if jail.HasJailType("cpu") {
		t.Error("Should not have cpu jail type after removal")
	}
}

// TestCommandExists tests command existence check
func TestCommandExists(t *testing.T) {
	// Test with a command that certainly exists
	if !commandExists("ls") {
		t.Error("ls command should exist on Unix systems")
	}

	// Test with a command that doesn't exist
	if commandExists("this_command_does_not_exist_12345") {
		t.Error("Non-existent command should not be found")
	}
}

// TestCgroupInitialization tests cgroup initialization (requires root)
func TestCgroupInitialization(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("Skipping cgroup initialization test: requires root privileges")
	}

	state := NewJailerState()
	err := initializeCgroup(state)
	if err != nil {
		t.Fatalf("Failed to initialize cgroups: %v", err)
	}

	// Check that paths are set
	if state.NetworkCgroupPath == "" {
		t.Error("NetworkCgroupPath should be set")
	}

	if state.CpuCgroupPath == "" {
		t.Error("CpuCgroupPath should be set")
	}

	if state.NetworkCpuCgroupPath == "" {
		t.Error("NetworkCpuCgroupPath should be set")
	}

	if state.CgroupVersion != 1 && state.CgroupVersion != 2 {
		t.Errorf("Invalid cgroup version: %d", state.CgroupVersion)
	}

	t.Logf("Initialized cgroups v%d", state.CgroupVersion)
	t.Logf("Network cgroup path: %s", state.NetworkCgroupPath)
	t.Logf("CPU cgroup path: %s", state.CpuCgroupPath)
	t.Logf("Combined cgroup path: %s", state.NetworkCpuCgroupPath)
}

// BenchmarkGetProcessChildren benchmark for retrieving child processes
func BenchmarkGetProcessChildren(b *testing.B) {
	currentPID := os.Getpid()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := getProcessChildren(currentPID)
		if err != nil {
			b.Fatalf("Failed to get process children: %v", err)
		}
	}
}

// BenchmarkProcessExists benchmark for process existence check
func BenchmarkProcessExists(b *testing.B) {
	currentPID := os.Getpid()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		processExists(currentPID)
	}
}

// BenchmarkJailMethods benchmark for jail type operations
func BenchmarkJailMethods(b *testing.B) {
	jail := &Jail{
		PID:            1234,
		OriginalCgroup: "/",
		JailTypes:      []string{"network"},
		Timestamp:      time.Now(),
		Children:       []int{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jail.AddJailType("cpu")
		jail.HasJailType("cpu")
		jail.RemoveJailType("cpu")
		jail.GetJailTypesString()
	}
}
