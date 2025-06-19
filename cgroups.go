package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

const (
	cpuPeriod = "100000\n" // 100ms
	cpuQuota  = "1000\n"   // 1% of 100ms

	JailCpuCgroup        = "jail-cpu"
	JailNetworkCgroup    = "jail-network"
	JailNetworkCpuCgroup = "jail-network-cpu"
)

// detectCgroupVersion detects whether the system uses cgroups v1 or v2
func detectCgroupVersion() (int, string, error) {
	// Check cgroups v2 first (unified hierarchy)
	if _, err := os.Stat("/sys/fs/cgroup/cgroup.controllers"); err == nil {
		return 2, "/sys/fs/cgroup", nil
	}

	// Check cgroups v1
	if _, err := os.Stat("/sys/fs/cgroup/memory"); err == nil {
		return 1, "/sys/fs/cgroup", nil
	}

	return 0, "", fmt.Errorf("neither cgroups v1 nor v2 found")
}

// initializeCgroup initializes the jail cgroup according to the detected version
func initializeCgroup(state *JailerState) error {
	version, basePath, err := detectCgroupVersion()
	if err != nil {
		return fmt.Errorf("failed to detect cgroup version: %v", err)
	}

	state.CgroupVersion = version
	fmt.Printf("Detected cgroups v%d at %s\n", version, basePath)

	if version == 2 {
		state.NetworkCgroupPath = filepath.Join(basePath, JailNetworkCgroup)
		state.CpuCgroupPath = filepath.Join(basePath, JailCpuCgroup)
		state.NetworkCpuCgroupPath = filepath.Join(basePath, JailNetworkCpuCgroup)
		return initializeCgroupV2(state)
	} else {
		state.NetworkCgroupPath = filepath.Join(basePath, "memory", JailNetworkCgroup)
		state.CpuCgroupPath = filepath.Join(basePath, "cpu", JailCpuCgroup)
		state.NetworkCpuCgroupPath = filepath.Join(basePath, "cpu", JailNetworkCpuCgroup)
		return initializeCgroupV1(state)
	}
}

// initializeCgroupV2 initializes the cgroup for cgroups v2
func initializeCgroupV2(state *JailerState) error {
	// Create the network jail cgroup directory
	if err := os.MkdirAll(state.NetworkCgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create network cgroup directory: %v", err)
	}

	// Create the CPU jail cgroup directory
	if err := os.MkdirAll(state.CpuCgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create CPU cgroup directory: %v", err)
	}

	// Create the network and CPU combined jail cgroup directory
	if err := os.MkdirAll(state.NetworkCpuCgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create network and CPU combined cgroup directory: %v", err)
	}

	// Enable necessary controllers in the parent cgroup
	controllersFile := "/sys/fs/cgroup/cgroup.subtree_control"
	controllers := "+memory +pids +cpu\n"

	if err := os.WriteFile(controllersFile, []byte(controllers), 0644); err != nil {
		// Don't fail if we can't write (may already be configured)
		fmt.Printf("Warning: could not enable controllers: %v\n", err)
	}

	// Setup CPU limit for the CPU jail (1% of one core)
	if err := setupCpuLimitV2(state); err != nil {
		return fmt.Errorf("failed to setup CPU limit: %v", err)
	}

	fmt.Printf("Cgroup v2 jails initialized - Network: %s, CPU: %s, Network+CPU: %s\n", state.NetworkCgroupPath, state.CpuCgroupPath, state.NetworkCpuCgroupPath)
	return nil
}

// setupCpuLimitV2 configures CPU limit to 1% of one core for cgroups v2
func setupCpuLimitV2(state *JailerState) error {
	// cpu.max format: "quota period" in microseconds
	// 1% of one core = 10000 microseconds quota in 100000 microseconds period
	cpuMaxFile := filepath.Join(state.CpuCgroupPath, "cpu.max")
	cpuLimit := "10000 100000\n"

	if err := os.WriteFile(cpuMaxFile, []byte(cpuLimit), 0644); err != nil {
		return fmt.Errorf("failed to set CPU limit in %s: %v", cpuMaxFile, err)
	}

	fmt.Printf("CPU limit set to 1%% of one core (10ms/100ms) in %s\n", state.CpuCgroupPath)
	return nil
}

// initializeCgroupV1 initializes the cgroup for cgroups v1
func initializeCgroupV1(state *JailerState) error {
	// Define the subsystems for which we need to create cgroups
	subsystems := []string{"memory", "pids", "net_cls", "cpu"}

	// Create the cgroup directory for each subsystem
	for _, subsys := range subsystems {
		cgroupDir := filepath.Join("/sys/fs/cgroup", subsys, JailNetworkCgroup)
		if err := os.MkdirAll(cgroupDir, 0755); err != nil {
			return fmt.Errorf("failed to create cgroup for subsystem %s: %v", subsys, err)
		}
	}

	// Create the CPU jail cgroup directory
	cpuCgroupDir := filepath.Join("/sys/fs/cgroup/cpu", JailCpuCgroup)
	if err := os.MkdirAll(cpuCgroupDir, 0755); err != nil {
		return fmt.Errorf("failed to create CPU cgroup directory: %v", err)
	}

	// Verify the CPU cgroup directory exists
	if _, err := os.Stat(cpuCgroupDir); os.IsNotExist(err) {
		return fmt.Errorf("CPU cgroup directory does not exist: %v", err)
	}

	// Create the network and CPU combined jail cgroup directory
	networkCpuCgroupDir := filepath.Join("/sys/fs/cgroup/cpu", JailNetworkCpuCgroup)
	if err := os.MkdirAll(networkCpuCgroupDir, 0755); err != nil {
		return fmt.Errorf("failed to create network and CPU combined cgroup directory: %v", err)
	}

	// Verify the network and CPU combined cgroup directory exists
	if _, err := os.Stat(networkCpuCgroupDir); os.IsNotExist(err) {
		return fmt.Errorf("network and CPU combined cgroup directory does not exist: %v", err)
	}

	// Set CPU limit for the CPU jail (1% of one core)
	if err := setupCpuLimitV1(state); err != nil {
		return fmt.Errorf("failed to setup CPU limit: %v", err)
	}

	fmt.Printf("Cgroup v1 jail initialized for subsystems: %v, CPU: %s, Network+CPU: %s\n", subsystems, cpuCgroupDir, networkCpuCgroupDir)
	return nil
}

// setupCpuLimitV1 configures CPU limit to 1% of one core for cgroups v1
func setupCpuLimitV1(state *JailerState) error {
	// Define the CPU limit using cfs_quota_us and cfs_period_us
	cpuCfsPeriodFile := filepath.Join(state.CpuCgroupPath, "cpu.cfs_period_us")
	cpuCfsQuotaFile := filepath.Join(state.CpuCgroupPath, "cpu.cfs_quota_us")

	// Verify the CPU cgroup directory exists
	if _, err := os.Stat(state.CpuCgroupPath); os.IsNotExist(err) {
		return fmt.Errorf("CPU cgroup directory does not exist: %v", err)
	}

	// Set the CPU period
	if err := os.WriteFile(cpuCfsPeriodFile, []byte(cpuPeriod), 0644); err != nil {
		return fmt.Errorf("failed to set CPU period in %s: %v", cpuCfsPeriodFile, err)
	}

	// Set the CPU quota
	if err := os.WriteFile(cpuCfsQuotaFile, []byte(cpuQuota), 0644); err != nil {
		return fmt.Errorf("failed to set CPU quota in %s: %v", cpuCfsQuotaFile, err)
	}

	// Apply CPU limits to the combined jail-network-cpu cgroup path
	combinedCpuCgroupPath := state.NetworkCpuCgroupPath
	cpuCfsPeriodFileCombined := filepath.Join(combinedCpuCgroupPath, "cpu.cfs_period_us")
	cpuCfsQuotaFileCombined := filepath.Join(combinedCpuCgroupPath, "cpu.cfs_quota_us")

	// Set the CPU period for the combined cgroup
	if err := os.WriteFile(cpuCfsPeriodFileCombined, []byte(cpuPeriod), 0644); err != nil {
		return fmt.Errorf("failed to set CPU period in %s: %v", cpuCfsPeriodFileCombined, err)
	}

	// Set the CPU quota for the combined cgroup
	if err := os.WriteFile(cpuCfsQuotaFileCombined, []byte(cpuQuota), 0644); err != nil {
		return fmt.Errorf("failed to set CPU quota in %s: %v", cpuCfsQuotaFileCombined, err)
	}

	fmt.Printf("CPU limit set to 1%% of one core (1ms/100ms) in %s\n", combinedCpuCgroupPath)
	return nil
}

// getProcessCgroup returns the current cgroup of a process
func getProcessCgroup(pid int) (string, error) {
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	content, err := os.ReadFile(cgroupFile)
	if err != nil {
		return "", fmt.Errorf("failed to read cgroup file for PID %d: %v", pid, err)
	}

	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Format for cgroups v2: 0::/path
		// Format for cgroups v1: hierarchy-ID:controller-list:/path
		parts := strings.Split(line, ":")
		if len(parts) >= 3 {
			return parts[2], nil // Return the path
		}
	}

	return "", fmt.Errorf("no cgroup found for PID %d", pid)
}

// moveProcessToCgroup moves a process to the jail cgroup
func moveProcessToCgroup(state *JailerState, pid int) error {
	if state.CgroupVersion == 2 {
		return moveProcessToCgroupV2(state, pid)
	} else {
		return moveProcessToCgroupV1(state, pid)
	}
}

// moveProcessToCgroupV2 moves a process to the jail cgroup (v2)
func moveProcessToCgroupV2(state *JailerState, pid int) error {
	procsFile := filepath.Join(state.NetworkCgroupPath, "cgroup.procs")
	pidStr := strconv.Itoa(pid) + "\n"

	if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
		return fmt.Errorf("failed to move PID %d to jail cgroup: %v", pid, err)
	}

	return nil
}

// moveProcessToCgroupV1 moves a process to the jail cgroup (v1)
func moveProcessToCgroupV1(_ *JailerState, pid int) error {
	// For network jail, we only need net_cls cgroup
	subsystems := []string{"net_cls"}
	pidStr := strconv.Itoa(pid) + "\n"

	for _, subsys := range subsystems {
		procsFile := filepath.Join("/sys/fs/cgroup", subsys, "jail", "cgroup.procs")
		fmt.Printf("[DEBUG] Attempting to move PID %d to %s cgroup: %s\n", pid, subsys, procsFile)
		if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
			fmt.Printf("[ERROR] Failed to move PID %d to jail cgroup (subsystem %s): %v\n", pid, subsys, err)
			return fmt.Errorf("failed to move PID %d to jail cgroup (subsystem %s): %v", pid, subsys, err)
		}
		fmt.Printf("[DEBUG] Successfully moved PID %d to %s cgroup\n", pid, subsys)
	}

	return nil
}

// moveProcessToCpuCgroup moves a process to the CPU jail cgroup based on the cgroup version
func moveProcessToCpuCgroup(state *JailerState, pid int) error {
	if state.CgroupVersion == 2 {
		return moveProcessToCpuCgroupV2(state, pid)
	} else {
		return moveProcessToCpuCgroupV1(state, pid)
	}
}

// moveProcessToCpuCgroupV2 moves a process to the CPU jail cgroup (v2)
func moveProcessToCpuCgroupV2(state *JailerState, pid int) error {
	procsFile := filepath.Join(state.CpuCgroupPath, "cgroup.procs")
	pidStr := strconv.Itoa(pid) + "\n"

	if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
		return fmt.Errorf("failed to move PID %d to CPU jail cgroup: %v", pid, err)
	}

	return nil
}

// moveProcessToCpuCgroupV1 moves a process to the CPU jail cgroup (v1)
func moveProcessToCpuCgroupV1(state *JailerState, pid int) error {
	// Ensure the CPU cgroup directory is created
	if err := os.MkdirAll(state.CpuCgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create CPU cgroup directory: %v", err)
	}

	// Verify the CPU cgroup directory exists
	if _, err := os.Stat(state.CpuCgroupPath); os.IsNotExist(err) {
		return fmt.Errorf("CPU cgroup directory does not exist: %v", err)
	}

	procsFile := filepath.Join(state.CpuCgroupPath, "cgroup.procs")
	pidStr := strconv.Itoa(pid) + "\n"

	if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
		return fmt.Errorf("failed to move PID %d to CPU jail cgroup: %v", pid, err)
	}

	return nil
}

// restoreProcessCgroup restores a process to its original cgroup
func restoreProcessCgroup(state *JailerState, pid int, originalCgroup string) error {
	if state.CgroupVersion == 2 {
		return restoreProcessCgroupV2(pid, originalCgroup)
	} else {
		return restoreProcessCgroupV1(pid, originalCgroup)
	}
}

// restoreProcessCgroupV2 restores a process to its original cgroup (v2)
func restoreProcessCgroupV2(pid int, originalCgroup string) error {
	procsFile := filepath.Join("/sys/fs/cgroup", strings.TrimPrefix(originalCgroup, "/"), "cgroup.procs")
	pidStr := strconv.Itoa(pid) + "\n"

	if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
		return fmt.Errorf("failed to restore PID %d to original cgroup %s: %v", pid, originalCgroup, err)
	}

	fmt.Printf("Successfully restored PID %d to original cgroup: %s\n", pid, originalCgroup)
	return nil
}

// restoreProcessCgroupV1 restores a process to its original cgroup (v1)
func restoreProcessCgroupV1(pid int, originalCgroup string) error {
	subsystems := []string{"memory", "pids", "net_cls", "cpu"}
	pidStr := strconv.Itoa(pid) + "\n"

	for _, subsys := range subsystems {
		procsFile := filepath.Join("/sys/fs/cgroup", subsys, strings.TrimPrefix(originalCgroup, "/"), "cgroup.procs")
		if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
			return fmt.Errorf("failed to restore PID %d to original cgroup %s (subsystem %s): %v", pid, originalCgroup, subsys, err)
		}
	}

	fmt.Printf("Successfully restored PID %d to original cgroup: %s\n", pid, originalCgroup)
	return nil
}

// cleanupCgroup cleans up the jail cgroup
func cleanupCgroup(state *JailerState) error {
	if state.CgroupVersion == 2 {
		return cleanupCgroupV2(state)
	} else {
		return cleanupCgroupV1(state)
	}
}

// cleanupCgroupV2 cleans up the jail cgroup (v2)
func cleanupCgroupV2(state *JailerState) error {
	cleanupEmptyCgroup(state.NetworkCgroupPath, "network jail")
	cleanupEmptyCgroup(state.CpuCgroupPath, "CPU jail")
	cleanupEmptyCgroup(state.NetworkCpuCgroupPath, "network+CPU jail")
	return nil
}

// cleanupEmptyCgroup removes a cgroup directory if it's empty
func cleanupEmptyCgroup(cgroupPath, description string) {
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	if content, err := os.ReadFile(procsFile); err == nil && len(strings.TrimSpace(string(content))) == 0 {
		// The cgroup is empty, we can remove it
		if err := os.Remove(cgroupPath); err != nil {
			fmt.Printf("Warning: failed to remove %s cgroup: %v\n", description, err)
		}
	}
}

// cleanupCgroupV1 cleans up the jail cgroup (v1)
func cleanupCgroupV1(_ *JailerState) error {
	subsystems := []string{"memory", "pids", "net_cls", "cpu"}

	for _, subsys := range subsystems {
		procsFile := filepath.Join("/sys/fs/cgroup", subsys, JailNetworkCgroup, "cgroup.procs")
		if content, err := os.ReadFile(procsFile); err == nil && len(strings.TrimSpace(string(content))) == 0 {
			// The cgroup is empty, we can remove it
			if err := os.Remove(filepath.Join("/sys/fs/cgroup", subsys, JailNetworkCgroup)); err != nil {
				fmt.Printf("Warning: failed to remove %s jail cgroup: %v\n", subsys, err)
			}
		}
	}

	// Check if there are still processes in the CPU cgroup
	cpuProcsFile := filepath.Join("/sys/fs/cgroup/cpu", JailCpuCgroup, "cgroup.procs")
	if content, err := os.ReadFile(cpuProcsFile); err == nil && len(strings.TrimSpace(string(content))) == 0 {
		// The CPU cgroup is empty, we can remove it
		if err := os.Remove(filepath.Join("/sys/fs/cgroup/cpu", JailCpuCgroup)); err != nil {
			fmt.Printf("Warning: failed to remove CPU jail cgroup: %v\n", err)
		}
	}

	// Check if there are still processes in the network+CPU cgroup
	networkCpuProcsFile := filepath.Join("/sys/fs/cgroup/cpu", JailNetworkCpuCgroup, "cgroup.procs")
	if content, err := os.ReadFile(networkCpuProcsFile); err == nil && len(strings.TrimSpace(string(content))) == 0 {
		// The network+CPU cgroup is empty, we can remove it
		if err := os.Remove(filepath.Join("/sys/fs/cgroup/cpu", JailNetworkCpuCgroup)); err != nil {
			fmt.Printf("Warning: failed to remove network+CPU jail cgroup: %v\n", err)
		}
	}

	return nil
}

// moveProcessToCombinedCgroup moves a process to a combined cgroup based on the jail types
func moveProcessToCombinedCgroup(state *JailerState, pid int, combinedJailType string) error {
	// Determine the directory path for the combined cgroup
	combinedCgroupPath := state.NetworkCpuCgroupPath

	// Ensure the combined cgroup directory is created for both cpu and net_cls
	netClsDir := filepath.Join("/sys/fs/cgroup/net_cls", JailNetworkCpuCgroup)
	if err := os.MkdirAll(netClsDir, 0755); err != nil {
		fmt.Printf("Error creating net_cls directory for combined jail: %v\n", err)
		return fmt.Errorf("failed to create net_cls directory for combined jail: %v", err)
	}

	// Move the process to the combined cgroup
	procsFile := filepath.Join(combinedCgroupPath, "cgroup.procs")
	pidStr := strconv.Itoa(pid) + "\n"
	fmt.Printf("Attempting to move PID %d to combined cgroup: %s\n", pid, combinedCgroupPath)
	if err := os.WriteFile(procsFile, []byte(pidStr), 0644); err != nil {
		fmt.Printf("Error moving PID %d to combined cgroup %s: %v\n", pid, combinedCgroupPath, err)
		return fmt.Errorf("failed to move PID %d to combined cgroup %s: %v", pid, combinedCgroupPath, err)
	}

	// Move the process to the net_cls cgroup
	netClsProcsFile := filepath.Join(netClsDir, "cgroup.procs")
	if err := os.WriteFile(netClsProcsFile, []byte(pidStr), 0644); err != nil {
		fmt.Printf("Error moving PID %d to net_cls combined cgroup %s: %v\n", pid, netClsDir, err)
		return fmt.Errorf("failed to move PID %d to net_cls combined cgroup %s: %v", pid, netClsDir, err)
	}

	fmt.Printf("Successfully moved PID %d to combined cgroup: %s\n", pid, combinedJailType)
	return nil
}
