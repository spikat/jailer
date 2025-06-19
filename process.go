package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// getProcessChildren returns all direct child processes of a process
func getProcessChildren(pid int) ([]int, error) {
	var children []int

	// Browse all processes in /proc
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("failed to read /proc directory: %v", err)
	}

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		// Check if it's a PID (numeric name)
		childPid, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue // Not a PID
		}

		// Read the PPID (parent PID) of this process
		statFile := filepath.Join("/proc", entry.Name(), "stat")
		content, err := os.ReadFile(statFile)
		if err != nil {
			continue // Process may have disappeared
		}

		// stat file format: pid (comm) state ppid ...
		fields := strings.Fields(string(content))
		if len(fields) < 4 {
			continue
		}

		ppid, err := strconv.Atoi(fields[3])
		if err != nil {
			continue
		}

		// If the PPID matches our PID, it's a child
		if ppid == pid {
			children = append(children, childPid)
		}
	}

	return children, nil
}

// getAllDescendants returns all descendants (children, grandchildren, etc.) of a process
func getAllDescendants(pid int) ([]int, error) {
	var descendants []int
	visited := make(map[int]bool)

	// Recursive function to find all descendants
	var findDescendants func(int) error
	findDescendants = func(parentPid int) error {
		if visited[parentPid] {
			return nil // Avoid infinite loops
		}
		visited[parentPid] = true

		children, err := getProcessChildren(parentPid)
		if err != nil {
			return err
		}

		for _, childPid := range children {
			descendants = append(descendants, childPid)
			// Recursively find descendants of this child
			if err := findDescendants(childPid); err != nil {
				// Continue even if we can't access certain processes
				continue
			}
		}

		return nil
	}

	if err := findDescendants(pid); err != nil {
		return nil, err
	}

	return descendants, nil
}

// processExists checks if a process still exists
func processExists(pid int) bool {
	_, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil
}

// getProcessName returns the name of a process
func getProcessName(pid int) string {
	commFile := fmt.Sprintf("/proc/%d/comm", pid)
	content, err := os.ReadFile(commFile)
	if err != nil {
		return fmt.Sprintf("PID-%d", pid)
	}
	return strings.TrimSpace(string(content))
}

// validateProcessAccess checks that we can access the process and its information
func validateProcessAccess(pid int) error {
	// Check that the process exists
	if !processExists(pid) {
		return fmt.Errorf("process %d does not exist", pid)
	}

	// Check that we can read its cgroup information
	cgroupFile := fmt.Sprintf("/proc/%d/cgroup", pid)
	if _, err := os.Stat(cgroupFile); err != nil {
		return fmt.Errorf("cannot access cgroup info for process %d: %v", pid, err)
	}

	return nil
}

// cleanupDeadProcesses cleans up dead processes from the active jails list
func cleanupDeadProcesses(state *JailerState) {
	var deadProcesses []int

	for pid, jail := range state.ActiveJails {
		if !processExists(pid) {
			fmt.Printf("Process %d no longer exists, removing from jail list (had jails: %s)\n",
				pid, jail.GetJailTypesString())
			deadProcesses = append(deadProcesses, pid)
			continue
		}

		// Also clean up the children list
		aliveChildren := jail.Children[:0] // Reuse slice capacity
		deadChildren := 0
		for _, childPid := range jail.Children {
			if processExists(childPid) {
				aliveChildren = append(aliveChildren, childPid)
			} else {
				deadChildren++
			}
		}

		// Update children list and log if any children died
		if deadChildren > 0 {
			fmt.Printf("Process %d (%s): %d child processes died, %d still alive\n",
				pid, jail.GetJailTypesString(), deadChildren, len(aliveChildren))
			jail.Children = aliveChildren
		}
	}

	// Remove all dead processes from the active jails map
	for _, pid := range deadProcesses {
		delete(state.ActiveJails, pid)
	}

	if len(deadProcesses) > 0 {
		fmt.Printf("Cleaned up %d dead processes from jail list\n", len(deadProcesses))
	}
}
