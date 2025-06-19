package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/chzyer/readline"
)

// Jail represents an active quarantine
type Jail struct {
	PID            int
	OriginalCgroup string
	JailTypes      []string // "network", "cpu", etc.
	Timestamp      time.Time
	Children       []int
}

// HasJailType checks if the jail has a specific type
func (j *Jail) HasJailType(jailType string) bool {
	for _, t := range j.JailTypes {
		if t == jailType {
			return true
		}
	}
	return false
}

// AddJailType adds a jail type if not already present
func (j *Jail) AddJailType(jailType string) {
	if !j.HasJailType(jailType) {
		j.JailTypes = append(j.JailTypes, jailType)
	}
}

// RemoveJailType removes a jail type if present
func (j *Jail) RemoveJailType(jailType string) {
	for i, t := range j.JailTypes {
		if t == jailType {
			j.JailTypes = append(j.JailTypes[:i], j.JailTypes[i+1:]...)
			break
		}
	}
}

// GetJailTypesString returns a comma-separated string of jail types
func (j *Jail) GetJailTypesString() string {
	if len(j.JailTypes) == 0 {
		return "none"
	}
	return strings.Join(j.JailTypes, ",")
}

// JailerState contains the global application state
type JailerState struct {
	ActiveJails          map[int]*Jail
	NetworkCgroupPath    string // Network jail cgroup path
	CpuCgroupPath        string // CPU jail cgroup path
	NetworkCpuCgroupPath string // Network and CPU combined jail cgroup path
	CgroupVersion        int    // 1 or 2
	FirewallTool         string // "nftables" or "iptables"
}

// NewJailerState creates a new instance of the jailer state
func NewJailerState() *JailerState {
	return &JailerState{
		ActiveJails: make(map[int]*Jail),
	}
}

// createReadlineConfig creates the readline configuration with autocompletion
func createReadlineConfig() *readline.Config {
	return &readline.Config{
		Prompt:      "$> ",
		HistoryFile: "/tmp/jailer_history",
		AutoComplete: readline.NewPrefixCompleter(
			readline.PcItem("help"),
			readline.PcItem("jail",
				readline.PcItem("network"),
				readline.PcItem("n"),
				readline.PcItem("cpu"),
				readline.PcItem("c"),
				readline.PcItem("both"),
			),
			readline.PcItem("unjail",
				readline.PcItem("network"),
				readline.PcItem("n"),
				readline.PcItem("cpu"),
				readline.PcItem("c"),
			),
			readline.PcItem("list"),
			readline.PcItem("exit"),
			readline.PcItem("quit"),
		),
		InterruptPrompt: "^C",
		EOFPrompt:       "exit",
	}
}

func main() {
	// Check root privileges
	if os.Geteuid() != 0 {
		fmt.Println("Error: This tool requires root privileges")
		fmt.Println("Please run with sudo or as root user")
		os.Exit(1)
	}

	// Initialize jailer state
	state := NewJailerState()

	// Initialize cgroups
	if err := initializeCgroup(state); err != nil {
		fmt.Printf("Error initializing cgroups: %v\n", err)
		os.Exit(1)
	}

	// Detect available firewall tool
	firewallTool, err := detectFirewallTool()
	if err != nil {
		fmt.Printf("Error detecting firewall tool: %v\n", err)
		os.Exit(1)
	}
	state.FirewallTool = firewallTool

	// Initialize network filtering on startup
	fmt.Println("Setting up network filtering rules...")
	if err := setupNetworkJail(state); err != nil {
		fmt.Printf("Error setting up network jail: %v\n", err)
		os.Exit(1)
	}

	// Configure signal handling for clean shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigChan
		fmt.Println("\nReceived interrupt signal, cleaning up...")
		cleanup(state)
		os.Exit(0)
	}()

	fmt.Println("Jailer Tool v1.0")
	fmt.Println("Type 'help' for available commands or 'exit' to quit")
	fmt.Println("Use Tab for autocompletion, Up/Down arrows for history")
	fmt.Println()

	// Create readline instance with configuration
	rl, err := readline.NewEx(createReadlineConfig())
	if err != nil {
		fmt.Printf("Error creating readline interface: %v\n", err)
		cleanup(state)
		os.Exit(1)
	}
	defer rl.Close()

	// Handle SIGINT for readline
	rl.CaptureExitSignal()

	// Main prompt loop
	for {
		line, err := rl.Readline()
		if err != nil {
			if err == readline.ErrInterrupt {
				if len(line) == 0 {
					fmt.Println("Use 'exit' to quit or Ctrl+D")
					continue
				} else {
					continue
				}
			} else if err == io.EOF {
				fmt.Println("\nGoodbye!")
				break
			}
			fmt.Printf("Error reading input: %v\n", err)
			continue
		}

		input := strings.TrimSpace(line)
		if input == "" {
			continue
		}

		// Parse and execute command
		if err := executeCommand(state, input); err != nil {
			fmt.Printf("Error: %v\n", err)
		}
	}

	// Cleanup before exit
	cleanup(state)
}

// normalizeJailType converts short forms to full jail type names
func normalizeJailType(jailType string) string {
	switch jailType {
	case "n":
		return "network"
	case "c":
		return "cpu"
	default:
		return jailType
	}
}

// executeCommand parses and executes a user command
func executeCommand(state *JailerState, input string) error {
	parts := strings.Fields(input)
	if len(parts) == 0 {
		return nil
	}

	command := strings.ToLower(parts[0])

	switch command {
	case "help":
		showHelp()
	case "exit", "quit":
		fmt.Println("Cleaning up and exiting...")
		cleanup(state)
		os.Exit(0)
	case "list":
		listJails(state)
	case "jail":
		if len(parts) < 3 {
			return fmt.Errorf("usage: jail <type> <pid>")
		}
		jailType := normalizeJailType(strings.ToLower(parts[1]))
		if jailType == "both" {
			// Apply both network and CPU jails
			pid := parts[2]
			if err := jailProcess(state, "network", pid); err != nil {
				return fmt.Errorf("failed to apply network jail: %v", err)
			}
			if err := jailProcess(state, "cpu", pid); err != nil {
				return fmt.Errorf("failed to apply CPU jail: %v", err)
			}
			return nil
		}
		return jailProcess(state, jailType, parts[2])
	case "unjail":
		if len(parts) < 2 {
			return fmt.Errorf("usage: unjail <pid> or unjail <type> <pid>")
		}
		if len(parts) == 2 {
			// unjail <pid> - remove all jails
			return unjailProcess(state, parts[1])
		} else if len(parts) == 3 {
			// unjail <type> <pid> - remove specific jail type
			jailType := normalizeJailType(strings.ToLower(parts[1]))
			return unjailProcessSelective(state, jailType, parts[2])
		} else {
			return fmt.Errorf("usage: unjail <pid> or unjail <type> <pid>")
		}
	default:
		return fmt.Errorf("unknown command: %s (type 'help' for available commands)", command)
	}

	return nil
}

// showHelp displays help for available commands
func showHelp() {
	fmt.Println("Available commands:")
	fmt.Println("  jail network <pid>  - Put process in network jail")
	fmt.Println("  jail n <pid>        - Short form for network jail")
	fmt.Println("  jail cpu <pid>      - Put process in CPU jail (1% limit)")
	fmt.Println("  jail c <pid>        - Short form for CPU jail")
	fmt.Println("  jail both <pid>     - Put process in both network and CPU jail")
	fmt.Println("  unjail <pid>        - Remove all jails from process")
	fmt.Println("  unjail <type> <pid> - Remove specific jail type from process")
	fmt.Println("  list                - List active jails")
	fmt.Println("  help                - Show this help")
	fmt.Println("  exit                - Clean up and exit")
	fmt.Println()
	fmt.Println("Jail types:")
	fmt.Println("  network/n           - Block network access")
	fmt.Println("  cpu/c               - Limit CPU usage to 1% of one core")
	fmt.Println("  both                - Apply both network and CPU jails")
	fmt.Println()
	fmt.Println("Enhanced features:")
	fmt.Println("  Tab                 - Autocomplete commands")
	fmt.Println("  Up/Down arrows      - Navigate command history")
	fmt.Println("  Ctrl+A/Home         - Move cursor to beginning of line")
	fmt.Println("  Ctrl+E/End          - Move cursor to end of line")
	fmt.Println("  Ctrl+L              - Clear screen")
	fmt.Println("  Ctrl+C              - Interrupt current input")
}

// listJails displays the list of active quarantines
func listJails(state *JailerState) {
	// Clean up dead processes before displaying
	cleanupDeadProcesses(state)

	if len(state.ActiveJails) == 0 {
		fmt.Println("No active jails")
		return
	}

	fmt.Println("Active jails:")
	fmt.Printf("%-8s %-12s %-15s %-10s %-20s\n", "PID", "Name", "Type", "Children", "Since")
	fmt.Println(strings.Repeat("-", 75))

	for pid, jail := range state.ActiveJails {
		duration := time.Since(jail.Timestamp).Round(time.Second)
		childrenCount := len(jail.Children)
		processName := getProcessName(pid)
		fmt.Printf("%-8d %-12s %-15s %-10d %-20s\n",
			pid, processName, jail.GetJailTypesString(), childrenCount, duration.String())
	}
}

// jailProcess puts a process in quarantine
func jailProcess(state *JailerState, jailType, pidStr string) error {
	// Parse the PID
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid PID: %s", pidStr)
	}

	// Check that the jail type is supported
	if jailType != "network" && jailType != "cpu" {
		return fmt.Errorf("unsupported jail type: %s (only 'network' and 'cpu' are supported)", jailType)
	}

	// Check if the process is already jailed with this specific type
	if jail, exists := state.ActiveJails[pid]; exists {
		if jail.HasJailType(jailType) {
			return fmt.Errorf("process %d is already jailed with %s jail", pid, jailType)
		}
		// Process exists but doesn't have this jail type, we'll add it
		jail.AddJailType(jailType)
		processName := getProcessName(pid)
		fmt.Printf("Added %s jail to already jailed process %d (%s)\n", jailType, pid, processName)

		// Move to combined jail if necessary
		combinedJailType := jail.GetJailTypesString()
		if err := moveProcessToCombinedCgroup(state, pid, combinedJailType); err != nil {
			return fmt.Errorf("failed to move process to combined jail: %v", err)
		}
		return nil
	}

	// Validate process access
	if err := validateProcessAccess(pid); err != nil {
		return err
	}

	// Get the original cgroup of the process
	originalCgroup, err := getProcessCgroup(pid)
	if err != nil {
		return fmt.Errorf("failed to get original cgroup for PID %d: %v", pid, err)
	}

	// Find all descendants
	descendants, err := getAllDescendants(pid)
	if err != nil {
		return fmt.Errorf("failed to get descendants for PID %d: %v", pid, err)
	}

	processName := getProcessName(pid)
	fmt.Printf("Jailing process %d (%s) and %d descendants with %s jail...\n",
		pid, processName, len(descendants), jailType)

	// Move the main process to the appropriate jail cgroup
	if jailType == "cpu" {
		if err := moveProcessToCpuCgroup(state, pid); err != nil {
			return fmt.Errorf("failed to move main process to CPU jail: %v", err)
		}
	} else {
		if err := moveProcessToCgroup(state, pid); err != nil {
			return fmt.Errorf("failed to move main process to jail: %v", err)
		}
	}

	// Move all descendants
	var successfulDescendants []int
	for _, descendantPid := range descendants {
		if jailType == "cpu" {
			if err := moveProcessToCpuCgroup(state, descendantPid); err != nil {
				fmt.Printf("Warning: failed to move descendant %d to CPU jail: %v\n", descendantPid, err)
				continue
			}
		} else {
			if err := moveProcessToCgroup(state, descendantPid); err != nil {
				fmt.Printf("Warning: failed to move descendant %d to jail: %v\n", descendantPid, err)
				continue
			}
		}
		successfulDescendants = append(successfulDescendants, descendantPid)
	}

	// Create jail entry
	jail := &Jail{
		PID:            pid,
		OriginalCgroup: originalCgroup,
		JailTypes:      []string{jailType},
		Timestamp:      time.Now(),
		Children:       successfulDescendants,
	}

	state.ActiveJails[pid] = jail

	fmt.Printf("Successfully jailed process %d (%s) with %d descendants\n",
		pid, processName, len(successfulDescendants))

	return nil
}

// unjailProcessSelective removes a specific jail type from a process
func unjailProcessSelective(state *JailerState, jailType, pidStr string) error {
	// Parse the PID
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid PID: %s", pidStr)
	}

	// Check if the process is in jail
	jail, exists := state.ActiveJails[pid]
	if !exists {
		return fmt.Errorf("process %d is not jailed", pid)
	}

	// Check if the process has this specific jail type
	if !jail.HasJailType(jailType) {
		return fmt.Errorf("process %d is not jailed with %s jail", pid, jailType)
	}

	processName := getProcessName(pid)

	// If this is the only jail type, remove the entire jail
	if len(jail.JailTypes) == 1 {
		fmt.Printf("Removing last jail type (%s) from process %d (%s), completely unjailing...\n", jailType, pid, processName)
		return unjailProcess(state, pidStr)
	}

	// Remove the specific jail type
	jail.RemoveJailType(jailType)
	fmt.Printf("Removed %s jail from process %d (%s), remaining jails: %s\n",
		jailType, pid, processName, jail.GetJailTypesString())

	// Move the process to the appropriate cgroup based on remaining jail types
	remainingJailTypes := jail.GetJailTypesString()

	// If only one jail type remains, move to single jail cgroup
	if len(jail.JailTypes) == 1 {
		remainingType := jail.JailTypes[0]
		fmt.Printf("Moving process %d to single %s jail cgroup\n", pid, remainingType)

		// Move main process and descendants to the single jail type
		if remainingType == "cpu" {
			if err := moveProcessToCpuCgroup(state, pid); err != nil {
				fmt.Printf("Warning: failed to move process %d to CPU jail: %v\n", pid, err)
			}
			for _, childPid := range jail.Children {
				if processExists(childPid) {
					if err := moveProcessToCpuCgroup(state, childPid); err != nil {
						fmt.Printf("Warning: failed to move child %d to CPU jail: %v\n", childPid, err)
					}
				}
			}
		} else if remainingType == "network" {
			if err := moveProcessToCgroup(state, pid); err != nil {
				fmt.Printf("Warning: failed to move process %d to network jail: %v\n", pid, err)
			}
			for _, childPid := range jail.Children {
				if processExists(childPid) {
					if err := moveProcessToCgroup(state, childPid); err != nil {
						fmt.Printf("Warning: failed to move child %d to network jail: %v\n", childPid, err)
					}
				}
			}
		}
	} else {
		// Multiple jail types remain, move to combined cgroup
		fmt.Printf("Moving process %d to combined jail cgroup for: %s\n", pid, remainingJailTypes)
		if err := moveProcessToCombinedCgroup(state, pid, remainingJailTypes); err != nil {
			fmt.Printf("Warning: failed to move process %d to combined jail: %v\n", pid, err)
		}
		for _, childPid := range jail.Children {
			if processExists(childPid) {
				if err := moveProcessToCombinedCgroup(state, childPid, remainingJailTypes); err != nil {
					fmt.Printf("Warning: failed to move child %d to combined jail: %v\n", childPid, err)
				}
			}
		}
	}

	return nil
}

// unjailProcess removes a process from quarantine
func unjailProcess(state *JailerState, pidStr string) error {
	// Parse the PID
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return fmt.Errorf("invalid PID: %s", pidStr)
	}

	// Check if the process is in jail
	jail, exists := state.ActiveJails[pid]
	if !exists {
		return fmt.Errorf("process %d is not jailed", pid)
	}

	processName := getProcessName(pid)
	fmt.Printf("Unjailing process %d (%s) and its descendants...\n", pid, processName)

	// Restore the main process
	if processExists(pid) {
		if err := restoreProcessCgroup(state, pid, jail.OriginalCgroup); err != nil {
			fmt.Printf("Warning: failed to restore main process %d: %v\n", pid, err)
		} else {
			fmt.Printf("  Restored main process %d\n", pid)
		}
	} else {
		fmt.Printf("  Main process %d no longer exists\n", pid)
	}

	// Restore all descendants
	restoredCount := 0
	for _, childPid := range jail.Children {
		if !processExists(childPid) {
			fmt.Printf("  Child process %d no longer exists\n", childPid)
			continue
		}

		if err := restoreProcessCgroup(state, childPid, jail.OriginalCgroup); err != nil {
			fmt.Printf("Warning: failed to restore child process %d: %v\n", childPid, err)
			continue
		}
		restoredCount++
	}

	// Remove from active jails list
	delete(state.ActiveJails, pid)

	fmt.Printf("Successfully unjailed process %d with %d descendants restored\n",
		pid, restoredCount)

	return nil
}

// cleanup cleans up all quarantines before exit
func cleanup(state *JailerState) {
	if len(state.ActiveJails) == 0 {
		return
	}

	fmt.Printf("Cleaning up %d active jails...\n", len(state.ActiveJails))

	// Clean up all jailed processes
	for pid := range state.ActiveJails {
		pidStr := strconv.Itoa(pid)
		if err := unjailProcess(state, pidStr); err != nil {
			fmt.Printf("  Warning: failed to unjail PID %d: %v\n", pid, err)
		}
	}

	// Clean up network filtering
	fmt.Println("Cleaning up network filtering rules...")
	if err := cleanupNetworkJail(state); err != nil {
		fmt.Printf("Warning: failed to cleanup network jail: %v\n", err)
	}

	// Clean up cgroups
	if err := cleanupCgroup(state); err != nil {
		fmt.Printf("Warning: failed to cleanup cgroups: %v\n", err)
	}

	fmt.Println("Cleanup completed")
}
