package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const (
	netClsClassID = "0x00100001"
	classIDPath   = "/sys/fs/cgroup/net_cls/jail/net_cls.classid"
)

// detectFirewallTool detects which firewall tool is available and used on the system
func detectFirewallTool() (string, error) {
	// Check nftables first (more modern)
	if isNftablesAvailable() {
		fmt.Println("Detected nftables as primary firewall tool")
		return "nftables", nil
	}

	// Check iptables
	if isIptablesAvailable() {
		fmt.Println("Detected iptables as primary firewall tool")
		return "iptables", nil
	}

	return "", fmt.Errorf("neither nftables nor iptables found on system")
}

// isNftablesAvailable checks if nftables is available and usable
func isNftablesAvailable() bool {
	// Check if nft command exists
	if !commandExists("nft") {
		return false
	}

	// Check if we can list tables (tests permissions and availability)
	cmd := exec.Command("nft", "list", "tables")
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

// isIptablesAvailable checks if iptables is available and usable
func isIptablesAvailable() bool {
	// Check if iptables command exists
	if !commandExists("iptables") {
		return false
	}

	// Check if we can list rules (tests permissions and availability)
	cmd := exec.Command("iptables", "-L", "-n")
	if err := cmd.Run(); err != nil {
		return false
	}

	return true
}

// commandExists checks if a command exists in PATH
func commandExists(cmd string) bool {
	_, err := exec.LookPath(cmd)
	return err == nil
}

// setupNetworkJail configures firewall rules to block traffic from the jail cgroup
func setupNetworkJail(state *JailerState) error {
	if state.FirewallTool == "nftables" {
		return setupNftablesJail(state)
	} else if state.FirewallTool == "iptables" {
		return setupIptablesJail(state)
	}
	return fmt.Errorf("unsupported firewall tool: %s", state.FirewallTool)
}

// setupNftablesJail configures nftables rules for the jail
func setupNftablesJail(state *JailerState) error {
	// Create a dedicated table for the jail
	commands := [][]string{
		// Create the jail table
		{"nft", "add", "table", "inet", "jail"},

		// Create a chain to filter outgoing traffic
		{"nft", "add", "chain", "inet", "jail", "output", "{", "type", "filter", "hook", "output", "priority", "100", ";", "}"},

		// Create a chain to filter incoming traffic
		{"nft", "add", "chain", "inet", "jail", "input", "{", "type", "filter", "hook", "input", "priority", "100", ";", "}"},
	}

	// Add rules to block traffic from the jail cgroup
	if state.CgroupVersion == 2 {
		// For cgroups v2, use socket cgroupv2
		commands = append(commands, []string{
			"nft", "add", "rule", "inet", "jail", "output",
			"socket", "cgroupv2", "level", "1", "\"jail\"", "drop",
		})
		commands = append(commands, []string{
			"nft", "add", "rule", "inet", "jail", "input",
			"socket", "cgroupv2", "level", "1", "\"jail\"", "drop",
		})
	} else {
		// For cgroups v1, use net_cls classid
		// First define a classid for the jail cgroup
		if err := writeFile(classIDPath, netClsClassID+"\n"); err != nil {
			return fmt.Errorf("failed to set net_cls classid: %v", err)
		}

		commands = append(commands, []string{
			"nft", "add", "rule", "inet", "jail", "output",
			"meta", "cgroup", netClsClassID, "drop",
		})
		commands = append(commands, []string{
			"nft", "add", "rule", "inet", "jail", "input",
			"meta", "cgroup", netClsClassID, "drop",
		})
	}

	// Execute all commands
	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("failed to execute nftables command %v: %v\nOutput: %s",
				cmdArgs, err, string(output))
		}
	}

	fmt.Println("Nftables jail rules configured successfully")
	return nil
}

// setupIptablesJail configures iptables rules for the jail
func setupIptablesJail(state *JailerState) error {
	var commands [][]string

	if state.CgroupVersion == 2 {
		// For cgroups v2, use cgroup match
		commands = [][]string{
			// Block outgoing traffic from jail cgroup
			{"iptables", "-A", "OUTPUT", "-m", "cgroup", "--path", "jail", "-j", "DROP"},

			// Block incoming traffic to jail cgroup
			{"iptables", "-A", "INPUT", "-m", "cgroup", "--path", "jail", "-j", "DROP"},
		}
	} else {
		// For cgroups v1, use net_cls classid
		// First define a classid for the jail cgroup
		if err := writeFile(classIDPath, netClsClassID+"\n"); err != nil {
			return fmt.Errorf("failed to set net_cls classid: %v", err)
		}

		commands = [][]string{
			// Block outgoing traffic with classid
			{"iptables", "-A", "OUTPUT", "-m", "cgroup", "--cgroup", netClsClassID, "-j", "DROP"},

			// Block incoming traffic with classid
			{"iptables", "-A", "INPUT", "-m", "cgroup", "--cgroup", netClsClassID, "-j", "DROP"},
		}
	}

	// Add logging to capture details about the iptables rules and any errors
	fmt.Println("Setting up iptables rules for the jail...")

	// Execute all commands
	for _, cmdArgs := range commands {
		fmt.Printf("Executing iptables command: %v\n", cmdArgs)
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			fmt.Printf("Error executing iptables command %v: %v\nOutput: %s\n", cmdArgs, err, string(output))
			return fmt.Errorf("failed to execute iptables command %v: %v\nOutput: %s", cmdArgs, err, string(output))
		}
	}

	fmt.Println("Iptables jail rules configured successfully")
	return nil
}

// cleanupNetworkJail removes firewall rules from the jail
func cleanupNetworkJail(state *JailerState) error {
	if state.FirewallTool == "nftables" {
		return cleanupNftablesJail()
	} else if state.FirewallTool == "iptables" {
		return cleanupIptablesJail(state)
	}
	return fmt.Errorf("unsupported firewall tool: %s", state.FirewallTool)
}

// cleanupNftablesJail removes nftables rules from the jail
func cleanupNftablesJail() error {
	// Remove the entire jail table
	cmd := exec.Command("nft", "delete", "table", "inet", "jail")
	if output, err := cmd.CombinedOutput(); err != nil {
		// Don't fail if the table doesn't exist
		if !strings.Contains(string(output), "No such file or directory") {
			return fmt.Errorf("failed to cleanup nftables jail: %v\nOutput: %s", err, string(output))
		}
	}

	fmt.Println("Nftables jail rules cleaned up")
	return nil
}

// cleanupIptablesJail removes iptables rules from the jail
func cleanupIptablesJail(state *JailerState) error {
	var commands [][]string

	if state.CgroupVersion == 2 {
		commands = [][]string{
			{"iptables", "-D", "OUTPUT", "-m", "cgroup", "--path", "jail", "-j", "DROP"},
			{"iptables", "-D", "INPUT", "-m", "cgroup", "--path", "jail", "-j", "DROP"},
		}
	} else {
		commands = [][]string{
			{"iptables", "-D", "OUTPUT", "-m", "cgroup", "--cgroup", netClsClassID, "-j", "DROP"},
			{"iptables", "-D", "INPUT", "-m", "cgroup", "--cgroup", netClsClassID, "-j", "DROP"},
		}
	}

	// Execute removal commands
	for _, cmdArgs := range commands {
		cmd := exec.Command(cmdArgs[0], cmdArgs[1:]...)
		if output, err := cmd.CombinedOutput(); err != nil {
			// Don't fail if the rule doesn't exist
			if !strings.Contains(string(output), "No chain/target/match by that name") {
				fmt.Printf("Warning: failed to remove iptables rule %v: %v\n", cmdArgs, err)
			}
		}
	}

	fmt.Println("Iptables jail rules cleaned up")
	return nil
}

// writeFile writes content to a file (helper function)
func writeFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}
