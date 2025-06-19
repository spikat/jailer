# Jailer - Process Network/CPU Quarantine Tool

A Go tool for quarantining running processes using cgroups and network filtering rules. Supports both network isolation and CPU limiting with multiple jail types on the same process.

## Features

- ✅ **Network Quarantine** : Complete blocking of incoming and outgoing traffic
- ✅ **CPU Limiting** : Limit CPU usage to 1% of a single core
- ✅ **Multiple Jail Types** : Combine network and CPU jails on the same process
- ✅ **Descendant Management** : Automatic quarantine of child processes
- ✅ **cgroups v1/v2 Support** : Automatic detection and adaptation
- ✅ **nftables/iptables Support** : Automatic detection of available tool
- ✅ **Interactive Interface** : Intuitive prompt with simple commands
- ✅ **Selective Removal** : Remove specific jail types without affecting others
- ✅ **Automatic Cleanup** : Clean restoration on exit

## Prerequisites

- **Linux** with cgroups support (v1 or v2)
- **Root privileges** required
- **nftables** or **iptables** installed and functional

## Installation

```bash
# Clone the project
git clone <repo-url>
cd jailer

# Compile
go build -o jailer

# Install (optional)
sudo cp jailer /usr/local/bin/
```

## Usage

### Starting

```bash
sudo ./jailer
```

The tool automatically detects:
- The cgroups version (v1 or v2)
- The available firewall tool (nftables or iptables)
- Configures network filtering rules and CPU limits

### Available Commands

```
$> help                    # Show help
$> jail network <pid>      # Put process in network quarantine
$> jail n <pid>            # Short form for network quarantine
$> jail cpu <pid>          # Put process in CPU jail (1% limit)
$> jail c <pid>            # Short form for CPU jail
$> jail both <pid>         # Apply both network and CPU jails
$> unjail <pid>            # Remove all jails from process
$> unjail <type> <pid>     # Remove specific jail type from process
$> list                    # List active jails
$> exit                    # Clean up everything and quit
```

### Examples

```bash
# Start jailer
sudo ./jailer

# Put process 1234 in network quarantine only
$> jail network 1234

# Add CPU limiting to the same process
$> jail cpu 1234

# Or apply both jails at once
$> jail both 5678

# List active jails
$> list
Active jails:
PID      Name         Type            Children   Since               
-----------------------------------------------------------------------
1234     myprocess    network,cpu     2          15s                 
5678     otherproc    network,cpu     0          5s                  

# Remove only the CPU jail, keep network jail
$> unjail cpu 1234

# Remove all jails from a process
$> unjail 5678

# Exit cleanly
$> exit
```

## Technical Architecture

### Cgroups

#### Network Jails
- **v1** : Uses `net_cls` subsystem only (optimized)
- **v2** : Uses unified hierarchy with network controller
- **Network jail cgroup** : `/sys/fs/cgroup/net_cls/jail` (v1) or `/sys/fs/cgroup/jail-network` (v2)

#### CPU Jails
- **v1** : Uses `cpu` subsystem with `cpu.cfs_quota_us=1000` and `cpu.cfs_period_us=100000` (1% of one core)
- **v2** : Uses unified hierarchy with `cpu.max="10000 100000"` (1% of one core)
- **CPU jail cgroup** : `/sys/fs/cgroup/cpu/jail-cpu` (v1) or `/sys/fs/cgroup/jail-cpu` (v2)

#### Combined Jails
- **v1** : Uses separate cgroups for CPU and network with combined management
- **v2** : Uses unified hierarchy with multiple controllers
- **Combined cgroup** : `/sys/fs/cgroup/cpu/jail-network-cpu` + `/sys/fs/cgroup/net_cls/jail-network-cpu` (v1)

### Network Filtering

#### nftables (recommended)
```bash
# Dedicated table: inet jail
# Chains: input and output with priority 100
# v2 rules: socket cgroupv2 level 1 "jail" drop
# v1 rules: meta cgroup 0x00100001 drop
```

#### iptables (fallback)
```bash
# v2 rules: -m cgroup --path jail -j DROP
# v1 rules: -m cgroup --cgroup 0x00100001 -j DROP
```

### Process Management

- **Child Detection** : Recursive analysis via `/proc/*/stat`
- **Descendant Management** : Automatic movement of all child processes
- **Monitoring** : Detection and cleanup of terminated processes
- **Restoration** : Return to original cgroup on unjail
- **Selective Management** : Remove specific jail types without affecting others

## Complete Usage Example

```bash
# Terminal 1: Start a process to test
$ stress-ng --cpu 1 --timeout 300s &
[1] 12345

# Terminal 2: Launch jailer
$ sudo ./jailer
Detected cgroups v1 at /sys/fs/cgroup
CPU limit set to 1% of one core (1ms/100ms) in /sys/fs/cgroup/cpu/jail-network-cpu
Cgroup v1 jail initialized for subsystems: [memory pids net_cls cpu], CPU: /sys/fs/cgroup/cpu/jail-cpu, Network+CPU: /sys/fs/cgroup/cpu/jail-network-cpu
Detected iptables as primary firewall tool
Setting up network filtering rules...
Iptables jail rules configured successfully
Jailer Tool v1.0
Type 'help' for available commands or 'exit' to quit

# Apply CPU limiting (will reduce CPU usage to 1%)
$> jail cpu 12345
Jailing process 12345 (stress-ng-cpu) and 0 descendants with cpu jail...
Successfully jailed process 12345 (stress-ng-cpu) with 0 descendants

# Add network quarantine to the same process
$> jail network 12345
Added network jail to already jailed process 12345 (stress-ng-cpu)
Successfully moved PID 12345 to combined cgroup: cpu,network

$> list
Active jails:
PID      Name         Type            Children   Since               
-----------------------------------------------------------------------
12345    stress-ng-cpu cpu,network    0          10s                 

# Remove only the network jail, keep CPU limiting
$> unjail network 12345
Removed network jail from process 12345 (stress-ng-cpu), remaining jails: cpu
Moving process 12345 to single cpu jail cgroup

# Completely unjail the process
$> unjail 12345
Unjailing process 12345 (stress-ng-cpu) and its descendants...
  Restored main process 12345
Successfully unjailed process 12345 with 0 descendants restored

$> exit
Cleaning up 0 active jails...
Cleaning up network filtering rules...
Iptables jail rules cleaned up
Cleanup completed
```

## Jail Types

### Network Jail (`network` / `n`)
- **Purpose** : Block all network traffic (incoming and outgoing)
- **Implementation** : Uses `net_cls` cgroup + iptables/nftables rules
- **Effect** : Process cannot access network resources
- **Use case** : Isolate potentially malicious processes

### CPU Jail (`cpu` / `c`)
- **Purpose** : Limit CPU usage to 1% of a single core
- **Implementation** : Uses `cpu` cgroup with quota/period limits
- **Effect** : Process CPU usage is heavily throttled
- **Use case** : Prevent CPU-intensive processes from consuming resources

### Combined Jail (`both`)
- **Purpose** : Apply both network and CPU restrictions
- **Implementation** : Uses both cgroup types simultaneously
- **Effect** : Process is both network-isolated and CPU-limited
- **Use case** : Maximum containment of problematic processes

## Tests

```bash
# Unit tests (basic functionality)
go test -v

# Tests with root (for cgroups and firewall)
sudo go test -v

# Benchmarks
go test -bench=.
```

## Error Handling

- **Non-existent process** : Validation before jail/unjail
- **Insufficient permissions** : Root privilege verification
- **Terminated process** : Automatic cleanup in `list`
- **Unavailable cgroups** : Detection and explicit error
- **Unavailable firewall** : Detection and explicit error
- **Failed restoration** : Warnings but not fatal failure
- **Multiple jail conflicts** : Intelligent transition between jail types

## Limitations

- **Linux only** : Uses Linux cgroups and procfs
- **Root required** : Modification of cgroups and network rules
- **No persistence** : State lost on restart
- **Fixed CPU limit** : Currently hardcoded to 1% (configurable in future versions)

## File Architecture

```
.
├── main.go           # Entry point and main logic
├── cgroups.go        # cgroups v1/v2 management
├── firewall.go       # nftables/iptables management
├── process.go        # Process and relationship management
├── main_test.go      # Unit tests
└── README.md        # This documentation
```
