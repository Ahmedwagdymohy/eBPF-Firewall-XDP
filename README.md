# eBPF-Firewall-XDP

## Abstract

Linux kernel programming and network security through eBPF-based firewall implementation using XDP (eXpress Data Path). The system operates at the kernel level to provide real-time packet filtering and monitoring capabilities, showcasing deep expertise in eBPF technology, network packet processing, and systems programming.

The firewall intercepts network packets before they reach the network stack, enabling ultra-low latency packet filtering decisions. It combines C-based eBPF programs for kernel-space execution with Python-based userspace monitoring, demonstrating proficiency in both system-level programming and modern network security approaches.

## Key Features

- **Kernel-Level Packet Filtering**: Intercepts packets using XDP before network stack processing
- **Real-Time Monitoring**: Live packet counting and statistics with sub-microsecond latency  
- **Configurable IP Blocking**: Blocks packets from specified source IP addresses
- **Debug Logging**: Perf event-based debugging for blocked packets
- **Graceful Shutdown**: Signal handling for clean program termination
- **Performance Metrics**: Packets-per-second monitoring and analytics

## Technical Architecture

### eBPF Program (`ebpf-probe.c`)
- **Language**: C with eBPF extensions
- **Execution Context**: Linux kernel XDP hook
- **Key Components**:
  - Ethernet and IP header parsing
  - BPF map-based packet counters
  - Atomic operations for thread safety
  - Perf event buffer for debug output

### Control Program (`ebpf-runner.py`)
- **Language**: Python with BCC framework
- **Responsibilities**:
  - eBPF program compilation and loading
  - XDP attachment to network interfaces
  - Real-time statistics collection
  - Event handling and monitoring

## Prerequisites

### System Requirements
- **OS**: Linux kernel 4.8+ (XDP support required)
- **Architecture**: x86_64 (tested) or ARM64
- **Privileges**: Root access or CAP_NET_ADMIN + CAP_BPF capabilities

### Dependencies
```bash
# Ubuntu/Debian
sudo apt update
sudo apt install python3-bpfcc bpfcc-tools linux-headers-$(uname -r)

# CentOS/RHEL/Fedora  
sudo yum install python3-bcc bcc-tools kernel-devel

# Arch Linux
sudo pacman -S python-bcc bcc-tools linux-headers
```

## Project Setup

### 1. Clone and Navigate
```bash
git clone <repository-url>
cd eBPF-Firewall/eBPF-firewall
```

### 2. Verify Kernel Support
```bash
# Check XDP support
sudo bpftool prog show
sudo bpftool map show

# Verify network interface
ip link show
```

### 3. Configure Network Interface
Edit `ebpf-runner.py` line 48 to match your network interface:
```python
INTERFACE = "your-interface-name"  # e.g., "eth0", "wlan0", "enp0s3"
```

### 4. Configure Blocked IP (Optional)
Modify the blocked IP in `ebpf-probe.c` line 65:
```c
// Current: blocks 8.8.8.8
__be32 blocked_ip = (8 << 24) | (8 << 16) | (8 << 8) | 8;
```

## Usage

### Basic Execution
```bash
sudo python3 ebpf-runner.py
```

### Expected Output
```
Counting packets, press Ctrl+C to stop...
Packets per second: 42
Packets per second: 38
Packet to 8.8.8.8 dropped
Packets per second: 45
...
```

### Testing the Firewall
```bash
# In another terminal, test blocked IP
ping 8.8.8.8  # Should be blocked (no response)

# Test allowed traffic
ping google.com  # Should work normally
```

## Monitoring and Debugging
### Real-time BPF Statistics
```bash
# View loaded programs
sudo bpftool prog list

# Monitor map contents
sudo bpftool map dump id <map_id>

# Trace perf events
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

### Performance Analysis
```bash
# Monitor XDP statistics
sudo ip -s link show <interface>

# System-wide network monitoring
sudo iftop -i <interface>
```


##  Customization

### Adding Multiple Blocked IPs
Extend the `drop_packet_to_destination` function with a BPF hash map:
```c
BPF_HASH(blocked_ips, __be32, __u8);
```

### Advanced Filtering Rules
Implement port-based filtering, protocol filtering, or rate limiting by extending the XDP program logic.

### Integration with Network Tools
The program can be integrated with:
- **iptables**: As a fast pre-filter
- **Suricata/Snort**: For IDS integration  
- **Prometheus**: For metrics collection
- **Grafana**: For visualization





## References
- [eBPF Documentation](https://ebpf.io/what-is-ebpf)
- [XDP Tutorial](https://github.com/xdp-project/xdp-tutorial)
- [BCC Reference Guide](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md)
- [Linux Network Stack](https://wiki.linuxfoundation.org/networking/kernel_flow)


