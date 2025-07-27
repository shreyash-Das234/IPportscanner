# IPportscanner

## Features

### IP Scanner
• Network discovery using ARP requests
• Multi-interface support with auto-detection
• Real-time device discovery and status updates
• MAC address vendor identification (OUI database)
• Hostname resolution for discovered IPs
• Ping connectivity testing
• Export results to CSV format
• Advanced search and filtering
• Auto-refresh scanning (5-minute intervals)
• Color-coded status indicators
• Batch ping testing for selected IPs

### Port Scanner
• Quick scan of common ports (21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3389)
• Full port scan (1-65535 range)
• Real-time scan progress display
• Socket-based port detection
• Multi-threaded scanning
• Service detection on open ports

### Vulnerability Scanner
• Nmap script engine integration
• Automated vulnerability detection
• CVE identification and reporting
• Service version fingerprinting
• Security misconfiguration detection
• SSL/TLS certificate analysis
• Web application vulnerability testing
• Database security assessment
• Network service enumeration
• Brute force attack detection
• Default credential identification
• Operating system detection

### User Interface
• Tabbed interface for different scan types
• Progress bars and status indicators
• Resizable columns and scrollable results
• Double-click actions for quick operations
• Export functionality
• Search and filter capabilities

## Libraries

### Core Dependencies
• `tkinter` - GUI framework
• `threading` - Multi-threaded operations
• `socket` - Network socket operations
• `ipaddress` - IP address manipulation
• `subprocess` - System command execution
• `csv` - CSV file operations
• `queue` - Thread-safe data exchange

### External Libraries
• `psutil` - System and network interface information
• `scapy` - Network packet manipulation and ARP scanning
• `python-nmap` - Nmap integration for vulnerability scanning
• `datetime` - Timestamp operations
• `time` - Timing and delays
• `os` - Operating system interface
• `platform` - Platform identification
