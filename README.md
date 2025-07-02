# radvan-go
Router advertisement processing agent for agentic networks

## Overview

radvan-go is a specialized IPv6 Router Advertisement (RA) processing daemon designed for agentic networks. It provides fine-grained control over IPv6 prefix and route management by selectively processing RA messages from specific routers and applying custom routing policies.

## How It Works

### Core Functionality

The daemon operates as a selective IPv6 RA processor that:

1. **Listens for Router Advertisements** - Monitors specified network interfaces for incoming ICMPv6 Router Advertisement messages
2. **Filters by Router Source** - Only processes RAs from explicitly allowed routers while blocking blacklisted ones
3. **Validates Prefixes and Routes** - Checks advertised prefixes and routes against configured allow/deny lists
4. **Manages Routing Tables** - Adds routes to custom routing tables for traffic segregation
5. **Handles SLAAC Addresses** - Optionally configures IPv6 addresses using Stateless Address Autoconfiguration
6. **Maintains Route State** - Tracks configured routes and addresses to avoid duplicates

### Step-by-Step Operation

#### 1. Interface Configuration
- Enables IPv6 RA acceptance on specified interfaces
- Disables automatic IPv6 configuration to maintain manual control
- Binds ICMPv6 sockets to specific interfaces

#### 2. RA Message Processing
When a Router Advertisement is received:
- **Source Validation**: Checks if the RA source router is in the allowed list
- **Blacklist Check**: Rejects RAs from blacklisted routers
- **Self-Detection**: Ignores RAs from the interface's own link-local addresses

#### 3. Option Processing
For each RA option type:

**Prefix Information Options (Type 3)**:
- Extracts IPv6 prefix and flags
- Validates prefix against configured allow/blacklist
- Adds on-link routes if the on-link flag is set
- Configures SLAAC addresses if autonomous flag is set and auto-IP is enabled

**Route Information Options (Type 24)**:
- Extracts route prefix and gateway information
- Validates route against configured allow/blacklist
- Adds specific routes via the advertising router

#### 4. Route Management
- **On-link Routes**: Direct routes to prefixes via the interface
- **Gateway Routes**: Routes to specific destinations via router gateways
- **Default Routes**: Default IPv6 routes via validated routers
- **Self Routes**: Routes via auto-configured addresses (if enabled)

#### 5. Address Configuration
When auto-IP is enabled:
- Generates interface identifiers using EUI-64 from MAC addresses
- Creates SLAAC addresses by combining prefixes with interface IDs
- Configures addresses on the interface with appropriate prefix lengths

#### 6. State Management
- Tracks all configured routes and addresses to prevent duplicates
- Loads existing routes and addresses on startup
- Maintains separate state for each interface configuration

## Configuration Structure

The daemon supports multiple configurations per interface, allowing different policies for different traffic types:

```yaml
interfaces:
  <interface_name>:
    <config_name>:
      prefix:           # Prefix filtering
        allow: []       # Allowed prefix patterns
        blacklist: []   # Blacklisted prefix patterns
      route:            # Route filtering  
        allow: []       # Allowed route patterns
        blacklist: []   # Blacklisted route patterns
      routers:          # Router filtering
        allow: []       # Allowed router sources
        blacklist: []   # Blacklisted router sources
      iptable: <num>    # Custom routing table number
      auto-ip: <bool>   # Enable SLAAC address configuration
      addSelfRoute: <bool> # Add routes via self-configured addresses
```

## Use Cases

### Network Segmentation
- Separate different types of traffic into different routing tables
- Apply different policies based on traffic destination
- Isolate experimental or untrusted network segments

### Agentic Network Management
- Allow agents to advertise specific routes for their services
- Control which agents can influence routing decisions
- Implement hierarchical routing policies

### Security and Control
- Prevent rogue routers from affecting network routing
- Implement fine-grained access control for route advertisements
- Monitor and log all routing changes

## Example Scenarios

### Scenario 1: Production vs Development Traffic
```yaml
interfaces:
  eth0:
    production:
      prefix:
        allow: ["2001:db8:prod::/48"]
      routers:
        allow: ["2001:db8:prod::1/128"]
      iptable: 100
    development:
      prefix:
        allow: ["2001:db8:dev::/48"]
      routers:
        allow: ["2001:db8:dev::1/128"]
      iptable: 200
```

### Scenario 2: Selective Route Acceptance
```yaml
interfaces:
  enp9s0:
    config1:
      route:
        allow: ["2000::/3"]        # Accept most global unicast
        blacklist: ["2001:db8::/32"] # Block documentation prefix
      routers:
        allow: ["fe80::/64"]       # Accept from link-local routers
        blacklist: ["fe80::bad:router/128"] # Block specific router
      iptable: 300
      auto-ip: true
```

## Installation

### System Service Installation

To install radvan-go as a systemd service:

```bash
# Make the install script executable
chmod +x install.sh

# Run installation (requires root)
sudo ./install.sh
```

### Manual Installation

```bash
# Build the binary
go build -o radvan-go .

# Copy binary to system path
sudo cp radvan-go /usr/local/bin/

# Create configuration directory
sudo mkdir -p /etc/radvan-go

# Copy configuration file
sudo cp config.yaml /etc/radvan-go/
```

## Usage

### Running as a Service

```bash
# Start the service
sudo systemctl start radvan-go

# Enable auto-start on boot
sudo systemctl enable radvan-go

# Check service status
sudo systemctl status radvan-go

# View logs
sudo journalctl -u radvan-go -f
```

### Running Manually

```bash
# Run with default configuration
./radvan-go

# Run with custom configuration
./radvan-go -c /path/to/config.yaml

# Run with verbose logging
./radvan-go -v

# Show help
./radvan-go -h
```

## Configuration

Edit `/etc/radvan-go/config.yaml` to configure interfaces and routing policies.

After making configuration changes, restart the service:
```bash
sudo systemctl restart radvan-go
```

## Service Management

```bash
# Start service
sudo systemctl start radvan-go

# Stop service
sudo systemctl stop radvan-go

# Restart service
sudo systemctl restart radvan-go

# Reload configuration (if supported)
sudo systemctl reload radvan-go

# Enable auto-start on boot
sudo systemctl enable radvan-go

# Disable auto-start on boot
sudo systemctl disable radvan-go

# Check service status
sudo systemctl status radvan-go

# View recent logs
sudo journalctl -u radvan-go

# Follow logs in real-time
sudo journalctl -u radvan-go -f
```

## Requirements

- Linux with systemd
- IPv6 support
- Root privileges (for network configuration)
- Go 1.19+ (for building from source)
