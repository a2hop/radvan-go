package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv6"
)

type RADaemon struct {
	config    *Config
	listeners map[string]*net.PacketConn
	stopChans map[string]chan struct{}
	wg        sync.WaitGroup
	verbose   bool
}

func NewRADaemon(config *Config, verbose bool) *RADaemon {
	return &RADaemon{
		config:    config,
		listeners: make(map[string]*net.PacketConn),
		stopChans: make(map[string]chan struct{}),
		verbose:   verbose,
	}
}

func (d *RADaemon) logVerbose(format string, args ...interface{}) {
	if d.verbose {
		log.Printf("[VERBOSE] "+format, args...)
	}
}

func (d *RADaemon) Start() error {
	for ifName, ifConfigs := range d.config.Interfaces {
		if err := d.configureInterface(ifName); err != nil {
			return fmt.Errorf("failed to configure interface %s: %v", ifName, err)
		}

		// Load existing routes and addresses for each configuration
		for configName, ifConfig := range ifConfigs {
			d.logVerbose("Loading existing state for interface %s config %s", ifName, configName)

			// Load existing routes from system table
			if err := d.loadExistingRoutes(ifName, configName, ifConfig); err != nil {
				log.Printf("Warning: Failed to load existing routes for %s/%s: %v", ifName, configName, err)
			}

			// Load existing addresses
			if err := d.loadExistingAddresses(ifName, configName, ifConfig); err != nil {
				log.Printf("Warning: Failed to load existing addresses for %s/%s: %v", ifName, configName, err)
			}
		}

		stopChan := make(chan struct{})
		d.stopChans[ifName] = stopChan

		d.wg.Add(1)
		go d.listenInterface(ifName, ifConfigs, stopChan)
	}

	log.Println("RA daemon started")
	return nil
}

func (d *RADaemon) Stop() {
	for _, stopChan := range d.stopChans {
		close(stopChan)
	}
	d.wg.Wait()

	for _, conn := range d.listeners {
		(*conn).Close()
	}

	log.Println("RA daemon stopped")
}

func (d *RADaemon) configureInterface(ifName string) error {
	// Enable RA acceptance but disable autoconf
	cmds := [][]string{
		{"sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.accept_ra=1", ifName)},
		{"sysctl", "-w", fmt.Sprintf("net.ipv6.conf.%s.autoconf=0", ifName)},
	}

	for _, cmd := range cmds {
		if err := exec.Command(cmd[0], cmd[1:]...).Run(); err != nil {
			return fmt.Errorf("failed to run %v: %v", cmd, err)
		}
	}

	return nil
}

func (d *RADaemon) listenInterface(ifName string, configs map[string]*InterfaceConfig, stopChan chan struct{}) {
	defer d.wg.Done()

	d.logVerbose("Starting listener for interface %s with %d configurations", ifName, len(configs))

	// Create ICMPv6 socket
	conn, err := net.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		log.Printf("Failed to create ICMPv6 socket for %s: %v", ifName, err)
		return
	}
	defer conn.Close()

	d.logVerbose("Created ICMPv6 socket for %s", ifName)

	// Bind to specific interface
	ipConn, ok := conn.(*net.IPConn)
	if !ok {
		log.Printf("Failed to assert conn to *net.IPConn for %s", ifName)
		return
	}

	// Use syscall to bind to interface
	fd, err := ipConn.SyscallConn()
	if err != nil {
		log.Printf("Failed to get syscall conn for %s: %v", ifName, err)
		return
	}

	err = fd.Control(func(fdInt uintptr) {
		syscall.SetsockoptString(int(fdInt), syscall.SOL_SOCKET, syscall.SO_BINDTODEVICE, ifName)
	})
	if err != nil {
		log.Printf("Failed to bind to interface %s: %v", ifName, err)
		return
	}

	d.logVerbose("Bound socket to interface %s", ifName)

	d.listeners[ifName] = &conn

	// Set ICMPv6 filter to only receive Router Advertisements
	p := ipv6.NewPacketConn(conn)
	filter := &ipv6.ICMPFilter{}
	filter.SetAll(true)
	filter.Accept(ipv6.ICMPTypeRouterAdvertisement)

	if err := p.SetICMPFilter(filter); err != nil {
		log.Printf("Failed to set ICMP filter for %s: %v", ifName, err)
		return
	}

	d.logVerbose("Set ICMPv6 filter for %s to accept Router Advertisements only", ifName)

	log.Printf("Listening for RAs on interface %s", ifName)

	buffer := make([]byte, 1500)
	for {
		select {
		case <-stopChan:
			d.logVerbose("Stop signal received for interface %s", ifName)
			return
		default:
			conn.SetReadDeadline(time.Now().Add(1 * time.Second))
			n, addr, err := conn.ReadFrom(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("Error reading from %s: %v", ifName, err)
				continue
			}

			d.logVerbose("Received %d bytes from %s on %s", n, addr, ifName)
			d.processRA(ifName, configs, buffer[:n], addr)
		}
	}
}

func (d *RADaemon) processRA(ifName string, configs map[string]*InterfaceConfig, data []byte, addr net.Addr) {
	d.logVerbose("Processing RA packet of %d bytes for %d configurations", len(data), len(configs))

	if d.verbose {
		d.logVerbose("Raw packet data: %s", hex.EncodeToString(data))
	}

	msg, err := icmp.ParseMessage(58, data) // 58 is the protocol number for ICMPv6
	if err != nil {
		log.Printf("Failed to parse ICMP message: %v", err)
		return
	}

	d.logVerbose("Parsed ICMP message: Type=%d, Code=%d", msg.Type, msg.Code)

	// ICMPv6 Router Advertisement messages have Type 134
	if msg.Type != ipv6.ICMPTypeRouterAdvertisement {
		d.logVerbose("Ignoring non-RA ICMP message type %d", msg.Type)
		return
	}

	log.Printf("Received RA from %s on %s", addr, ifName)

	// Parse RA body manually
	body, ok := msg.Body.(*icmp.RawBody)
	if !ok {
		log.Printf("Failed to get raw body from RA")
		return
	}

	d.logVerbose("RA body length: %d bytes", len(body.Data))

	// Parse RA header and options
	if len(body.Data) < 12 {
		log.Printf("RA message too short")
		return
	}

	// Log RA header fields
	if d.verbose {
		hopLimit := body.Data[0]
		flags := body.Data[1]
		routerLifetime := binary.BigEndian.Uint16(body.Data[2:4])
		reachableTime := binary.BigEndian.Uint32(body.Data[4:8])
		retransTimer := binary.BigEndian.Uint32(body.Data[8:12])

		d.logVerbose("RA Header - HopLimit:%d, Flags:0x%02x, RouterLifetime:%d, ReachableTime:%d, RetransTimer:%d",
			hopLimit, flags, routerLifetime, reachableTime, retransTimer)
	}

	// Extract router IP from source address
	var routerIP net.IP
	var gateway string
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		routerIP = udpAddr.IP
		gateway = udpAddr.IP.String()
	} else if ipAddr, ok := addr.(*net.IPAddr); ok {
		routerIP = ipAddr.IP
		gateway = ipAddr.IP.String()
	} else {
		gateway = addr.String()
		// Try to parse the string as IP
		if ip := net.ParseIP(gateway); ip != nil {
			routerIP = ip
		}
	}

	d.logVerbose("Router IP: %s", routerIP)

	// Check if this RA is from our own interface (ignore self-sent RAs)
	if d.isOwnInterfaceRA(ifName, routerIP) {
		d.logVerbose("Ignoring RA from own interface %s (source: %s)", ifName, routerIP)
		return
	}

	// Process RA for each configuration that allows this router
	for configName, config := range configs {
		d.logVerbose("Checking configuration %s for interface %s", configName, ifName)

		// Check if this router is blacklisted
		if config.IsRouterBlacklisted(routerIP) {
			d.logVerbose("Router %s is blacklisted in config %s", routerIP, configName)
			if config.Routers != nil {
				d.logVerbose("Router blacklist: %v", config.Routers.Blacklist)
			}
			continue
		}

		// Check if this router is allowed
		if !config.IsRouterAllowed(routerIP) {
			d.logVerbose("Router %s not allowed in config %s", routerIP, configName)
			if config.Routers != nil {
				d.logVerbose("Router allow list: %v", config.Routers.Allow)
			}
			continue
		}

		d.logVerbose("Router %s is allowed in config %s, processing RA", routerIP, configName)

		// Skip RA header (first 12 bytes) and parse options
		options := body.Data[12:]
		d.logVerbose("Processing %d bytes of RA options for config %s", len(options), configName)
		d.parseRAOptions(ifName, configName, config, options, gateway)
	}
}

func (d *RADaemon) isOwnInterfaceRA(ifName string, sourceIP net.IP) bool {
	// Only check for link-local addresses as they indicate local interface
	if !sourceIP.IsLinkLocalUnicast() {
		return false
	}

	// Get the interface and check its addresses
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		d.logVerbose("Failed to get interface %s for self-check: %v", ifName, err)
		return false
	}

	addrs, err := iface.Addrs()
	if err != nil {
		d.logVerbose("Failed to get addresses for interface %s: %v", ifName, err)
		return false
	}

	// Check if the source IP matches any of our interface's link-local addresses
	for _, addr := range addrs {
		if ipNet, ok := addr.(*net.IPNet); ok {
			if ipNet.IP.IsLinkLocalUnicast() && ipNet.IP.Equal(sourceIP) {
				d.logVerbose("Found matching link-local address %s on interface %s", sourceIP, ifName)
				return true
			}
		}
	}

	// Also check using ip command as a fallback
	cmd := exec.Command("ip", "-6", "addr", "show", "dev", ifName, "scope", "link")
	output, err := cmd.Output()
	if err != nil {
		d.logVerbose("Failed to check link-local addresses via ip command: %v", err)
		return false
	}

	// Parse output to find link-local addresses
	lines := strings.Split(string(output), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet6 ") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addrWithPrefix := parts[1]
				if strings.Contains(addrWithPrefix, "/") {
					addr := strings.Split(addrWithPrefix, "/")[0]
					if ip := net.ParseIP(addr); ip != nil && ip.Equal(sourceIP) {
						d.logVerbose("Found matching link-local address %s on interface %s via ip command", sourceIP, ifName)
						return true
					}
				}
			}
		}
	}

	return false
}

func (d *RADaemon) parseRAOptions(ifName, configName string, config *InterfaceConfig, options []byte, gateway string) {
	offset := 0
	foundMatchingPrefix := false
	foundMatchingRoute := false
	optionCount := 0

	d.logVerbose("Parsing RA options from %d bytes for config %s", len(options), configName)

	for offset < len(options) {
		if offset+2 > len(options) {
			d.logVerbose("Not enough bytes for option header at offset %d", offset)
			break
		}

		optType := options[offset]
		optLen := int(options[offset+1]) * 8 // Length in 8-byte units

		d.logVerbose("Option %d: Type=%d, Length=%d bytes", optionCount, optType, optLen)

		if optLen == 0 || offset+optLen > len(options) {
			d.logVerbose("Invalid option length %d at offset %d", optLen, offset)
			break
		}

		// Process Prefix Information Option (type 3)
		if optType == 3 && optLen >= 32 {
			d.logVerbose("Processing Prefix Information Option")

			prefixLen := options[offset+2]
			flags := options[offset+3]
			validLifetime := binary.BigEndian.Uint32(options[offset+4 : 8])
			preferredLifetime := binary.BigEndian.Uint32(options[offset+8 : 12])

			d.logVerbose("Prefix Info - Length:%d, Flags:0x%02x, ValidLifetime:%d, PreferredLifetime:%d",
				prefixLen, flags, validLifetime, preferredLifetime)

			// Extract prefix (16 bytes starting at offset 16)
			if offset+32 <= len(options) {
				prefixBytes := options[offset+16 : offset+32]
				prefixIP := net.IP(prefixBytes)

				prefix := &net.IPNet{
					IP:   prefixIP,
					Mask: net.CIDRMask(int(prefixLen), 128),
				}

				log.Printf("Found prefix option: %s, flags: 0x%02x", prefix, flags)
				d.logVerbose("On-link flag: %t, Autonomous flag: %t", flags&0x80 != 0, flags&0x40 != 0)

				// Check against configured match patterns
				if config.MatchesPrefix(prefix) {
					d.logVerbose("Prefix %s matches configured patterns in config %s", prefix, configName)
					foundMatchingPrefix = true

					// Check if on-link flag is set (bit 7)
					if flags&0x80 != 0 {
						d.logVerbose("Adding on-link route for prefix %s in config %s", prefix, configName)
						d.addRoute(ifName, configName, prefix, config.IPTable)
					} else {
						d.logVerbose("Skipping route for prefix %s (on-link flag not set)", prefix)
					}

					// Check if autonomous flag is set (bit 6) and auto-ip is enabled
					if flags&0x40 != 0 && config.AutoIP {
						d.logVerbose("Configuring auto-IP for prefix %s in config %s", prefix, configName)
						d.configureAutoIP(ifName, configName, prefix, config)
					} else if flags&0x40 == 0 {
						d.logVerbose("Skipping auto-IP for prefix %s (autonomous flag not set)", prefix)
					} else {
						d.logVerbose("Skipping auto-IP for prefix %s (auto-ip disabled)", prefix)
					}
				} else {
					log.Printf("Rejecting prefix %s in config %s (blacklisted or not in allow list)", prefix, configName)
					if config.Prefix != nil {
						d.logVerbose("Prefix allow list: %v", config.Prefix.Allow)
						d.logVerbose("Prefix blacklist: %v", config.Prefix.Blacklist)
					}
				}
			}
		} else if optType == 24 && optLen >= 8 {
			// Process Route Information Option (type 24)
			d.logVerbose("Processing Route Information Option")

			routePrefixLen := options[offset+2]
			flags := options[offset+3]
			routeLifetime := binary.BigEndian.Uint32(options[offset+4 : offset+8])

			d.logVerbose("Route Info - PrefixLen:%d, Flags:0x%02x, Lifetime:%d", routePrefixLen, flags, routeLifetime)

			// Calculate how many bytes we need for the prefix
			prefixByteLen := (int(routePrefixLen) + 7) / 8 // Round up to nearest byte
			if prefixByteLen > 16 {
				prefixByteLen = 16
			}

			// Make sure we have enough bytes in the option
			if offset+8+prefixByteLen <= len(options) && offset+8+prefixByteLen <= offset+optLen {
				prefixBytes := make([]byte, 16)
				copy(prefixBytes, options[offset+8:offset+8+prefixByteLen])

				routePrefix := &net.IPNet{
					IP:   net.IP(prefixBytes),
					Mask: net.CIDRMask(int(routePrefixLen), 128),
				}

				log.Printf("Found route option: %s, preference: %d, lifetime: %d",
					routePrefix, (flags>>3)&0x3, routeLifetime)

				// Check if this route matches our configuration
				if config.MatchesRoute(routePrefix) {
					d.logVerbose("Route %s matches configured patterns in config %s", routePrefix, configName)
					foundMatchingRoute = true

					if routeLifetime > 0 {
						d.logVerbose("Adding route %s via %s in config %s", routePrefix, gateway, configName)
						d.addRouteVia(ifName, configName, routePrefix, gateway, config.IPTable)
					} else {
						d.logVerbose("Skipping route %s (lifetime is 0)", routePrefix)
					}
				} else {
					log.Printf("Rejecting route %s in config %s (blacklisted or not in allow list)", routePrefix, configName)
					if config.Route != nil {
						d.logVerbose("Route allow list: %v", config.Route.Allow)
						d.logVerbose("Route blacklist: %v", config.Route.Blacklist)
					}
				}
			} else {
				d.logVerbose("Route Information Option too short or malformed")
			}
		} else if optType == 1 {
			d.logVerbose("Found Source Link-layer Address option")
		} else if optType == 5 {
			d.logVerbose("Found MTU option")
		} else {
			d.logVerbose("Found unknown option type %d", optType)
		}

		offset += optLen
		optionCount++
	}

	d.logVerbose("Processed %d options total", optionCount)

	// Add default route if we found matching prefixes or routes
	if (foundMatchingPrefix || foundMatchingRoute) && gateway != "" {
		d.logVerbose("Adding default route via %s for config %s", gateway, configName)
		d.addDefaultRoute(ifName, configName, gateway, config.IPTable)
	} else if !foundMatchingPrefix && !foundMatchingRoute {
		d.logVerbose("No matching prefixes or routes found, skipping default route")
	} else {
		d.logVerbose("No gateway address, skipping default route")
	}
}

func (d *RADaemon) addRoute(ifName, configName string, prefix *net.IPNet, table int) {
	routeKey := fmt.Sprintf("%s-table-%d-config-%s", prefix.String(), table, configName)

	// Check if route already exists
	if config := d.getInterfaceConfig(ifName, configName); config != nil && config.HasRoute(routeKey) {
		d.logVerbose("Route %s already exists in table %d for config %s", prefix, table, configName)
		return
	}

	cmd := exec.Command("ip", "-6", "route", "add", prefix.String(), "dev", ifName, "table", fmt.Sprintf("%d", table), "proto", "ra")
	if err := cmd.Run(); err != nil {
		// Check if route already exists (ignore this error)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			log.Printf("Route %s already exists in table %d", prefix, table)
		} else {
			log.Printf("Failed to add route %s: %v", prefix, err)
		}
	} else {
		log.Printf("Added route %s to table %d (config: %s)", prefix, table, configName)
		// Track the route
		if config := d.getInterfaceConfig(ifName, configName); config != nil {
			config.AddRoute(routeKey)
		}
	}
}

func (d *RADaemon) addDefaultRoute(ifName, configName, gateway string, table int) {
	routeKey := fmt.Sprintf("default-via-%s-table-%d-config-%s", gateway, table, configName)

	// Check if default route already exists
	if config := d.getInterfaceConfig(ifName, configName); config != nil && config.HasRoute(routeKey) {
		d.logVerbose("Default route via %s already exists in table %d for config %s", gateway, table, configName)
		return
	}

	cmd := exec.Command("ip", "-6", "route", "add", "default", "via", gateway, "dev", ifName, "table", fmt.Sprintf("%d", table), "proto", "ra")
	if err := cmd.Run(); err != nil {
		// Check if route already exists (ignore this error)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			log.Printf("Default route via %s already exists in table %d", gateway, table)
		} else {
			log.Printf("Failed to add default route via %s: %v", gateway, err)
		}
	} else {
		log.Printf("Added default route via %s to table %d (config: %s)", gateway, table, configName)
		// Track the route
		if config := d.getInterfaceConfig(ifName, configName); config != nil {
			config.AddRoute(routeKey)
		}
	}
}

func (d *RADaemon) addRouteVia(ifName, configName string, routeNet *net.IPNet, gateway string, table int) {
	routeKey := fmt.Sprintf("%s-via-%s-table-%d-config-%s", routeNet.String(), gateway, table, configName)

	// Check if route already exists
	if config := d.getInterfaceConfig(ifName, configName); config != nil && config.HasRoute(routeKey) {
		d.logVerbose("Route %s via %s already exists in table %d for config %s", routeNet, gateway, table, configName)
		return
	}

	cmd := exec.Command("ip", "-6", "route", "add", routeNet.String(), "via", gateway, "dev", ifName, "table", fmt.Sprintf("%d", table), "proto", "ra")
	if err := cmd.Run(); err != nil {
		// Check if route already exists (ignore this error)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			log.Printf("Route %s via %s already exists in table %d", routeNet, gateway, table)
		} else {
			log.Printf("Failed to add route %s via %s: %v", routeNet, gateway, err)
		}
	} else {
		log.Printf("Added route %s via %s to table %d (config: %s)", routeNet, gateway, table, configName)
		// Track the route
		if config := d.getInterfaceConfig(ifName, configName); config != nil {
			config.AddRoute(routeKey)
		}
	}
}

func (d *RADaemon) configureAutoIP(ifName, configName string, prefix *net.IPNet, config *InterfaceConfig) {
	d.logVerbose("Starting auto-IP configuration for %s on %s (config: %s)", prefix, ifName, configName)

	// Generate SLAAC address using EUI-64 or random generation
	iface, err := net.InterfaceByName(ifName)
	if err != nil {
		log.Printf("Failed to get interface %s for auto-IP: %v", ifName, err)
		return
	}

	d.logVerbose("Interface %s MAC address: %s", ifName, iface.HardwareAddr)

	// Generate interface identifier from MAC address (EUI-64)
	var interfaceID []byte
	if len(iface.HardwareAddr) == 6 {
		d.logVerbose("Generating EUI-64 interface ID from MAC address")
		// Convert MAC to EUI-64
		interfaceID = make([]byte, 8)
		copy(interfaceID[:3], iface.HardwareAddr[:3])
		interfaceID[3] = 0xff
		interfaceID[4] = 0xfe
		copy(interfaceID[5:], iface.HardwareAddr[3:])
		// Flip the universal/local bit
		interfaceID[0] ^= 0x02
	} else {
		d.logVerbose("Generating random interface ID (no MAC address available)")
		// Use random interface ID if no MAC available
		interfaceID = make([]byte, 8)
		binary.BigEndian.PutUint64(interfaceID, uint64(time.Now().UnixNano()))
	}

	d.logVerbose("Interface ID: %s", hex.EncodeToString(interfaceID))

	// Combine prefix with interface ID
	autoIP := make(net.IP, 16)
	copy(autoIP[:8], prefix.IP[:8])
	copy(autoIP[8:], interfaceID)

	d.logVerbose("Generated auto-configured address: %s", autoIP)

	// Check if address is already tracked
	addrKey := fmt.Sprintf("addr-%s-%s-config-%s", autoIP.String(), ifName, configName)
	if config.HasRoute(addrKey) {
		d.logVerbose("Auto-configured IP %s already tracked for %s (config: %s)", autoIP, ifName, configName)
		return
	}

	// Add the address to the interface with proper prefix length
	prefixLen := 64 // Default for SLAAC
	if ones, _ := prefix.Mask.Size(); ones > 0 {
		prefixLen = ones
	}

	cmd := exec.Command("ip", "-6", "addr", "add", fmt.Sprintf("%s/%d", autoIP, prefixLen), "dev", ifName)
	if err := cmd.Run(); err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			d.logVerbose("ip command failed with exit code %d", exitErr.ExitCode())
			if exitErr.ExitCode() == 2 {
				d.logVerbose("Address %s may already exist on %s", autoIP, ifName)
				// Track it anyway since it exists
				config.AddRoute(addrKey)
			} else {
				log.Printf("Failed to add auto-configured IP %s to %s: %v", autoIP, ifName, err)
				return
			}
		} else {
			log.Printf("Failed to add auto-configured IP %s to %s: %v", autoIP, ifName, err)
			return
		}
	} else {
		log.Printf("Auto-configured IP %s/%d on %s", autoIP, prefixLen, ifName)
		// Track the new address
		config.AddRoute(addrKey)
	}

	// Handle addSelfRoute configuration
	if config.AddSelfRoute {
		d.logVerbose("Adding self-route for prefix %s via %s (config: %s)", prefix, autoIP, configName)
		d.addSelfRoute(ifName, configName, prefix, autoIP, config.IPTable)
	}
}

func (d *RADaemon) addSelfRoute(ifName, configName string, prefix *net.IPNet, selfIP net.IP, table int) {
	routeKey := fmt.Sprintf("%s-via-%s-table-%d-self-config-%s", prefix.String(), selfIP.String(), table, configName)

	// Check if self-route already exists
	if config := d.getInterfaceConfig(ifName, configName); config != nil && config.HasRoute(routeKey) {
		d.logVerbose("Self-route %s via %s already exists in table %d for config %s", prefix, selfIP, table, configName)
		return
	}

	// Add direct route to the prefix via the auto-configured address
	cmd := exec.Command("ip", "-6", "route", "add", prefix.String(), "via", selfIP.String(), "dev", ifName, "table", fmt.Sprintf("%d", table), "proto", "ra")
	if err := cmd.Run(); err != nil {
		// Check if route already exists (ignore this error)
		if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 2 {
			d.logVerbose("Self-route %s via %s already exists in table %d", prefix, selfIP, table)
		} else {
			log.Printf("Failed to add self-route %s via %s: %v", prefix, selfIP, err)
		}
	} else {
		log.Printf("Added self-route %s via %s to table %d (config: %s)", prefix, selfIP, table, configName)
		// Track the route
		if config := d.getInterfaceConfig(ifName, configName); config != nil {
			config.AddRoute(routeKey)
		}
	}
}

func (d *RADaemon) getInterfaceConfig(ifName, configName string) *InterfaceConfig {
	if ifConfigs, exists := d.config.Interfaces[ifName]; exists {
		if config, exists := ifConfigs[configName]; exists {
			return config
		}
	}
	return nil
}

func (d *RADaemon) loadExistingRoutes(ifName, configName string, config *InterfaceConfig) error {
	d.logVerbose("Loading existing routes for interface %s config %s from table %d", ifName, configName, config.IPTable)

	// Get routes from the specific table
	cmd := exec.Command("ip", "-6", "route", "show", "table", fmt.Sprintf("%d", config.IPTable))
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get routes: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	routeCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		d.logVerbose("Parsing route line: %s", line)

		// Parse different route types
		if strings.HasPrefix(line, "default ") {
			// Default route: "default via fe80::216:3eff:fe0a:7ee1 dev enp9s0 proto ra"
			if strings.Contains(line, " via ") && strings.Contains(line, " dev "+ifName) {
				parts := strings.Fields(line)
				for i, part := range parts {
					if part == "via" && i+1 < len(parts) {
						gateway := parts[i+1]
						routeKey := fmt.Sprintf("default-via-%s-table-%d-config-%s", gateway, config.IPTable, configName)
						config.AddRoute(routeKey)
						d.logVerbose("Loaded existing default route via %s", gateway)
						routeCount++
						break
					}
				}
			}
		} else {
			// Regular routes: "2000::/3 via fe80::216:3eff:fe0a:7ee1 dev enp9s0 proto ra"
			// or on-link routes: "a8:62:1:1::/64 dev enp9s0 proto ra"
			// or self-routes: "a8:62:1:1::/64 via a8:62:1:1:5054:ff:febf:fb69 dev enp9s0 proto ra"
			parts := strings.Fields(line)
			if len(parts) >= 3 && strings.Contains(line, " dev "+ifName) {
				routeDest := parts[0]

				// Validate it's a valid IPv6 network
				if _, _, err := net.ParseCIDR(routeDest); err == nil {
					var routeKey string

					if strings.Contains(line, " via ") {
						// Route with gateway
						for i, part := range parts {
							if part == "via" && i+1 < len(parts) {
								gateway := parts[i+1]
								// Check if this looks like a self-route (gateway is within the same prefix)
								if gatewayIP := net.ParseIP(gateway); gatewayIP != nil {
									if _, routeNet, _ := net.ParseCIDR(routeDest); routeNet != nil && routeNet.Contains(gatewayIP) {
										routeKey = fmt.Sprintf("%s-via-%s-table-%d-self-config-%s", routeDest, gateway, config.IPTable, configName)
										d.logVerbose("Loaded existing self-route %s via %s", routeDest, gateway)
									} else {
										routeKey = fmt.Sprintf("%s-via-%s-table-%d-config-%s", routeDest, gateway, config.IPTable, configName)
										d.logVerbose("Loaded existing route %s via %s", routeDest, gateway)
									}
								}
								break
							}
						}
					} else {
						// On-link route
						routeKey = fmt.Sprintf("%s-table-%d-config-%s", routeDest, config.IPTable, configName)
						d.logVerbose("Loaded existing on-link route %s", routeDest)
					}

					if routeKey != "" {
						config.AddRoute(routeKey)
						routeCount++
					}
				}
			}
		}
	}

	d.logVerbose("Loaded %d existing routes for interface %s config %s", routeCount, ifName, configName)
	return nil
}

func (d *RADaemon) loadExistingAddresses(ifName, configName string, config *InterfaceConfig) error {
	d.logVerbose("Loading existing addresses for interface %s config %s", ifName, configName)

	cmd := exec.Command("ip", "-6", "addr", "show", "dev", ifName)
	output, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("failed to get addresses: %v", err)
	}

	lines := strings.Split(string(output), "\n")
	addressCount := 0

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "inet6 ") {
			// Parse lines like: "inet6 a8:62:1:1:5054:ff:febf:fb69/64 scope global"
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				addrWithPrefix := parts[1]
				if strings.Contains(addrWithPrefix, "/") {
					addr := strings.Split(addrWithPrefix, "/")[0]
					if ip := net.ParseIP(addr); ip != nil && !ip.IsLinkLocalUnicast() && !ip.IsLoopback() {
						// Track this as a configured address
						addrKey := fmt.Sprintf("addr-%s-%s-config-%s", addr, ifName, configName)
						config.AddRoute(addrKey) // Reuse route tracking for addresses
						d.logVerbose("Loaded existing address %s", addr)
						addressCount++
					}
				}
			}
		}
	}

	d.logVerbose("Loaded %d existing addresses for interface %s config %s", addressCount, ifName, configName)
	return nil
}
