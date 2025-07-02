package main

import (
	"net"
	"os"
	"sync"

	"gopkg.in/yaml.v2"
)

type Config struct {
	LogLevel   string                                 `yaml:"loglevel"`
	Interfaces map[string]map[string]*InterfaceConfig `yaml:"interfaces"`
}

type PrefixConfig struct {
	Allow     []string `yaml:"allow"`
	Blacklist []string `yaml:"blacklist"`
}

type RouteConfig struct {
	Allow     []string `yaml:"allow"`
	Blacklist []string `yaml:"blacklist"`
}

type RouterConfig struct {
	Allow     []string `yaml:"allow"`
	Blacklist []string `yaml:"blacklist"`
}

type InterfaceConfig struct {
	// New structured configuration
	Prefix  *PrefixConfig `yaml:"prefix"`
	Route   *RouteConfig  `yaml:"route"`
	Routers *RouterConfig `yaml:"routers"`

	// Legacy fields for backward compatibility
	MatchDest        []string `yaml:"match-dest"`
	AllowedRouters   []string `yaml:"allowed-routers"`
	BlacklistRouters []string `yaml:"blacklist-routers"`

	// Common fields
	IPTable      int  `yaml:"iptable"`
	AutoIP       bool `yaml:"auto-ip"`
	AddSelfRoute bool `yaml:"addSelfRoute"`

	// Parsed networks
	prefixAllowed     []*net.IPNet    // Allowed prefix networks
	prefixBlacklisted []*net.IPNet    // Blacklisted prefix networks
	routeAllowed      []*net.IPNet    // Allowed route networks
	routeBlacklisted  []*net.IPNet    // Blacklisted route networks
	routerAllowed     []*net.IPNet    // Allowed router networks
	routerBlacklisted []*net.IPNet    // Blacklisted router networks
	routes            map[string]bool // Track added routes
	routesMux         sync.RWMutex    // Protect routes map
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var config Config
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, err
	}

	// Parse CIDR prefixes for all configurations
	for ifName, ifConfigs := range config.Interfaces {
		for configName, ifConfig := range ifConfigs {
			ifConfig.routes = make(map[string]bool)

			// Parse new structured configuration
			if ifConfig.Prefix != nil {
				// Parse allowed prefix networks
				for _, prefix := range ifConfig.Prefix.Allow {
					_, ipNet, err := net.ParseCIDR(prefix)
					if err != nil {
						return nil, err
					}
					ifConfig.prefixAllowed = append(ifConfig.prefixAllowed, ipNet)
				}

				// Parse blacklisted prefix networks
				for _, prefix := range ifConfig.Prefix.Blacklist {
					_, ipNet, err := net.ParseCIDR(prefix)
					if err != nil {
						return nil, err
					}
					ifConfig.prefixBlacklisted = append(ifConfig.prefixBlacklisted, ipNet)
				}
			}

			if ifConfig.Route != nil {
				// Parse allowed route networks
				for _, route := range ifConfig.Route.Allow {
					_, ipNet, err := net.ParseCIDR(route)
					if err != nil {
						return nil, err
					}
					ifConfig.routeAllowed = append(ifConfig.routeAllowed, ipNet)
				}

				// Parse blacklisted route networks
				for _, route := range ifConfig.Route.Blacklist {
					_, ipNet, err := net.ParseCIDR(route)
					if err != nil {
						return nil, err
					}
					ifConfig.routeBlacklisted = append(ifConfig.routeBlacklisted, ipNet)
				}
			}

			if ifConfig.Routers != nil {
				// Parse allowed router networks
				for _, router := range ifConfig.Routers.Allow {
					_, ipNet, err := net.ParseCIDR(router)
					if err != nil {
						return nil, err
					}
					ifConfig.routerAllowed = append(ifConfig.routerAllowed, ipNet)
				}

				// Parse blacklisted router networks
				for _, router := range ifConfig.Routers.Blacklist {
					_, ipNet, err := net.ParseCIDR(router)
					if err != nil {
						return nil, err
					}
					ifConfig.routerBlacklisted = append(ifConfig.routerBlacklisted, ipNet)
				}
			}

			// Handle legacy configuration for backward compatibility
			if len(ifConfig.MatchDest) > 0 {
				for _, prefix := range ifConfig.MatchDest {
					_, ipNet, err := net.ParseCIDR(prefix)
					if err != nil {
						return nil, err
					}
					// Add to both prefix and route allowed if using legacy config
					ifConfig.prefixAllowed = append(ifConfig.prefixAllowed, ipNet)
					ifConfig.routeAllowed = append(ifConfig.routeAllowed, ipNet)
				}
			}

			if len(ifConfig.AllowedRouters) > 0 {
				for _, router := range ifConfig.AllowedRouters {
					_, ipNet, err := net.ParseCIDR(router)
					if err != nil {
						return nil, err
					}
					ifConfig.routerAllowed = append(ifConfig.routerAllowed, ipNet)
				}
			}

			if len(ifConfig.BlacklistRouters) > 0 {
				for _, router := range ifConfig.BlacklistRouters {
					_, ipNet, err := net.ParseCIDR(router)
					if err != nil {
						return nil, err
					}
					ifConfig.routerBlacklisted = append(ifConfig.routerBlacklisted, ipNet)
				}
			}

			config.Interfaces[ifName][configName] = ifConfig
		}
	}

	return &config, nil
}

// Check if a route destination matches configured networks
func (ic *InterfaceConfig) MatchesRoute(routeNet *net.IPNet) bool {
	// First check if it's blacklisted
	for _, blacklistNet := range ic.routeBlacklisted {
		if blacklistNet.Contains(routeNet.IP) || routeNet.Contains(blacklistNet.IP) {
			return false
		}
	}

	// If no allowed routes specified, allow all (except blacklisted)
	if len(ic.routeAllowed) == 0 {
		return true
	}

	// Check if route matches allowed networks
	for _, allowedNet := range ic.routeAllowed {
		if allowedNet.Contains(routeNet.IP) || routeNet.Contains(allowedNet.IP) {
			return true
		}
	}
	return false
}

// Check if a prefix matches configured networks
func (ic *InterfaceConfig) MatchesPrefix(prefix *net.IPNet) bool {
	// First check if it's blacklisted
	for _, blacklistNet := range ic.prefixBlacklisted {
		if blacklistNet.Contains(prefix.IP) || prefix.Contains(blacklistNet.IP) {
			return false
		}
	}

	// If no allowed prefixes specified, allow all (except blacklisted)
	if len(ic.prefixAllowed) == 0 {
		return true
	}

	// Check if prefix matches allowed networks
	for _, allowedNet := range ic.prefixAllowed {
		if allowedNet.Contains(prefix.IP) || prefix.Contains(allowedNet.IP) {
			return true
		}
	}
	return false
}

// Check if a router is allowed
func (ic *InterfaceConfig) IsRouterAllowed(routerIP net.IP) bool {
	// First check blacklist - if blacklisted, always deny
	if ic.IsRouterBlacklisted(routerIP) {
		return false
	}

	// If no allowed routers specified, allow all (except blacklisted)
	if len(ic.routerAllowed) == 0 {
		return true
	}

	// Check if router is in allowed list
	for _, allowedNet := range ic.routerAllowed {
		if allowedNet.Contains(routerIP) {
			return true
		}
	}
	return false
}

// Check if a router is blacklisted
func (ic *InterfaceConfig) IsRouterBlacklisted(routerIP net.IP) bool {
	for _, blacklistNet := range ic.routerBlacklisted {
		if blacklistNet.Contains(routerIP) {
			return true
		}
	}
	return false
}

func (ic *InterfaceConfig) HasRoute(route string) bool {
	ic.routesMux.RLock()
	defer ic.routesMux.RUnlock()
	return ic.routes[route]
}

func (ic *InterfaceConfig) AddRoute(route string) {
	ic.routesMux.Lock()
	defer ic.routesMux.Unlock()
	ic.routes[route] = true
}
