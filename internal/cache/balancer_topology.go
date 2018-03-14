package cache

import (
	"net"
)

// Topology Balance based on Topology, this only returns stats where the ip matches the topolology
func Topology(s Records, ip net.IP) Records {
	var matches Records
	for _, record := range s {
		for _, network := range record.LocalNetworks {
			if network.Contains(ip) {
				matches = append(matches, record)
			}
		}
	}
	if len(matches) > 0 {
		return matches
	}
	return s
}
