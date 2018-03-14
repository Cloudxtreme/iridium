package cache

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

// Len provides sort interface for records
func (s Records) Len() int { return len(s) }

// Swap provides sort interface for records
func (s Records) Swap(i, j int) { s[i], s[j] = s[j], s[i] }

// Sort sorts statistics based on value.
// ID can be a IP for ip based loadbalancing.
// ID van be sessionID for stickyness based loadbalancing.
func Sort(s Records, ip net.IP, mode string) (Records, error) {
	switch mode {

	case "roundrobin":
		sort.Sort(RoundRobin{s})
	case "preference":
		sort.Sort(Preference{s})
	case "leastconnected":
		sort.Sort(LeastConnected{s})
	case "leasttraffic":
		sort.Sort(LeastTraffic{s})
	case "topology":
		s = Topology(s, ip)
	case "firstavailable":
		s = FirstAvailable(s)
	default:
		return s, fmt.Errorf("Unknown balance mode: %s", mode)

	}
	return s, nil
}

// MultiSort sorts statistics based on multiple modes
func MultiSort(s Records, ip net.IP, mode string) (Records, error) {
	modes := reverse(strings.Split(mode, ","))
	var err error
	for _, m := range modes {
		s, err = Sort(s, ip, m)
		if err != nil {
			return s, err
		}
	}
	return s, nil
}

// reverse an array of strings
func reverse(s []string) []string {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
	return s
}
