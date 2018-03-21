package userip

import (
	"context"
	"net"
	"strings"
)

// The key type is unexported to prevent collisions with context keys defined in
// other packages.
type key int

// userIPkey is the context key for the user IP address.  Its value of zero is
// arbitrary.  If this package defined other context keys, they would have
// different integer values.
const userIPKey key = 0

// FromRequest extracts a userIP value from an string:
func FromRequest(addr string) net.IP {
	if idx := strings.LastIndex(addr, ":"); idx != -1 {
		addr = addr[:idx]
		// ugly for ipv6 parsing
		addr = strings.Replace(addr, "[", "", -1)
		addr = strings.Replace(addr, "]", "", -1)
	}
	return net.ParseIP(addr)
}

// NewContext returns a new Context that carries a provided userIP value:
func NewContext(ctx context.Context, userIP net.IP) context.Context {
	return context.WithValue(ctx, userIPKey, userIP)
}

// FromContext extracts a userIP from a Context:
func FromContext(ctx context.Context) (net.IP, bool) {
	// ctx.Value returns nil if ctx has no value for the key;
	// the net.IP type assertion returns ok=false for nil.
	userIP, ok := ctx.Value(userIPKey).(net.IP)
	return userIP, ok
}
