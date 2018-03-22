package forwarder

import (
	"net"
	"testing"

	"github.com/rdoorn/iridium/cache"
)

func TestRootImport(t *testing.T) {
	f := New()
	// Add fake A record
	zone := "A.ROOT-SERVERS.NET.      3600000      A     198.41.0.6"
	f.Cache.ImportZone(zone)

	// Test if we have records
	rs, result := f.Cache.Get(".", "NS", "", net.IP{}, true)
	if result == cache.ErrNotFound {
		t.Errorf("No initial root NS's found, did generate.sh run? %d", result)
	}
	rs, result = f.Cache.Get("ROOT-SERVERS.NET.", "A", "A", net.IP{}, true)

	hints, err := f.getRootHints()
	if err != nil {
		t.Errorf("Failed to get root hints file: %s", err)
	}
	f.parseRootHints(hints)
	rs, result = f.Cache.Get("ROOT-SERVERS.NET.", "A", "A", net.IP{}, true)

	if result != cache.Found {
		t.Errorf("Failed to get A record for A.ROOT-SERVERS.NET.: %d", result)
	}

	if len(rs) > 1 {
		t.Errorf("Expected 1 A record for A.ROOT-SERVERS.NET. but got %d", len(rs))
	}

}
