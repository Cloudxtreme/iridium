package forwarder

import (
	"net"
	"testing"
)

func TestRootImport(t *testing.T) {
	// Add fake A record
	zone := "A.ROOT-SERVERS.NET.      3600000      A     198.41.0.6"
	forwardCache.importZone(zone)

	// Test if we have records
	rs, err := forwardCache.Get(".", "NS", "", net.IP{}, true)
	if err == ErrNotFound {
		t.Errorf("No initial root NS's found, did generate.sh run? %s", err)
	}
	rs, err = forwardCache.Get("ROOT-SERVERS.NET.", "A", "A", net.IP{}, true)

	hints, err := getRootHints()
	if err != nil {
		t.Errorf("Failed to get root hints file: %s", err)
	}
	parseRootHints(hints)
	rs, err = forwardCache.Get("ROOT-SERVERS.NET.", "A", "A", net.IP{}, true)

	if err != nil {
		t.Errorf("Failed to get A record for A.ROOT-SERVERS.NET.: %s", err)
	}

	if len(rs) > 1 {
		t.Errorf("Expected 1 A record for A.ROOT-SERVERS.NET. but got %d", len(rs))
	}

}
