package iridium

import (
	"testing"

	"github.com/rdoorn/zdns/cache"
)

var channelRecordsAdd = map[string][]cache.Record{
	"example.com.": []cache.Record{
		{Name: "channel", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true},
		{Name: "channel", Type: "A", Target: "1.2.3.5", ClusterID: "localhost1", Online: true},
		{Name: "channel", Type: "A", Target: "1.2.3.6", ClusterID: "localhost1", Online: false},
	},
}

var channelRecordsRemove = map[string][]cache.Record{
	"example.com.": []cache.Record{
		{Name: "channel", Type: "A", Target: "1.2.3.4", ClusterID: "localhost1", Online: true},
	},
}

var address2 = "127.0.0.1:15354"

func TestChannels(t *testing.T) {
	m := New(address2)

	err := m.Start()
	if err != nil {
		t.Errorf("failed to start manager: %s", err)
	}

	for domain, records := range channelRecordsAdd {
		for _, record := range records {
			record.Domain = domain
			m.Channels.Add <- record
		}
	}

	for domain, records := range channelRecordsRemove {
		for _, record := range records {
			record.Domain = domain
			m.Channels.Remove <- record
		}
	}

	m.Stop()
}
