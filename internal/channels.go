package iridium

import (
	"github.com/rdoorn/iridium/internal/cache"
)

// ChannelManager defines the channels used to communicate outside the package
type ChannelManager struct {
	Add    chan cache.Record
	Remove chan cache.Record
	Update chan cache.Record
	quit   chan bool
}

// NewChannelManager creates a new channel manager
func NewChannelManager() *ChannelManager {
	c := &ChannelManager{
		Add:    make(chan cache.Record),
		Remove: make(chan cache.Record),
		Update: make(chan cache.Record),
		quit:   make(chan bool),
	}
	return c
}

// StartChannels starts the channel manager communications
func (s *Server) StartChannels() {
	for {
		select {
		case <-s.Channels.quit:
			return
		case record := <-s.Channels.Add:
			s.serverCache.Add(record.Domain, record)
		case record := <-s.Channels.Remove:
			s.serverCache.Remove(record.Domain, record)
			//case record := <-c.Update:
		}
	}
}
