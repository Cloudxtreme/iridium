package iridium

import (
	"fmt"
	"net"

	dnssrv "github.com/miekg/dns"
)

func (s *Server) startListener() error {
	s.Lock()
	defer s.Unlock()
	//password := md5sum(AXFERPassword)
	s.log("Starting dns listener on %s", s.Settings.Addr)
	tcpListener, err := net.Listen("tcp", s.Settings.Addr)
	if err != nil {
		return fmt.Errorf("Failed to start DNS TCP listener: %s", err)
	}
	s.serverTCP = &dnssrv.Server{Addr: s.Settings.Addr, Net: "TCP", Listener: tcpListener}
	s.serverTCP.TsigSecret = map[string]string{"axfr.": s.Settings.AXFERPassword}

	udpListener, err := net.ListenPacket("udp", s.Settings.Addr)
	if err != nil {
		return fmt.Errorf("Failed to start DNS UDP listener: %s", err)
	}
	s.serverUDP = &dnssrv.Server{Addr: s.Settings.Addr, Net: "UDP", PacketConn: udpListener}
	s.serverUDP.TsigSecret = map[string]string{"axfr.": s.Settings.AXFERPassword}

	go s.serverTCP.ActivateAndServe()
	go s.serverUDP.ActivateAndServe()

	return nil
}

func (s *Server) stopListener() {
	s.log("Stopping dns listener on %s", s.serverTCP.Addr)
	s.serverTCP.Shutdown()
	s.serverUDP.Shutdown()
}
