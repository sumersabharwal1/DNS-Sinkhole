package dnsserver

import (
	"github.com/miekg/dns"
	"github.com/sumersabharwal1/dns-sinkhole/internal/blocklist"
	"github.com/sumersabharwal1/dns-sinkhole/internal/resolver"
)

type Server struct {
	listenAddress string
	resolver      *resolver.Resolver
	dnsBlocklist  *blocklist.Blocklist
	server        *dns.Server
}

// New creates a new DNS server instance with the specified listen address, resolver, and blocklist.
func New(
	listenAddress string,
	resolver *resolver.Resolver,
	dnsBlocklist *blocklist.Blocklist,
) *Server {

	s := &Server{
		listenAddress: listenAddress,
		resolver:      resolver,
		dnsBlocklist:  dnsBlocklist,
	}

	// Register the handleDNSRequest function to handle all DNS queries (denoted by ".")
	dns.HandleFunc(".", s.handleDNSRequest)

	s.server = &dns.Server{
		Addr: s.listenAddress,
		Net:  "udp",
	}

	return s
}

// ListenAndServe starts the DNS server and listens for incoming DNS requests on the specified address.
func (s *Server) ListenAndServe() error {
	return s.server.ListenAndServe()
}
