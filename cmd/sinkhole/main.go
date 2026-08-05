package main

import (
	"log"

	"github.com/sumersabharwal1/dns-sinkhole/internal/blocklist"
	"github.com/sumersabharwal1/dns-sinkhole/internal/dnsserver"
	upstream "github.com/sumersabharwal1/dns-sinkhole/internal/resolver"
)

const (
	defaultUpstream = "8.8.8.8:53"
	listenAddress   = ":8053"
)

// main function initializes the DNS sinkhole server, sets up the blocklist, and starts listening for incoming DNS requests.
func main() {
	resolver := upstream.NewResolver(defaultUpstream)
	dnsBlocklist := blocklist.InitializeBlocklist()

	server := dnsserver.New(
		listenAddress,
		resolver,
		dnsBlocklist,
	)

	log.Printf("Listening on %s", listenAddress)

	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
