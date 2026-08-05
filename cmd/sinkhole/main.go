package main

import (
	"log"

	"github.com/miekg/dns"
	upstream "github.com/sumersabharwal1/dns-sinkhole/internal/resolver"
)

var resolver = upstream.NewResolver("8.8.8.8:53")

// '.' signifies every query is handled
func main() {
	dns.HandleFunc(".", handleDNSRequest)

	// create new DNS server with specified settings
	server := &dns.Server{
		Addr: ":8053",
		Net:  "udp", // use UDP protocol (its quicker than TCP)
	}

	log.Println("Listening on :8053")

	// start server
	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

// r - client request (DNS message); w - used to write server response
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Question is a slice of multiple questions in the DNS message
	for _, question := range r.Question {
		log.Printf(
			"Query: Name=%s, Type=%s",
			question.Name,
			dns.TypeToString[question.Qtype],
		)
	}
	response, err := resolver.Resolve(r)

	// handle error if upstream DNS query fails
	if err != nil {
		log.Printf("Upstream DNS query failed: %v", err)
		// create a new DNS message to indicate server failure
		failure := new(dns.Msg)
		failure.SetRcode(r, dns.RcodeServerFailure)

		// write failure response back to client
		err = w.WriteMsg(failure)
		if err != nil {
			log.Printf("Failed to write failure response: %v", err)
		}
		return
	}

	// write response back to client
	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
