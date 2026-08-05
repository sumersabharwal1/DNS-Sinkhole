package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/sumersabharwal1/dns-sinkhole/internal/blocklist"
	upstream "github.com/sumersabharwal1/dns-sinkhole/internal/resolver"
)

var resolver = upstream.NewResolver("8.8.8.8:53")
var dnsBlocklist = blocklist.NewBlocklist()

// '.' signifies every query is handled
func main() {
	dnsBlocklist.Add("example.com.")
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

func sendRcode(w dns.ResponseWriter, request *dns.Msg, rcode int) {
	response := new(dns.Msg)
	response.SetRcode(request, rcode)

	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

// r - client request (DNS message); w - used to write server response
func handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		sendRcode(w, r, dns.RcodeServerFailure)
		return
	}

	for _, question := range r.Question {
		log.Printf(
			"Query: Name=%s, Type=%s",
			question.Name,
			dns.TypeToString[question.Qtype],
		)
	}

	if dnsBlocklist.IsBlocked(r.Question[0].Name) {
		log.Printf("Blocked: %s", r.Question[0].Name)
		sendRcode(w, r, dns.RcodeNameError)
		return
	}

	response, err := resolver.Resolve(r)
	if err != nil {
		log.Printf("Upstream DNS query failed: %v", err)
		sendRcode(w, r, dns.RcodeServerFailure)
		return
	}

	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
