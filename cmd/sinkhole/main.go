package main

import (
	"log"

	"github.com/miekg/dns"
	"github.com/sumersabharwal1/dns-sinkhole/internal/blocklist"
	upstream "github.com/sumersabharwal1/dns-sinkhole/internal/resolver"
)

const (
	defaultUpstream = "8.8.8.8:53"
	listenAddress   = ":8053"
)

var (
	resolver     = upstream.NewResolver(defaultUpstream)
	dnsBlocklist = blocklist.InitializeBlocklist()
)

// '.' signifies every query is handled
func main() {
	dns.HandleFunc(".", handleDNSRequest)

	// create new DNS server with specified settings
	server := &dns.Server{
		Addr: listenAddress,
		Net:  "udp", // use UDP protocol (its quicker than TCP)
	}

	log.Printf("Listeining for DNS queries on %s", listenAddress)

	err := server.ListenAndServe()
	if err != nil {
		log.Fatal(err)
	}
}

func sendErrorResponse(w dns.ResponseWriter, request *dns.Msg, rcode int) {
	response := new(dns.Msg)
	response.SetRcode(request, rcode)

	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

func logQuestions(questions []dns.Question) {
	for _, question := range questions {
		log.Printf(
			"Query: Name=%s, Type=%s",
			question.Name,
			dns.TypeToString[question.Qtype],
		)
	}
}

// r - client request (DNS message); w - used to write server response
func handleDNSRequest(w dns.ResponseWriter, request *dns.Msg) {

	if len(request.Question) == 0 {
		sendErrorResponse(w, request, dns.RcodeServerFailure)
		return
	}

	question := request.Question[0]
	logQuestions(request.Question)

	if dnsBlocklist.IsBlocked(question.Name) {
		log.Printf("Blocked: %s", question.Name)
		sendErrorResponse(w, request, dns.RcodeNameError)
		return
	}

	response, err := resolver.Resolve(request)

	if err != nil {
		log.Printf("Upstream DNS query failed: %v", err)
		sendErrorResponse(w, request, dns.RcodeServerFailure)
		return
	}

	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
