package dnsserver

import (
	"log"

	"github.com/miekg/dns"
)

// sendErrorResponse sends a DNS response with the specified RCODE to the client.
func sendErrorResponse(w dns.ResponseWriter, request *dns.Msg, rcode int) {
	response := &dns.Msg{}
	response.SetRcode(request, rcode)

	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write DNS response: %v", err)
	}
}

// logQuestions logs the details of the DNS questions in the request for debugging purposes.
func logQuestions(questions []dns.Question) {
	for _, question := range questions {
		log.Printf(
			"Query: Name=%s, Type=%s",
			question.Name,
			dns.TypeToString[question.Qtype],
		)
	}
}

// Server represents a DNS server that handles incoming DNS requests, checks against a blocklist, and forwards valid requests to an upstream resolver.
func (s *Server) handleDNSRequest(w dns.ResponseWriter, request *dns.Msg) {
	// Check if the request contains any questions; if not, respond with a server failure.
	if len(request.Question) == 0 {
		sendErrorResponse(w, request, dns.RcodeServerFailure)
		return
	}

	question := request.Question[0]

	logQuestions(request.Question)

	// Check if the queried domain is in the blocklist; if so, respond with a name error.
	if s.dnsBlocklist.IsBlocked(question.Name) {
		log.Printf("Blocked: %s", question.Name)
		sendErrorResponse(w, request, dns.RcodeNameError)
		return
	}

	// Forward the request to the upstream resolver and handle any errors that may occur.
	response, err := s.resolver.Resolve(request)
	if err != nil {
		log.Printf("Upstream DNS query failed: %v", err)
		sendErrorResponse(w, request, dns.RcodeServerFailure)
		return
	}

	// Send the response back to the client; log any errors encountered while writing the response.
	if err := w.WriteMsg(response); err != nil {
		log.Printf("Failed to write response: %v", err)
	}
}
