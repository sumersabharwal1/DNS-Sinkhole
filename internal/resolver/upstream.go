package resolver

import (
	"github.com/miekg/dns"
)

type Resolver struct {
	upstream string
	client   *dns.Client
}

// Resolve sends a DNS request to the upstream resolver and returns the response.
func (r *Resolver) Resolve(request *dns.Msg) (*dns.Msg, error) {
	response, _, err := r.client.Exchange(request, r.upstream)
	if err != nil {
		return nil, err
	}
	return response, nil
}

// NewResolver creates a new Resolver with the specified upstream DNS server.
func NewResolver(upstream string) *Resolver {
	return &Resolver{
		upstream: upstream,
		client:   &dns.Client{},
	}
}
