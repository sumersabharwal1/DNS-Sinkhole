package blocklist

import "strings"

type Blocklist struct {
	entries map[string]struct{}
}

func NewBlocklist() *Blocklist {
	return &Blocklist{
		// Initialize the entries map to store blocked domains
		entries: make(map[string]struct{}),
	}
}

// normalizeDomain converts the domain to lowercase for consistent comparison
func normalizeDomain(domain string) string {
	return strings.ToLower(domain)
}

// IsBlocked checks if a domain is in the blocklist
func (b *Blocklist) IsBlocked(domain string) bool {
	domain = normalizeDomain(domain)
	_, exists := b.entries[domain]
	return exists
}

func (b *Blocklist) Add(domain string) {
	domain = normalizeDomain(domain)
	b.entries[domain] = struct{}{}
}

func (b *Blocklist) Remove(domain string) {
	domain = normalizeDomain(domain)
	delete(b.entries, domain)
}
