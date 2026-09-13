package detect

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// PrivateServersFlag is the flag that lets verification reach private
// networks; named here because more than one provider's report has to say
// so.
const PrivateServersFlag = "--verify-private-servers"

// ServerPolicy decides whether a server named in scanned content may be
// contacted: over https only, and not on a private, loopback or link-local
// address unless the operator allowed that. A repository must not be able
// to point patty at the network it runs in. Every ServerVerifier applies
// it to the servers it discovers; a server the operator named on the
// command line is the operator's decision and is not subject to it.
type ServerPolicy struct {
	// LookupIP resolves a server's host before it is contacted, so that a
	// private address can be refused; nil uses the system resolver, tests
	// fake it.
	LookupIP func(ctx context.Context, host string) ([]net.IP, error)
	// AllowPrivate lets verification contact servers on private, loopback
	// and link-local addresses.
	AllowPrivate bool
}

// Admit reports whether server may be contacted. When it may not, the
// Verification says why, as the unknown verdict the credential gets: a host
// that does not resolve is not reachable from here, which is no verdict on
// the credential either.
func (p ServerPolicy) Admit(ctx context.Context, server string) (Verification, bool) {
	u, err := url.Parse(server)
	if err != nil || u.Host == "" {
		return Unknown("server URL " + server + " does not parse"), false
	}
	if u.Scheme != "https" {
		return Unknown("server " + server + " is not https, not checked"), false
	}
	if p.AllowPrivate {
		return Verification{}, true
	}
	host := u.Hostname()
	ips := []net.IP{net.ParseIP(host)}
	if ips[0] == nil {
		lookup := p.LookupIP
		if lookup == nil {
			lookup = func(ctx context.Context, host string) ([]net.IP, error) {
				return net.DefaultResolver.LookupIP(ctx, "ip", host)
			}
		}
		if ips, err = lookup(ctx, host); err != nil {
			return Unreachable(host, err), false
		}
	}
	for _, ip := range ips {
		if isPrivate(ip) {
			return Unknown("server " + host + " is on a private network, not checked; pass " + PrivateServersFlag + " to check it"), false
		}
	}
	return Verification{}, true
}

func isPrivate(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified()
}

// Unknown is the verdict for a check that could not be completed, with
// the reason.
func Unknown(detail string) Verification {
	return Verification{Status: StatusUnknown, Detail: detail}
}

// Unreachable is the verdict for a request that got no answer from where:
// the DNS answer (no such host) or the TLS or transport error, without the
// URL the request was aimed at, which where already names.
func Unreachable(where string, err error) Verification {
	return Unknown(where + " not reachable from here: " + reachError(err))
}

func reachError(err error) string {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dns.Err
	}
	var u *url.Error
	if errors.As(err, &u) {
		return u.Err.Error()
	}
	return err.Error()
}

// AcrossInstances verifies a credential that is bound to one of several
// candidate instances, the credential itself not saying which: check asks
// one instance. The first instance that accepts the credential settles it
// as active. It is revoked only when every instance rejected it
// explicitly; a mix of rejections and failed checks is unknown, since the
// instance that would have accepted it may be the one that could not be
// asked. The caller decides what an empty candidate list means.
func AcrossInstances(instances []string, check func(instance string) Verification) Verification {
	var (
		details  []string
		rejected int
	)
	for _, instance := range instances {
		v := check(instance)
		switch v.Status {
		case StatusActive:
			return v
		case StatusRevoked:
			rejected++
			if v.Detail == "" {
				v.Detail = HostOf(instance) + " rejects it"
			}
			details = append(details, v.Detail)
		default:
			details = append(details, v.Detail)
		}
	}
	status := StatusUnknown
	if rejected == len(instances) && rejected > 0 {
		status = StatusRevoked
	}
	return Verification{Status: status, Detail: strings.Join(details, "; ")}
}

// HostOf returns the host and port of a URL, or the string itself when it
// is not one.
func HostOf(server string) string {
	if u, err := url.Parse(server); err == nil && u.Host != "" {
		return u.Host
	}
	return server
}

// ScanHosts finds every host name in content that contains needle and
// that accept admits, and returns the origins they were written under,
// each once: the scheme when the host followed one (`https://`,
// `http://`), https otherwise, and the port when one was written. A host
// is a run of letters, digits, dots and dashes with at least one dot, no
// empty label and a public top-level domain; the needle has to start a
// label or end one, so `grafana.` matches grafana.example.com and not
// mygrafana.example.com.
func ScanHosts(content []byte, needle string, accept func(host string) bool) []string {
	var out []string
	seen := map[string]bool{}
	pattern := []byte(needle)
	idx := 0
	for {
		i := bytes.Index(content[idx:], pattern)
		if i < 0 {
			return out
		}
		at := idx + i
		idx = at + len(needle)
		start, end := at, at+len(needle)
		for start > 0 && isHostByte(content[start-1]) {
			start--
		}
		for end < len(content) && isHostByte(content[end]) {
			end++
		}
		host := strings.ToLower(string(content[start:end]))
		if !validHost(host) || !labelStart(host, at-start) || !accept(host) {
			continue
		}
		origin := scheme(content, start) + "://" + host + port(content, end)
		if !seen[origin] {
			seen[origin] = true
			out = append(out, origin)
		}
	}
}

func isHostByte(c byte) bool { return IsAlnum(c) || c == '.' || c == '-' }

// validHost reports whether host is a name with at least two non-empty
// labels that neither start nor end with a dash, under a top-level domain
// ICANN delegates: grafana.yaml is a file, grafana.local an mDNS name and
// grafana.example.com-tls a Secret, none of them a host anyone reaches
// from here. An instance under an internal domain is the operator's to
// name.
func validHost(host string) bool {
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, l := range labels {
		if l == "" || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	_, icann := publicsuffix.PublicSuffix(labels[len(labels)-1])
	return icann
}

// labelStart reports whether offset is the beginning of a label of host.
func labelStart(host string, offset int) bool {
	return offset == 0 || host[offset-1] == '.'
}

// scheme returns the URL scheme written before position start, when the
// host follows `://`, else https.
func scheme(content []byte, start int) string {
	if start >= 3 && string(content[start-3:start]) == "://" {
		s := start - 3
		for s > 0 && IsAlnum(content[s-1]) {
			s--
		}
		if sch := strings.ToLower(string(content[s : start-3])); sch == "http" || sch == "https" {
			return sch
		}
	}
	return "https"
}

// port returns the `:port` written right after position end, or "".
func port(content []byte, end int) string {
	if end >= len(content) || content[end] != ':' {
		return ""
	}
	n := Span(content, end+1, 6, IsDigit)
	if n == 0 || AlnumAt(content, end+1+n) {
		return ""
	}
	return string(content[end : end+1+n])
}

// Uniq returns items with duplicates removed, first occurrence kept.
func Uniq(items ...string) []string {
	var out []string
	seen := map[string]bool{}
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

// Set indexes items for membership tests.
func Set(items []string) map[string]bool {
	set := make(map[string]bool, len(items))
	for _, item := range items {
		set[item] = true
	}
	return set
}
