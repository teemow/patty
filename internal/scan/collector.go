package scan

import (
	"context"
	"sync"

	"github.com/teemow/patty/internal/detect"
)

// collector gathers what the parallel readers of one scan find: the
// credentials, keyed by value, with every place each was hit, and the
// identifiers the correlating providers saw, keyed by the content they saw
// them in. H says where a hit was: an object and line for a repository, a
// path and line for a file tree.
type collector[H comparable] struct {
	mu        sync.Mutex
	registry  *detect.Registry
	ignore    map[string]bool
	findings  map[string]*Finding
	hits      map[string]map[H]bool        // token value -> distinct locations
	sightings map[string][]detect.Sighting // content key -> identifiers it names, per correlators
	bytes     int64
}

func newCollector[H comparable](opts Options) *collector[H] {
	return &collector[H]{
		registry:  opts.providers(),
		ignore:    opts.Ignore,
		findings:  map[string]*Finding{},
		hits:      map[string]map[H]bool{},
		sightings: map[string][]detect.Sighting{},
	}
}

// observe shows content to the correlating providers and remembers what
// they saw under key.
func (c *collector[H]) observe(key string, content []byte) {
	if seen := c.registry.Observe(content); len(seen) > 0 {
		c.mu.Lock()
		c.sightings[key] = append(c.sightings[key], seen...)
		c.mu.Unlock()
	}
}

// find records every credential in content that is not ignored, located
// by at.
func (c *collector[H]) find(content []byte, at func(line int) H) {
	for _, tok := range c.registry.Find(content) {
		if c.ignore[tok.Fingerprint()] || c.ignore[string(tok.Kind)] {
			continue
		}
		c.mu.Lock()
		f := c.findings[tok.Value]
		if f == nil {
			f = NewFinding(c.registry, tok)
			c.findings[tok.Value] = f
			c.hits[tok.Value] = map[H]bool{}
		} else {
			f.complete(tok.Secret, tok.Attribution)
		}
		f.Occurrences++
		c.hits[tok.Value][at(tok.Line)] = true
		c.mu.Unlock()
	}
}

// read counts n bytes of scanned content.
func (c *collector[H]) read(n int64) {
	c.mu.Lock()
	c.bytes += n
	c.mu.Unlock()
}

// results drops the findings correlate reclassified into an ignored kind,
// verifies the rest when asked, and returns them sorted.
func (c *collector[H]) results(ctx context.Context, opts Options) []Finding {
	var out []Finding
	for _, f := range c.findings {
		if c.ignore[string(f.Kind)] {
			continue
		}
		out = append(out, *f)
	}
	if opts.Verify {
		verify(ctx, c.registry, out)
	}
	SortFindings(out)
	return out
}

// verify asks each finding's provider whether the credential is still live.
func verify(ctx context.Context, registry *detect.Registry, findings []Finding) {
	for i := range findings {
		v := registry.Verify(ctx, findings[i].Detected())
		findings[i].Verification = &v
	}
}
