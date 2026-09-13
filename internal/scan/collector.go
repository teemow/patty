package scan

import (
	"context"
	"sort"
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
	hits      map[string]map[H]bool                // token value -> distinct locations
	sightings map[string][]detect.Sighting         // content key -> identifiers it names, per correlators
	instances map[string][]detect.InstanceSighting // content key -> instances it names, per instance observers
	bytes     int64
}

func newCollector[H comparable](opts Options) *collector[H] {
	return &collector[H]{
		registry:  opts.providers(),
		ignore:    opts.Ignore,
		findings:  map[string]*Finding{},
		hits:      map[string]map[H]bool{},
		sightings: map[string][]detect.Sighting{},
		instances: map[string][]detect.InstanceSighting{},
	}
}

// observe shows content to the correlating and instance-observing
// providers and remembers what they saw under key.
func (c *collector[H]) observe(key string, content []byte) {
	seen, instances := c.registry.Observe(content), c.registry.Instances(content)
	if len(seen) == 0 && len(instances) == 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(seen) > 0 {
		c.sightings[key] = append(c.sightings[key], seen...)
	}
	if len(instances) > 0 {
		c.instances[key] = append(c.instances[key], instances...)
	}
}

// bind hands every finding of an instance-observing provider the instances
// that provider saw in the scanned content: the ones named in the objects
// the credential itself was found in first, then the rest of the
// repository. keyOf names the content a hit was in.
func (c *collector[H]) bind(keyOf func(H) string) {
	if len(c.instances) == 0 {
		return
	}
	for value, f := range c.findings {
		observer, ok := c.registry.Provider(f.Kind).(detect.InstanceObserver)
		if !ok {
			continue
		}
		near := map[string]bool{}
		for h := range c.hits[value] {
			near[keyOf(h)] = true
		}
		var first, rest []string
		for key, seen := range c.instances {
			for _, s := range seen {
				if s.Observer != observer {
					continue
				}
				if near[key] {
					first = appendUnique(first, s.Origin)
				} else {
					rest = appendUnique(rest, s.Origin)
				}
			}
		}
		sort.Strings(first)
		sort.Strings(rest)
		instances := appendUnique(first, rest...)
		if len(instances) == 0 {
			continue
		}
		bound := observer.Bind(f.Detected(), instances)
		f.Secret, f.Attribution = bound.Secret, bound.Attribution
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
