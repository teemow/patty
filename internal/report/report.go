// Package report renders scan results for terminals and machines.
package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/teemow/patty/internal/detect"
	"github.com/teemow/patty/internal/scan"
)

// Options control text rendering.
type Options struct {
	Color       bool
	ShowSecrets bool
}

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	green  = "\033[32m"
	yellow = "\033[33m"
)

// printer writes report text; write errors on a terminal are not actionable.
type printer struct{ w io.Writer }

func (p printer) f(format string, args ...any) { _, _ = fmt.Fprintf(p.w, format, args...) }

func (p printer) ln() { _, _ = fmt.Fprintln(p.w) }

func (o Options) paint(code, s string) string {
	if !o.Color || s == "" {
		return s
	}
	return code + s + reset
}

// StatusLine renders the one-line outcome for a target as it completes.
func StatusLine(r scan.Result, o Options) string {
	mark, color := "✔", green
	switch {
	case r.Skipped:
		mark, color = "–", yellow
	case r.Err != nil:
		mark, color = "✘", red
	case len(r.Findings) > 0:
		mark, color = "!", red
	}
	line := fmt.Sprintf("%s %-32s %s", o.paint(color, mark), r.Target, o.paint(dim, scan.Describe(r)))
	if n := len(r.Findings); n > 0 {
		line += " · " + o.paint(bold+red, fmt.Sprintf("%d %s", n, plural(n, "token", "tokens")))
	}
	for _, note := range r.Notes {
		line += "\n  " + o.paint(yellow, "note: "+note)
	}
	return line
}

// Text writes the final report: every distinct token with all the places
// it was found, followed by a summary line.
func Text(w io.Writer, results []scan.Result, o Options) {
	p := printer{w}
	findings := merge(results)
	s := scan.Summarize(results)

	if len(findings) == 0 {
		p.f("\n%s %s\n", o.paint(green+bold, "No GitHub tokens found"), o.paint(dim, footer(s)))
		return
	}

	head := fmt.Sprintf("%d GitHub %s found", len(findings), plural(len(findings), "token", "tokens"))
	if s.Active > 0 {
		head += o.paint(red+bold, fmt.Sprintf(" (%d active)", s.Active))
	}
	p.f("\n%s %s\n", o.paint(bold, head), o.paint(dim, footer(s)))

	for _, f := range findings {
		value := f.Redacted
		if o.ShowSecrets {
			value = f.Token
		}
		state, color := "unverified", yellow
		if f.Verification != nil {
			state = string(f.Verification.Status)
			switch f.Verification.Status {
			case detect.StatusActive:
				state, color = "ACTIVE", red+bold
			case detect.StatusRevoked:
				color = green
			}
		}
		p.f("\n%s %-10s %-24s %s  %s", o.paint(color, "●"), o.paint(color, state), f.Kind, o.paint(bold, value), o.paint(dim, "fp "+f.Fingerprint))
		if f.Verification != nil && f.Verification.Detail != "" {
			p.f("  %s", o.paint(dim, f.Verification.Detail))
		}
		if !f.ChecksumVerified {
			p.f("  %s", o.paint(dim, "(shape match, no checksum)"))
		}
		p.ln()
		for _, l := range f.Locations {
			where := l.Path
			if l.ObjectType == "commit" {
				where = "commit message"
			} else if where == "" {
				where = "object " + short(l.Object)
			} else {
				where = fmt.Sprintf("%s:%d", where, l.Line)
			}
			p.f("    %s  %s", o.paint(bold, l.Repo), where)
			if c := l.Commit; c != nil {
				p.f("  %s %s %s %s", o.paint(dim, short(c.SHA)), o.paint(dim, day(c.Date)), c.Author, o.paint(dim, "· "+truncate(c.Subject, 60)))
			}
			p.ln()
			p.f("    %s  %s\n", strings.Repeat(" ", len(l.Repo)), o.paint(dim, reachability(l, o)))
		}
	}
	p.ln()
}

func reachability(l scan.Location, o Options) string {
	if l.Commit == nil {
		return "commit unknown"
	}
	if l.Orphaned {
		s := o.paint(red, "orphaned: no branch, tag or PR reaches this commit")
		if l.Rewrite != "" {
			s += " · " + l.Rewrite
		}
		return s
	}
	g := groupRefs(l.Refs)
	if len(g.branches) == 0 && len(g.tags) == 0 {
		return o.paint(yellow, "not on any branch or tag, only reachable through pull request refs: "+join(g.pulls, 5))
	}
	return "on " + Refs(l.Refs, 5)
}

type refGroups struct {
	branches, tags, pulls, other []string
}

// groupRefs sorts refs into branches (default branches first), tags, pull
// request refs and the rest, with display names and duplicates removed.
func groupRefs(refs []string) refGroups {
	var g refGroups
	seen := map[string]bool{}
	add := func(list *[]string, name string) {
		if !seen[name] {
			seen[name] = true
			*list = append(*list, name)
		}
	}
	for _, r := range refs {
		switch {
		case strings.HasPrefix(r, "refs/heads/"):
			add(&g.branches, strings.TrimPrefix(r, "refs/heads/"))
		case strings.HasPrefix(r, "refs/tags/"):
			add(&g.tags, "tag "+strings.TrimPrefix(r, "refs/tags/"))
		case strings.HasPrefix(r, "refs/pull/"):
			num, _, _ := strings.Cut(strings.TrimPrefix(r, "refs/pull/"), "/")
			add(&g.pulls, "PR #"+num)
		case strings.HasPrefix(r, "refs/remotes/"):
			add(&g.branches, strings.TrimPrefix(r, "refs/remotes/"))
		default:
			add(&g.other, r)
		}
	}
	sort.SliceStable(g.branches, func(i, j int) bool { return isDefault(g.branches[i]) && !isDefault(g.branches[j]) })
	return g
}

func isDefault(branch string) bool {
	switch strings.TrimPrefix(branch, "origin/") {
	case "main", "master", "trunk", "develop":
		return true
	}
	return false
}

// Refs renders ref names compactly: branches by name (default branches
// first), tags as "tag v1", pull request refs as "PR #12", at most limit
// entries.
func Refs(refs []string, limit int) string {
	g := groupRefs(refs)
	names := append(append(append(g.branches, g.tags...), g.pulls...), g.other...)
	return join(names, limit)
}

func join(names []string, limit int) string {
	if len(names) > limit {
		return strings.Join(names[:limit], ", ") + fmt.Sprintf(", +%d more", len(names)-limit)
	}
	return strings.Join(names, ", ")
}

// merge groups findings across repositories by fingerprint.
func merge(results []scan.Result) []scan.Finding {
	byFP := map[string]*scan.Finding{}
	var order []string
	for _, r := range results {
		for _, f := range r.Findings {
			m, ok := byFP[f.Fingerprint]
			if !ok {
				cp := f
				cp.Locations = nil
				byFP[f.Fingerprint] = &cp
				m = &cp
				order = append(order, f.Fingerprint)
			}
			m.Locations = append(m.Locations, f.Locations...)
			m.Occurrences += f.Occurrences
			if m.Verification == nil {
				m.Verification = f.Verification
			}
		}
	}
	out := make([]scan.Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, *byFP[fp])
	}
	scan.SortFindings(out)
	return out
}

func footer(s scan.Summary) string {
	parts := []string{fmt.Sprintf("%d %s", s.Repos, plural(s.Repos, "repository", "repositories"))}
	if s.Failed > 0 {
		parts = append(parts, fmt.Sprintf("%d failed", s.Failed))
	}
	if s.Skipped > 0 {
		parts = append(parts, fmt.Sprintf("%d skipped", s.Skipped))
	}
	parts = append(parts, fmt.Sprintf("%d objects", s.Objects), humanBytes(s.Bytes))
	return "in " + strings.Join(parts, ", ")
}

// Output is the JSON document written by JSON.
type Output struct {
	Summary summary       `json:"summary"`
	Results []scan.Result `json:"results"`
}

type summary struct {
	Repositories int   `json:"repositories"`
	Failed       int   `json:"failed"`
	Skipped      int   `json:"skipped"`
	Tokens       int   `json:"tokens"`
	Active       int   `json:"active"`
	Objects      int   `json:"objects"`
	Bytes        int64 `json:"bytes"`
}

// JSON writes results as one JSON document. Token values are redacted
// unless ShowSecrets is set.
func JSON(w io.Writer, results []scan.Result, o Options) error {
	s := scan.Summarize(results)
	out := Output{
		Summary: summary{Repositories: s.Repos, Failed: s.Failed, Skipped: s.Skipped, Tokens: s.Tokens, Active: s.Active, Objects: s.Objects, Bytes: s.Bytes},
		Results: make([]scan.Result, len(results)),
	}
	for i, r := range results {
		r.Findings = append([]scan.Finding(nil), r.Findings...)
		for j := range r.Findings {
			if o.ShowSecrets {
				r.Findings[j].Redacted = r.Findings[j].Token
			}
		}
		if r.Findings == nil {
			r.Findings = []scan.Finding{}
		}
		out.Results[i] = r
	}
	sort.SliceStable(out.Results, func(i, j int) bool { return len(out.Results[i].Findings) > len(out.Results[j].Findings) })
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func short(sha string) string {
	if len(sha) > 8 {
		return sha[:8]
	}
	return sha
}

func day(date string) string {
	if t, err := time.Parse(time.RFC3339, date); err == nil {
		return t.UTC().Format("2006-01-02")
	}
	if len(date) >= 10 {
		return date[:10]
	}
	return date
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<30:
		return fmt.Sprintf("%.1f GiB", float64(n)/float64(1<<30))
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MiB", float64(n)/float64(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KiB", float64(n)/float64(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
