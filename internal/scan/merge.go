package scan

// Merge groups the findings of all results by token, so a token that leaked
// into several repositories is one entry with every location. Active tokens
// come first.
func Merge(results []Result) []Finding {
	byFP := map[string]*Finding{}
	var order []string
	for _, r := range results {
		for _, f := range r.Findings {
			m, ok := byFP[f.Fingerprint]
			if !ok {
				cp := f
				cp.Locations = nil
				cp.Occurrences = 0
				byFP[f.Fingerprint] = &cp
				m = &cp
				order = append(order, f.Fingerprint)
			}
			m.Locations = append(m.Locations, f.Locations...)
			m.Occurrences += f.Occurrences
			if m.Verification == nil {
				m.Verification = f.Verification
			}
			if m.Revocation == "" {
				m.Revocation = f.Revocation
			}
			if m.Local == nil {
				m.Local = f.Local
			}
		}
	}
	out := make([]Finding, 0, len(order))
	for _, fp := range order {
		out = append(out, *byFP[fp])
	}
	SortFindings(out)
	return out
}

// AnnotateLocal marks every finding whose token is also configured on this
// machine, given the sources per fingerprint.
func AnnotateLocal(results []Result, local map[string][]string) {
	for i := range results {
		for j := range results[i].Findings {
			f := &results[i].Findings[j]
			f.Local = local[f.Fingerprint]
		}
	}
}
