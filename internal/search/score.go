package search

import "strings"

// Site scoring weights. Tuned by intuition; revisit when telemetry exists.
const (
	scoreNameExact      = 100
	scoreNamePrefix     = 60
	scoreNameSubstr     = 40
	scoreNSExact        = 30
	scoreNSSubstr       = 20
	scoreLabelValExact  = 25
	scoreLabelValSubstr = 18
	scoreAnnoSubstr     = 15
	scoreImageSubstr    = 20
	scoreKindExact      = 10
	scoreKindSubstr     = 5
)

// candidate carries the searchable face of a K8s object: identity,
// labels, annotations, container images. Built once per object so we
// don't repeatedly walk K8s typed structs.
type candidate struct {
	Kind        string
	Group       string
	Namespace   string
	Name        string
	Labels      map[string]string
	Annotations map[string]string
	Images      []string
}

// match runs the parsed query against a candidate and returns the score
// plus which sites matched. Returns (0, nil, false) when filters reject
// the candidate or when at least one free token didn't land anywhere.
func match(q Query, c candidate) (int, []MatchedField, bool) {
	// Hard filters first — cheaper to reject early.
	if len(q.KindFilter) > 0 && !kindMatches(c.Kind, q.KindFilter) {
		return 0, nil, false
	}
	if len(q.NSFilter) > 0 && !sliceContainsFold(q.NSFilter, c.Namespace) {
		return 0, nil, false
	}
	for _, lf := range q.LabelFilter {
		v, ok := c.Labels[lf.Key]
		if !ok {
			return 0, nil, false
		}
		if lf.Value != "" && v != lf.Value {
			return 0, nil, false
		}
	}
	for _, img := range q.ImageFilter {
		if !anyContainsFold(c.Images, img) {
			return 0, nil, false
		}
	}

	if len(q.Tokens) == 0 {
		// Pure-filter query: no scoring signal, but the candidate passed
		// every filter, so return a flat score so it shows up.
		return 1, nil, true
	}

	total := 0
	var matched []MatchedField
	for _, tok := range q.Tokens {
		best, site, ok := scoreToken(tok, c)
		if !ok {
			return 0, nil, false
		}
		total += best
		matched = append(matched, MatchedField{Token: tok, Site: site, Score: best})
	}
	return total, matched, true
}

// scoreToken returns the highest-scoring site a single free token matches,
// or (0, "", false) if the token doesn't land on any searchable field.
func scoreToken(tok string, c candidate) (int, string, bool) {
	low := strings.ToLower(tok)
	best := 0
	bestSite := ""
	consider := func(score int, site string) {
		if score > best {
			best = score
			bestSite = site
		}
	}

	if c.Name != "" {
		nameLow := strings.ToLower(c.Name)
		switch {
		case nameLow == low:
			consider(scoreNameExact, "name")
		case strings.HasPrefix(nameLow, low):
			consider(scoreNamePrefix, "name")
		case strings.Contains(nameLow, low):
			consider(scoreNameSubstr, "name")
		}
	}
	if c.Namespace != "" {
		nsLow := strings.ToLower(c.Namespace)
		switch {
		case nsLow == low:
			consider(scoreNSExact, "namespace")
		case strings.Contains(nsLow, low):
			consider(scoreNSSubstr, "namespace")
		}
	}
	for k, v := range c.Labels {
		vLow := strings.ToLower(v)
		switch {
		case vLow == low:
			consider(scoreLabelValExact, "label:"+k)
		case strings.Contains(vLow, low):
			consider(scoreLabelValSubstr, "label:"+k)
		}
	}
	for k, v := range c.Annotations {
		if strings.Contains(strings.ToLower(v), low) {
			consider(scoreAnnoSubstr, "annotation:"+k)
		}
	}
	for _, img := range c.Images {
		if strings.Contains(strings.ToLower(img), low) {
			consider(scoreImageSubstr, "image")
		}
	}
	if c.Kind != "" {
		kindLow := strings.ToLower(c.Kind)
		switch {
		case kindLow == low:
			consider(scoreKindExact, "kind")
		case strings.Contains(kindLow, low):
			consider(scoreKindSubstr, "kind")
		}
	}

	if best == 0 {
		return 0, "", false
	}
	return best, bestSite, true
}

// kindMatches returns true if any of the kind filters refer to the candidate kind.
// Filters are case-insensitive and accept either the singular Kind ("Pod") or the
// lowercase plural resource ("pods"). Trailing-s pluralization is the only tolerance.
func kindMatches(kind string, filters []string) bool {
	low := strings.ToLower(kind)
	plural := low + "s"
	for _, f := range filters {
		fLow := strings.ToLower(f)
		if fLow == low || fLow == plural || fLow+"s" == plural || fLow == strings.TrimSuffix(low, "s") {
			return true
		}
	}
	return false
}

func sliceContainsFold(haystack []string, needle string) bool {
	for _, h := range haystack {
		if strings.EqualFold(h, needle) {
			return true
		}
	}
	return false
}

func anyContainsFold(haystack []string, needle string) bool {
	low := strings.ToLower(needle)
	for _, h := range haystack {
		if strings.Contains(strings.ToLower(h), low) {
			return true
		}
	}
	return false
}
