package server

import (
	"context"
	"net/http"
	"sync"

	"github.com/skyhook-io/radar/internal/auth"
	"github.com/skyhook-io/radar/internal/k8s"
	pkgauth "github.com/skyhook-io/radar/pkg/auth"
)

// sensitiveSearchKinds enumerates kinds whose default presence in
// /api/search results would leak information beyond what the calling
// user can fetch via /api/resources/{kind} under their own RBAC.
// Secrets are sensitive even when redacted (names, label keys, env-
// var names already enough for a recon foothold). Cluster-scoped
// kinds (Node, PersistentVolume, StorageClass, Namespace) imply
// cluster-wide read which a namespace-bounded Cloud viewer doesn't
// have.
//
// The walker in internal/search consults Options.SkipKinds, populated
// by SAR per (user, kind) at cluster scope. Users without `list X`
// at cluster scope have X dropped from the scan — including for
// explicit `kind:X` queries, which return zero hits silently.
// Trade-off: a user with per-namespace `list secrets` permission
// loses /api/search coverage for secrets; they can still hit
// /api/resources/secrets?namespace=X directly, which the cache layer
// handles with its own SA-level gating. Deemed acceptable for v1.
// Per-namespace SAR fanout (one SAR per requested namespace per
// kind) is a follow-up if customer evidence demands it.
var sensitiveSearchKinds = []struct {
	Kind     string // singular Kind for SkipKinds map
	Resource string // plural for SAR ResourceAttributes
	Group    string // API group; empty for core
}{
	{"Secret", "secrets", ""},
	{"Node", "nodes", ""},
	{"PersistentVolume", "persistentvolumes", ""},
	{"StorageClass", "storageclasses", "storage.k8s.io"},
	{"Namespace", "namespaces", ""},
}

// computeSearchSkipKinds runs SARs for each sensitive kind and
// returns a SkipKinds map suitable for search.Options. Returns nil
// when there's no user identity (auth-mode=none) — the SA's own
// permissions apply via the cache layer, no extra gating needed.
//
// SARs run in parallel; a single failure (k8s API blip) is treated
// as "deny that kind" rather than failing the whole search — fail-
// closed is the safer default for sensitive data.
func (s *Server) computeSearchSkipKinds(r *http.Request) map[string]bool {
	user := auth.UserFromContext(r.Context())
	if user == nil {
		// auth.mode=none — no end-user identity, SA RBAC is the only
		// authorization layer. Cache lister already returns "forbidden"
		// when the SA can't list. Nothing for us to add.
		return nil
	}
	client := k8s.GetClient()
	if client == nil {
		// Defensive: cache client not initialized. Fail closed on all
		// sensitive kinds rather than silently leaking through.
		out := make(map[string]bool, len(sensitiveSearchKinds))
		for _, k := range sensitiveSearchKinds {
			out[k.Kind] = true
		}
		return out
	}

	type result struct {
		kind    string
		allowed bool
	}
	results := make(chan result, len(sensitiveSearchKinds))
	var wg sync.WaitGroup
	for _, k := range sensitiveSearchKinds {
		wg.Add(1)
		go func(kind, resource, group string) {
			defer wg.Done()
			// Cluster-scope SAR: namespace="" means "any namespace"
			// for namespaced resources and "the resource itself" for
			// cluster-scoped — both are the right shape for "can the
			// user enumerate this kind at all."
			allowed, err := pkgauth.SubjectCanI(r.Context(), client, user.Username, user.Groups, "", group, resource, "list")
			if err != nil {
				// SAR API itself failed (rare). Treat as deny.
				results <- result{kind: kind, allowed: false}
				return
			}
			results <- result{kind: kind, allowed: allowed}
		}(k.Kind, k.Resource, k.Group)
	}
	wg.Wait()
	close(results)

	skip := make(map[string]bool, len(sensitiveSearchKinds))
	for r := range results {
		if !r.allowed {
			skip[r.kind] = true
		}
	}
	return skip
}

// _ context.Context — kept to make ctx threading explicit if a future
// caller passes one in without an http.Request.
var _ context.Context
