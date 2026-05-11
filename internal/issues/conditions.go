package issues

import (
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// conditionTypesToWatch is the set of "is this resource healthy?"
// conditions that the generic CRD fallback flags when False. Order
// matters only for tiebreaking when multiple are False — first hit
// wins, which biases toward the most-fundamental signal.
//
// Curated from real CRDs across our integration matrix:
//
//   - Argo Application:   Synced, Healthy
//   - Flux HelmRelease:   Ready, Released
//   - Flux Kustomization: Ready, Reconciled
//   - cert-manager Cert:  Ready
//   - Knative Service:    Ready
//   - CNPG PostgresCluster: Ready, ContinuousArchiving
//   - Crossplane:         Ready, Synced
//   - KEDA ScaledObject:  Ready, Active
//   - Cluster API:        Ready, ControlPlaneReady, InfrastructureReady (CAPI has its own
//                          curated checker — generic fallback skips when CAPI is detected
//                          via the `cluster.x-k8s.io` group).
var conditionTypesToWatch = []string{
	"Ready",
	"Available",
	"Reconciled",
	"Healthy",
	"Synced",
	"Released",
}

// FindFalseCondition walks the unstructured object's status.conditions
// (with v1beta2 fallback path) and returns the first matching False
// condition. condTypes overrides the default watch list — pass nil to
// use conditionTypesToWatch.
//
// Mirrors the semantics of the closure in internal/k8s/problems.go's
// DetectCAPIProblems but lives here so the generic CRD fallback can
// share it without an import cycle.
func FindFalseCondition(obj *unstructured.Unstructured, condTypes ...string) (condType, reason, message string, since time.Duration, found bool) {
	if obj == nil {
		return "", "", "", 0, false
	}
	if len(condTypes) == 0 {
		condTypes = conditionTypesToWatch
	}
	now := time.Now()
	condSlices := [][]any{}
	if v1b2, ok, _ := unstructured.NestedSlice(obj.Object, "status", "v1beta2", "conditions"); ok {
		condSlices = append(condSlices, v1b2)
	}
	if v1b1, ok, _ := unstructured.NestedSlice(obj.Object, "status", "conditions"); ok {
		condSlices = append(condSlices, v1b1)
	}
	for _, conditions := range condSlices {
		for _, c := range conditions {
			cond, ok := c.(map[string]any)
			if !ok {
				continue
			}
			ct, _ := cond["type"].(string)
			status, _ := cond["status"].(string)
			if status != "False" {
				continue
			}
			for _, wanted := range condTypes {
				if ct == wanted {
					r, _ := cond["reason"].(string)
					m, _ := cond["message"].(string)
					var dur time.Duration
					if ts, _ := cond["lastTransitionTime"].(string); ts != "" {
						if t, err := time.Parse(time.RFC3339, ts); err == nil {
							dur = now.Sub(t)
						}
					}
					return ct, r, m, dur, true
				}
			}
		}
	}
	return "", "", "", 0, false
}
