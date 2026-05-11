package search

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

// SkipKinds gates kinds the calling user's RBAC excludes — even when
// the underlying SA-driven cache holds the objects. The handler
// populates SkipKinds via SARs; these tests pin the walker contract
// that consumes the map.

func TestSearch_SkipKinds_DropsKindEntirely(t *testing.T) {
	// Secret is in the cache; SAR said no — the row must not surface
	// even when the user explicitly types kind:Secret.
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"secrets": {
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db-cred"}},
			},
			"pods": {
				&corev1.Pod{
					ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db-cred-loader"},
					Spec:       corev1.PodSpec{Containers: []corev1.Container{{Name: "c", Image: "redis"}}},
				},
			},
		},
	}
	opts := Options{
		Include:   IncludeNone,
		SkipKinds: map[string]bool{"Secret": true},
	}
	// Default-scan: pods come through, secret excluded.
	res, _ := Search(context.Background(), p, Parse("db-cred"), opts)
	for _, h := range res.Hits {
		if h.Kind == "Secret" {
			t.Fatalf("Secret leaked into default search despite SkipKinds: %+v", h)
		}
	}
	// Explicit kind:Secret request: still zero (silent — same as RBAC
	// forbidden on the lister today).
	res, _ = Search(context.Background(), p, Parse("kind:Secret db-cred"), opts)
	if len(res.Hits) != 0 {
		t.Fatalf("kind:Secret returned hits despite SkipKinds: %+v", res.Hits)
	}
}

func TestSearch_SkipKinds_NilMapIsNoOp(t *testing.T) {
	// Empty/nil SkipKinds preserves the default scan — backward
	// compat for auth-mode=none / non-cloud installs.
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"secrets": {
				&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "db-cred"}},
			},
		},
	}
	res, _ := Search(context.Background(), p, Parse("db-cred"), Options{Include: IncludeNone, SkipKinds: nil})
	if len(res.Hits) == 0 {
		t.Fatal("nil SkipKinds should not gate Secrets")
	}
}

func TestSearch_SkipKinds_PreservesOtherKinds(t *testing.T) {
	// Skipping Secret must NOT affect Deployments / Pods scanning.
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"secrets":     {&corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: "ns", Name: "redis-cred"}}},
			"deployments": {newDeploy("ns", "redis-cache", "redis:6", nil)},
		},
	}
	res, _ := Search(context.Background(), p, Parse("redis"), Options{
		Include:   IncludeNone,
		SkipKinds: map[string]bool{"Secret": true, "Node": true, "PersistentVolume": true},
	})
	var kinds []string
	for _, h := range res.Hits {
		kinds = append(kinds, h.Kind)
	}
	if len(kinds) != 1 || kinds[0] != "Deployment" {
		t.Fatalf("expected only Deployment, got %v", kinds)
	}
}

// Keep appsv1 referenced so future test cases retain the import without
// linter churn.
var _ = appsv1.SchemeGroupVersion
