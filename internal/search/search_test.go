package search

import (
	"context"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

type fakeProvider struct {
	typed   map[string][]runtime.Object
	dynamic map[schema.GroupVersionResource][]*unstructured.Unstructured
	kinds   map[schema.GroupVersionResource]string
}

func (f *fakeProvider) ListTyped(kind string, namespaces []string) ([]runtime.Object, error) {
	return f.typed[kind], nil
}

func (f *fakeProvider) ListDynamic(_ context.Context, gvr schema.GroupVersionResource, _ string) ([]*unstructured.Unstructured, error) {
	return f.dynamic[gvr], nil
}

func (f *fakeProvider) WatchedDynamic() []schema.GroupVersionResource {
	out := make([]schema.GroupVersionResource, 0, len(f.dynamic))
	for g := range f.dynamic {
		out = append(out, g)
	}
	return out
}

func (f *fakeProvider) KindForGVR(gvr schema.GroupVersionResource) string {
	return f.kinds[gvr]
}

func newPod(ns, name, image string, labels map[string]string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: image}},
		},
	}
}

func newDeploy(ns, name, image string, labels map[string]string) *appsv1.Deployment {
	return &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Namespace: ns, Name: name, Labels: labels},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "c", Image: image}},
				},
			},
		},
	}
}

func TestSearch_RanksExactNameAboveSubstring(t *testing.T) {
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"pods": {
				newPod("default", "redis-master-1", "redis:6.2", nil),
				newPod("default", "redis", "redis:7.0", nil),
				newPod("default", "other", "redis:6.2", nil),
			},
		},
	}
	res, err := Search(context.Background(), p, Parse("redis"), Options{Include: IncludeNone})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Hits) < 2 {
		t.Fatalf("expected ≥2 hits, got %+v", res.Hits)
	}
	if res.Hits[0].Name != "redis" {
		t.Fatalf("expected 'redis' first (exact name beats prefix), got %q", res.Hits[0].Name)
	}
}

func TestSearch_KindFilter(t *testing.T) {
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"pods":        {newPod("ns", "redis", "redis:6.2", nil)},
			"deployments": {newDeploy("ns", "redis", "redis:6.2", nil)},
		},
	}
	res, _ := Search(context.Background(), p, Parse("kind:Deployment redis"), Options{Include: IncludeNone})
	if len(res.Hits) != 1 || res.Hits[0].Kind != "Deployment" {
		t.Fatalf("expected single Deployment hit, got %+v", res.Hits)
	}
}

func TestSearch_ImageMatch(t *testing.T) {
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"pods": {
				newPod("ns", "anonymous-1", "redis:6.2", nil),
				newPod("ns", "anonymous-2", "nginx:1.21", nil),
			},
		},
	}
	res, _ := Search(context.Background(), p, Parse("image:redis"), Options{Include: IncludeNone})
	if len(res.Hits) != 1 || res.Hits[0].Name != "anonymous-1" {
		t.Fatalf("expected anonymous-1 only, got %+v", res.Hits)
	}
}

func TestSearch_LimitTruncates(t *testing.T) {
	pods := make([]runtime.Object, 0, 100)
	for i := 0; i < 100; i++ {
		pods = append(pods, newPod("ns", "pod-with-redis", "redis:6.2", nil))
	}
	p := &fakeProvider{typed: map[string][]runtime.Object{"pods": pods}}
	res, _ := Search(context.Background(), p, Parse("redis"), Options{Limit: 10, Include: IncludeNone})
	if len(res.Hits) != 10 {
		t.Fatalf("limit=10 not honored, got %d", len(res.Hits))
	}
	if res.Searched != 100 {
		t.Fatalf("searched=%d, expected 100", res.Searched)
	}
}

func TestSearch_DefaultSkipsEvents(t *testing.T) {
	// Events are skipped unless kind:Event is explicit.
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"events": {&corev1.Event{ObjectMeta: metav1.ObjectMeta{Name: "redis-event", Namespace: "ns"}}},
		},
	}
	res, _ := Search(context.Background(), p, Parse("redis"), Options{Include: IncludeNone})
	if len(res.Hits) != 0 {
		t.Fatalf("default search should skip events, got %+v", res.Hits)
	}
	res, _ = Search(context.Background(), p, Parse("kind:Event redis"), Options{Include: IncludeNone})
	if len(res.Hits) != 1 {
		t.Fatalf("kind:Event should opt in, got %+v", res.Hits)
	}
}

func TestSearch_DynamicCRD(t *testing.T) {
	gvr := schema.GroupVersionResource{Group: "postgresql.cnpg.io", Version: "v1", Resource: "clusters"}
	u := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "postgresql.cnpg.io/v1",
		"kind":       "Cluster",
		"metadata": map[string]any{
			"name":      "redis-pg",
			"namespace": "data",
			"labels":    map[string]any{"app": "redis-cache-store"},
		},
	}}
	p := &fakeProvider{
		dynamic: map[schema.GroupVersionResource][]*unstructured.Unstructured{gvr: {u}},
		kinds:   map[schema.GroupVersionResource]string{gvr: "Cluster"},
	}
	res, _ := Search(context.Background(), p, Parse("redis"), Options{Include: IncludeNone})
	if len(res.Hits) != 1 {
		t.Fatalf("expected 1 hit, got %+v", res.Hits)
	}
	if res.Hits[0].Group != "postgresql.cnpg.io" {
		t.Fatalf("group not propagated: %+v", res.Hits[0])
	}
}

func TestSearch_IncludeSummary(t *testing.T) {
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"pods": {newPod("ns", "redis", "redis:6.2", map[string]string{"app": "redis"})},
		},
	}
	res, _ := Search(context.Background(), p, Parse("redis"), Options{Include: IncludeSummary})
	if res.Hits[0].Summary == nil {
		t.Fatalf("expected summary, got %+v", res.Hits[0])
	}
	if res.Hits[0].Raw != nil {
		t.Fatalf("expected no raw, got %+v", res.Hits[0])
	}
}

func TestSearch_IncludeNoneIdentityOnly(t *testing.T) {
	p := &fakeProvider{
		typed: map[string][]runtime.Object{
			"pods": {newPod("ns", "redis", "redis:6.2", nil)},
		},
	}
	res, _ := Search(context.Background(), p, Parse("redis"), Options{Include: IncludeNone})
	if res.Hits[0].Summary != nil || res.Hits[0].Raw != nil {
		t.Fatalf("IncludeNone should leave both empty, got %+v", res.Hits[0])
	}
	if res.Hits[0].Name != "redis" {
		t.Fatalf("identity missing: %+v", res.Hits[0])
	}
}
