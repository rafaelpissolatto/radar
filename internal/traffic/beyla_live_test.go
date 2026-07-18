//go:build livebeyla

// Live validation against a real Beyla + Prometheus-compatible backend.
// Excluded from the normal build; run explicitly:
//
//	kubectl port-forward -n monitoring svc/mimir-monolithic 8090:8080
//	go test -tags livebeyla -v ./internal/traffic/ -run TestLive \
//	  -beyla-url=http://localhost:8090 -beyla-basepath=/prometheus \
//	  -beyla-header=X-Scope-OrgID:anonymous
package traffic

import (
	"context"
	"flag"
	"net/http"
	"strings"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/skyhook-io/radar/pkg/prom"
)

var (
	liveURL      = flag.String("beyla-url", "http://localhost:8090", "Prometheus-compatible base URL")
	liveBasePath = flag.String("beyla-basepath", "/prometheus", "API base path")
	liveHeader   = flag.String("beyla-header", "", "extra header as Key:Value")
)

func liveSource(t *testing.T) *BeylaSource {
	t.Helper()
	tr := prom.NewHTTPTransport(*liveURL, *liveBasePath, &http.Client{Timeout: 20 * time.Second})
	if *liveHeader != "" {
		k, v, ok := strings.Cut(*liveHeader, ":")
		if !ok {
			t.Fatalf("bad -beyla-header %q, want Key:Value", *liveHeader)
		}
		tr.Headers = map[string]string{k: v}
	}
	client := prom.NewClient(tr)

	s := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	s.queryFn = func(ctx context.Context, q string) (*prom.QueryResult, error) {
		return client.Query(ctx, q)
	}
	return s
}

func TestLiveBeyla_Detect(t *testing.T) {
	res, err := liveSource(t).Detect(context.Background())
	if err != nil {
		t.Fatalf("Detect: %v", err)
	}
	t.Logf("available=%v native=%v version=%q message=%q", res.Available, res.Native, res.Version, res.Message)
	if !res.Available {
		t.Fatal("expected Beyla to be detected")
	}
}

func TestLiveBeyla_GetFlows(t *testing.T) {
	resp, err := liveSource(t).GetFlows(context.Background(), FlowOptions{})
	if err != nil {
		t.Fatalf("GetFlows: %v", err)
	}
	if resp.Warning != "" {
		t.Fatalf("query failed: %s", resp.Warning)
	}
	t.Logf("%d flows", len(resp.Flows))
	for _, f := range resp.Flows {
		if f.Source.Namespace == "demo-frontend" || f.Destination.Namespace == "demo-backend" {
			t.Logf("  %s/%s (%s) -> %s/%s (%s) port=%d proto=%s bytes=%d l7=%s %s %s",
				f.Source.Namespace, f.Source.Name, f.Source.Kind,
				f.Destination.Namespace, f.Destination.Name, f.Destination.Kind,
				f.Port, f.Protocol, f.BytesSent, f.L7Protocol, f.HTTPMethod, f.HTTPPath)
		}
	}
	if len(resp.Flows) == 0 {
		t.Fatal("expected at least one flow")
	}
}

// The pre-fix namespace filter emitted `... and (k8s_src_namespace="x" or ...)`,
// which is a PromQL parse error rather than an empty result.
func TestLiveBeyla_NamespaceFilter(t *testing.T) {
	src := liveSource(t)
	for _, ns := range []string{"demo-backend", "demo-frontend"} {
		resp, err := src.GetFlows(context.Background(), FlowOptions{Namespace: ns})
		if err != nil {
			t.Fatalf("GetFlows(%s): %v", ns, err)
		}
		if resp.Warning != "" {
			t.Fatalf("namespace %q query failed: %s", ns, resp.Warning)
		}
		for _, f := range resp.Flows {
			if f.Source.Namespace != ns && f.Destination.Namespace != ns {
				t.Errorf("namespace %q: flow leaked in: %s/%s -> %s/%s",
					ns, f.Source.Namespace, f.Source.Name, f.Destination.Namespace, f.Destination.Name)
			}
		}
		t.Logf("namespace %-14s -> %d flows", ns, len(resp.Flows))
		if len(resp.Flows) == 0 {
			t.Errorf("namespace %q returned no flows", ns)
		}
	}
}
