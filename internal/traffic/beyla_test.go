package traffic

import (
	"context"
	"fmt"
	"strings"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"

	"github.com/skyhook-io/radar/pkg/prom"
)

func TestBeylaSource_Detect_MetricProbe(t *testing.T) {
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, query string) (*prom.QueryResult, error) {
		if strings.Contains(query, "beyla_network_flow_bytes_total") {
			return promResult("vector", promSeries(map[string]string{}, 42)), nil
		}
		if strings.Contains(query, "beyla_build_info") {
			return promResult("vector", promSeries(map[string]string{"version": "1.0.0"}, 1)), nil
		}
		return emptyResult(), nil
	}

	result, err := src.Detect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Available {
		t.Fatal("expected available=true")
	}
	if result.Native {
		t.Error("expected Native=false")
	}
	if result.Version != "1.0.0" {
		t.Errorf("version = %q, want %q", result.Version, "1.0.0")
	}
}

func TestBeylaSource_Detect_LabelFallback_Alloy(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "alloy-abc",
			Namespace: "monitoring",
			Labels:    map[string]string{"app.kubernetes.io/name": "alloy"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset(pod)}
	src.queryFn = func(_ context.Context, _ string) (*prom.QueryResult, error) {
		return nil, fmt.Errorf("prometheus not available")
	}

	result, err := src.Detect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Available {
		t.Fatal("expected available=true via label fallback")
	}
}

func TestBeylaSource_Detect_LabelFallback_Beyla(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "beyla-xyz",
			Namespace: "default",
			Labels:    map[string]string{"app.kubernetes.io/name": "beyla"},
		},
		Status: corev1.PodStatus{Phase: corev1.PodRunning},
	}
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset(pod)}
	src.queryFn = func(_ context.Context, _ string) (*prom.QueryResult, error) {
		return nil, fmt.Errorf("prometheus not available")
	}

	result, err := src.Detect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Available {
		t.Fatal("expected available=true via standalone beyla label fallback")
	}
}

func TestBeylaSource_Detect_NotAvailable(t *testing.T) {
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, _ string) (*prom.QueryResult, error) {
		return nil, fmt.Errorf("prometheus not available")
	}

	result, err := src.Detect(context.Background())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Available {
		t.Fatal("expected available=false")
	}
}

func TestBeylaSource_GetFlows_OwnerLevel(t *testing.T) {
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, query string) (*prom.QueryResult, error) {
		if strings.Contains(query, "beyla_network_flow_bytes_total") {
			return promResult("vector", promSeries(map[string]string{
				"k8s_src_owner_name": "frontend", "k8s_src_namespace": "web",
				"k8s_src_owner_type": "Deployment",
				"k8s_dst_owner_name": "backend", "k8s_dst_namespace": "api",
				"k8s_dst_owner_type": "Deployment",
				"dst_port": "8080", "transport": "TCP",
			}, 15.5)), nil
		}
		return emptyResult(), nil
	}

	resp, err := src.GetFlows(context.Background(), FlowOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(resp.Flows))
	}
	f := resp.Flows[0]
	assertEq(t, "source name", f.Source.Name, "frontend")
	assertEq(t, "source namespace", f.Source.Namespace, "web")
	assertEq(t, "source kind", f.Source.Kind, "Workload")
	assertEq(t, "dest name", f.Destination.Name, "backend")
	assertEq(t, "dest kind", f.Destination.Kind, "Workload")
	assertEq(t, "port", fmt.Sprintf("%d", f.Port), "8080")
	assertEq(t, "protocol", f.Protocol, "tcp")
	assertEq(t, "verdict", f.Verdict, "forwarded")
	if f.Connections == 0 {
		t.Error("expected non-zero connections")
	}
}

func TestBeylaSource_GetFlows_ExtendedLabels(t *testing.T) {
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, query string) (*prom.QueryResult, error) {
		if strings.Contains(query, "beyla_network_flow_bytes_total") {
			return emptyResult(), nil
		}
		return promResult("vector", promSeries(map[string]string{
			"k8s_src_owner_name": "frontend", "k8s_src_namespace": "web",
			"k8s_dst_owner_name": "backend", "k8s_dst_namespace": "api",
			"http_method": "GET", "http_route": "/api/users", "http_status_code": "200",
		}, 8.0)), nil
	}

	resp, err := src.GetFlows(context.Background(), FlowOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Flows) != 1 {
		t.Fatalf("expected 1 L7-only flow, got %d", len(resp.Flows))
	}
	f := resp.Flows[0]
	assertEq(t, "httpMethod", f.HTTPMethod, "GET")
	assertEq(t, "httpPath", f.HTTPPath, "/api/users")
	assertEq(t, "httpStatus", fmt.Sprintf("%d", f.HTTPStatus), "200")
	assertEq(t, "l7Protocol", f.L7Protocol, "HTTP")
}

func TestBeylaSource_GetFlows_L4PlusL7(t *testing.T) {
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, query string) (*prom.QueryResult, error) {
		if strings.Contains(query, "beyla_network_flow_bytes_total") {
			return promResult("vector", promSeries(map[string]string{
				"k8s_src_owner_name": "frontend", "k8s_src_namespace": "web",
				"k8s_dst_owner_name": "backend", "k8s_dst_namespace": "api",
				"dst_port": "8080", "transport": "TCP",
			}, 10.0)), nil
		}
		return promResult("vector", promSeries(map[string]string{
			"k8s_src_owner_name": "frontend", "k8s_src_namespace": "web",
			"k8s_dst_owner_name": "backend", "k8s_dst_namespace": "api",
			"http_method": "POST", "http_route": "/api/orders", "http_status_code": "201",
		}, 5.0)), nil
	}

	resp, err := src.GetFlows(context.Background(), FlowOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Flows) != 1 {
		t.Fatalf("expected 1 merged flow, got %d", len(resp.Flows))
	}
	f := resp.Flows[0]
	assertEq(t, "httpMethod", f.HTTPMethod, "POST")
	assertEq(t, "port", fmt.Sprintf("%d", f.Port), "8080")
}

func TestBeylaSource_GetFlows_NamespaceFilter(t *testing.T) {
	var capturedQuery string
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, query string) (*prom.QueryResult, error) {
		capturedQuery = query
		return emptyResult(), nil
	}

	_, err := src.GetFlows(context.Background(), FlowOptions{Namespace: "test-ns"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(capturedQuery, "test-ns") {
		t.Errorf("expected namespace filter in query, got: %s", capturedQuery)
	}
}

func TestBeylaSource_GetFlows_FallbackToOwner(t *testing.T) {
	src := &BeylaSource{k8sClient: fake.NewSimpleClientset()}
	src.queryFn = func(_ context.Context, query string) (*prom.QueryResult, error) {
		if strings.Contains(query, "beyla_network_flow_bytes_total") {
			return promResult("vector", promSeries(map[string]string{
				"k8s_src_owner_name": "api", "k8s_src_namespace": "backend",
				"k8s_dst_owner_name": "db", "k8s_dst_namespace": "data",
				"k8s_src_owner_type": "Deployment", "k8s_dst_owner_type": "StatefulSet",
				"dst_port": "5432", "transport": "TCP",
			}, 3.0)), nil
		}
		return emptyResult(), nil
	}

	resp, err := src.GetFlows(context.Background(), FlowOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.Flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(resp.Flows))
	}
	f := resp.Flows[0]
	assertEq(t, "source kind", f.Source.Kind, "Workload")
	assertEq(t, "dest kind", f.Destination.Kind, "Workload")
	assertEq(t, "port", fmt.Sprintf("%d", f.Port), "5432")
}

func TestBeylaSource_MapBeylaKind(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"Pod", "Pod"}, {"Deployment", "Workload"}, {"ReplicaSet", "Workload"},
		{"StatefulSet", "Workload"}, {"DaemonSet", "Workload"}, {"Service", "Service"},
		{"Unknown", "Pod"}, {"pod", "Pod"}, {"deployment", "Workload"},
	}
	for _, tt := range tests {
		if got := mapBeylaKind(tt.input); got != tt.want {
			t.Errorf("mapBeylaKind(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestBeylaSource_MapBeylaTransport(t *testing.T) {
	tests := []struct {
		input, want string
	}{
		{"TCP", "tcp"}, {"UDP", "udp"}, {"tcp", "tcp"}, {"Tcp", "tcp"}, {"", "tcp"},
	}
	for _, tt := range tests {
		if got := mapBeylaTransport(tt.input); got != tt.want {
			t.Errorf("mapBeylaTransport(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestManager_DetectSources_IncludesBeyla(t *testing.T) {
	m := &Manager{sources: make(map[string]TrafficSource)}
	m.sources["beyla"] = NewBeylaSource(fake.NewSimpleClientset())
	if _, ok := m.sources["beyla"]; !ok {
		t.Fatal("expected 'beyla' in sources map")
	}
}

func TestBeylaSource_QueryL4_NamespaceFilterIsValidPromQL(t *testing.T) {
	q := beylaRateQuery(beylaL4GroupBy, "beyla_network_flow_bytes_total", "test-ns")
	if !strings.Contains(q, `k8s_src_namespace="test-ns"}`) || !strings.Contains(q, `k8s_dst_namespace="test-ns"}`) {
		t.Errorf("namespace matchers must live inside the label selector, got: %s", q)
	}
	if strings.Contains(q, " and (") {
		t.Errorf("bare label matchers after `and` are not valid PromQL, got: %s", q)
	}
}

// --- test helpers ---

func promResult(resultType string, series ...prom.Series) *prom.QueryResult {
	return &prom.QueryResult{ResultType: resultType, Series: series}
}

func promSeries(labels map[string]string, value float64) prom.Series {
	return prom.Series{
		Labels:     labels,
		DataPoints: []prom.DataPoint{{Value: value}},
	}
}

func emptyResult() *prom.QueryResult {
	return &prom.QueryResult{ResultType: "vector", Series: []prom.Series{}}
}

func assertEq(t *testing.T, label, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("%s = %q, want %q", label, got, want)
	}
}
