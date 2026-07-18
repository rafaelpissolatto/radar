package traffic

import (
	"context"
	"fmt"
	"log"
	"strconv"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"

	"github.com/skyhook-io/radar/internal/portforward"
	promclient "github.com/skyhook-io/radar/internal/prometheus"
	"github.com/skyhook-io/radar/pkg/prom"
)

const (
	beylaJobRegex = `job=~".*beyla.*|.*alloy.*"`
	// Rate window in the PromQL queries; used to turn per-second rates back
	// into absolute counts for the window.
	beylaRateWindowSeconds = 300
)

type promQueryFunc func(ctx context.Context, query string) (*prom.QueryResult, error)

// BeylaSource implements TrafficSource for Grafana Beyla via Prometheus metrics.
type BeylaSource struct {
	k8sClient kubernetes.Interface
	queryFn   promQueryFunc
}

// NewBeylaSource creates a new Beyla traffic source wired to the shared Prometheus client.
func NewBeylaSource(client kubernetes.Interface) *BeylaSource {
	s := &BeylaSource{k8sClient: client}
	s.queryFn = s.defaultQuery
	return s
}

func (s *BeylaSource) Name() string { return "beyla" }

func (s *BeylaSource) defaultQuery(ctx context.Context, query string) (*prom.QueryResult, error) {
	client := promclient.GetClient()
	if client == nil {
		return nil, fmt.Errorf("prometheus client not initialized")
	}
	return client.Query(ctx, query)
}

func (s *BeylaSource) query(ctx context.Context, query string) (*prom.QueryResult, error) {
	return s.queryFn(ctx, query)
}

// Connect delegates to the shared Prometheus client's EnsureConnected.
func (s *BeylaSource) Connect(ctx context.Context, contextName string) (*portforward.ConnectionInfo, error) {
	client := promclient.GetClient()
	if client == nil {
		return &portforward.ConnectionInfo{Connected: false, Error: "Prometheus client not initialized"}, nil
	}
	_, _, err := client.EnsureConnected(ctx)
	if err != nil {
		return &portforward.ConnectionInfo{Connected: false, Error: fmt.Sprintf("Failed to connect to Prometheus: %v", err)}, nil
	}
	status := client.GetStatus()
	info := &portforward.ConnectionInfo{Connected: true, Address: status.Address, ContextName: contextName}
	if status.Service != nil {
		info.Namespace = status.Service.Namespace
		info.ServiceName = status.Service.Name
	}
	return info, nil
}

func (s *BeylaSource) Close() error { return nil }

func (s *BeylaSource) Detect(ctx context.Context) (*DetectionResult, error) {
	result := &DetectionResult{Available: false}

	// Phase 1: metric probe via Prometheus. Scoped to the same jobs the flow
	// queries read, so detection can't succeed on metrics GetFlows won't see.
	qr, err := s.query(ctx, fmt.Sprintf(`count(beyla_network_flow_bytes_total{%s})`, beylaJobRegex))
	if err == nil && qr != nil && len(qr.Series) > 0 {
		result.Available = true
		result.Native = false
		result.Message = "Beyla detected via Prometheus metrics"
		result.Version = s.detectVersion(ctx)
		return result, nil
	}

	// Phase 2: pod label fallback
	if pods := s.countBeylaPods(ctx); pods > 0 {
		result.Available = true
		result.Native = false
		result.Message = fmt.Sprintf("Beyla detected via %d running pod(s) (Alloy or standalone)", pods)
		return result, nil
	}

	result.Message = "Beyla not detected. Install Alloy + Beyla for L7 traffic visibility."
	return result, nil
}

func (s *BeylaSource) detectVersion(ctx context.Context) string {
	qr, err := s.query(ctx, `beyla_build_info`)
	if err != nil {
		return ""
	}
	for _, series := range qr.Series {
		if v := series.Labels["version"]; v != "" {
			return v
		}
		if v := series.Labels["beyla_version"]; v != "" {
			return v
		}
	}
	return ""
}

func (s *BeylaSource) countBeylaPods(ctx context.Context) int {
	count := 0
	for _, label := range []string{"app.kubernetes.io/name=alloy", "app.kubernetes.io/name=beyla"} {
		pods, err := s.k8sClient.CoreV1().Pods("").List(ctx, metav1.ListOptions{LabelSelector: label})
		if err != nil {
			log.Printf("[beyla] Failed to list pods matching %s: %v", label, err)
			continue
		}
		for i := range pods.Items {
			if pods.Items[i].Status.Phase == corev1.PodRunning {
				count++
			}
		}
	}
	return count
}

// l4Key uniquely identifies an L4 flow for dedup.
type l4Key struct {
	srcNs, srcName string
	dstNs, dstName string
	dstPort        int
}

// noPortKey identifies a service-pair ignoring port — used to match L7 results
// (which lack dst_port) against L4 flows.
type noPortKey struct {
	srcNs, srcName string
	dstNs, dstName string
}

func (s *BeylaSource) GetFlows(ctx context.Context, opts FlowOptions) (*FlowsResponse, error) {
	flows, err := s.getFlowsInternal(ctx, opts)
	if err != nil {
		log.Printf("[beyla] Error fetching flows: %v", err)
		return &FlowsResponse{Source: "beyla", Timestamp: time.Now(), Flows: []Flow{},
			Warning: fmt.Sprintf("Failed to query Beyla metrics: %v", err)}, nil
	}
	return &FlowsResponse{Source: "beyla", Timestamp: time.Now(), Flows: flows}, nil
}

func (s *BeylaSource) getFlowsInternal(ctx context.Context, opts FlowOptions) ([]Flow, error) {
	l4Flows, err := s.queryL4(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("L4 query: %w", err)
	}

	l7Flows, err := s.queryL7(ctx, opts)
	if err != nil {
		log.Printf("[beyla] L7 query failed (continuing with L4 only): %v", err)
		l7Flows = nil
	}

	l4Map := make(map[l4Key]*Flow, len(l4Flows))
	byPair := make(map[noPortKey]*Flow, len(l4Flows))
	for i := range l4Flows {
		f := &l4Flows[i]
		l4Map[l4FlowKey(f)] = f
		byPair[noPortKey{f.Source.Namespace, f.Source.Name, f.Destination.Namespace, f.Destination.Name}] = f
	}

	// Merge L7 into L4 by service-pair only (L7 metrics lack dst_port). A pair
	// usually has several L7 series (one per route/method/status) but only one
	// set of L7 fields to fill, so pick the busiest rather than whichever the
	// map iteration happens to land on last.
	for _, l7 := range busiestL7PerPair(l7Flows) {
		pair := noPortKey{l7.Source.Namespace, l7.Source.Name, l7.Destination.Namespace, l7.Destination.Name}
		if existing, ok := byPair[pair]; ok {
			existing.L7Protocol = l7.L7Protocol
			existing.HTTPMethod = l7.HTTPMethod
			existing.HTTPPath = l7.HTTPPath
			existing.HTTPStatus = l7.HTTPStatus
			existing.RequestRate = l7.RequestRate
		} else {
			k := l4FlowKey(&l7)
			l4Map[k] = &l7
			byPair[pair] = &l7
		}
	}

	result := make([]Flow, 0, len(l4Map))
	for _, f := range l4Map {
		result = append(result, *f)
	}
	return result, nil
}

func busiestL7PerPair(l7Flows []Flow) []Flow {
	best := make(map[noPortKey]Flow, len(l7Flows))
	topRate := make(map[noPortKey]float64, len(l7Flows))
	for _, f := range l7Flows {
		pair := noPortKey{f.Source.Namespace, f.Source.Name, f.Destination.Namespace, f.Destination.Name}
		cur, ok := best[pair]
		if !ok {
			best[pair], topRate[pair] = f, f.RequestRate
			continue
		}
		// Rates and counts cover the whole pair; the route/method/status shown
		// is the busiest single series.
		if f.RequestRate > topRate[pair] {
			topRate[pair] = f.RequestRate
			cur.HTTPMethod, cur.HTTPPath, cur.HTTPStatus = f.HTTPMethod, f.HTTPPath, f.HTTPStatus
		}
		cur.RequestRate += f.RequestRate
		cur.Connections += f.Connections
		best[pair] = cur
	}
	out := make([]Flow, 0, len(best))
	for _, f := range best {
		out = append(out, f)
	}
	return out
}

func l4FlowKey(f *Flow) l4Key {
	return l4Key{
		srcNs: f.Source.Namespace, srcName: f.Source.Name,
		dstNs: f.Destination.Namespace, dstName: f.Destination.Name,
		dstPort: f.Port,
	}
}

const (
	beylaL4GroupBy = `k8s_src_owner_name, k8s_src_namespace, k8s_src_owner_type, k8s_dst_owner_name, k8s_dst_namespace, k8s_dst_owner_type, dst_port, transport`
	beylaL7GroupBy = `k8s_src_owner_name, k8s_src_namespace, k8s_dst_owner_name, k8s_dst_namespace, http_method, http_route, http_status_code`
)

// beylaRateQuery builds `sum by (groupBy) (rate(metric{job=~...}[5m]))`. A
// namespace filter has to become two OR'd selectors: PromQL cannot express
// "src OR dst namespace matches" inside a single label selector.
func beylaRateQuery(groupBy, metric, namespace string) string {
	sum := func(extra string) string {
		return fmt.Sprintf(`sum by (%s) (rate(%s{%s%s}[5m]))`, groupBy, metric, beylaJobRegex, extra)
	}
	if namespace == "" {
		return sum("")
	}
	return sum(fmt.Sprintf(`, k8s_src_namespace=%q`, namespace)) + " or " +
		sum(fmt.Sprintf(`, k8s_dst_namespace=%q`, namespace))
}

func (s *BeylaSource) queryL4(ctx context.Context, opts FlowOptions) ([]Flow, error) {
	query := beylaRateQuery(beylaL4GroupBy, "beyla_network_flow_bytes_total", opts.Namespace)
	result, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	return s.parseFlows(result, false), nil
}

func (s *BeylaSource) queryL7(ctx context.Context, opts FlowOptions) ([]Flow, error) {
	query := beylaRateQuery(beylaL7GroupBy, "http_request_duration_milliseconds_count", opts.Namespace)
	result, err := s.query(ctx, query)
	if err != nil {
		return nil, err
	}
	return s.parseFlows(result, true), nil
}

func (s *BeylaSource) parseFlows(result *prom.QueryResult, isL7 bool) []Flow {
	if result == nil {
		return nil
	}
	flows := make([]Flow, 0, len(result.Series))
	for _, series := range result.Series {
		labels := series.Labels
		if len(series.DataPoints) == 0 {
			continue
		}
		val := series.DataPoints[0].Value
		if val <= 0 {
			continue
		}

		srcName := pickLabel(labels, "k8s_src_owner_name", "k8s_src_name")
		srcNs := labels["k8s_src_namespace"]
		srcType := pickLabel(labels, "k8s_src_owner_type", "k8s_src_type")
		dstName := pickLabel(labels, "k8s_dst_owner_name", "k8s_dst_name")
		dstNs := labels["k8s_dst_namespace"]
		dstType := pickLabel(labels, "k8s_dst_owner_type", "k8s_dst_type")

		// A nameless endpoint renders as an anonymous node the UI can't resolve
		// or navigate to, so drop the series rather than emit a phantom.
		if srcName == "" || dstName == "" {
			continue
		}

		port := parseIntLabel(labels["dst_port"])
		flow := Flow{
			Source:      Endpoint{Name: srcName, Namespace: srcNs, Kind: mapBeylaKind(srcType), Workload: srcName},
			Destination: Endpoint{Name: dstName, Namespace: dstNs, Kind: mapBeylaKind(dstType), Workload: dstName, Port: port},
			Protocol:    mapBeylaTransport(labels["transport"]),
			Port:        port,
			Verdict:     "forwarded",
			LastSeen:    time.Now(),
		}

		// Both metrics are per-second rates over a 5m window. L4 counts bytes,
		// L7 counts requests; neither is a connection count, so Connections is
		// only a non-zero weight for downstream L7-protocol aggregation.
		if isL7 {
			flow.RequestRate = val
			flow.Connections = max(int64(val*beylaRateWindowSeconds), 1)
		} else {
			flow.BytesSent = int64(val * beylaRateWindowSeconds)
			flow.Connections = 1
		}

		if flow.Source.Namespace == "" && flow.Source.Name != "" {
			flow.Source.Kind = "External"
		}
		if flow.Destination.Namespace == "" && flow.Destination.Name != "" {
			flow.Destination.Kind = "External"
		}

		if isL7 {
			flow.L7Protocol = "HTTP"
			flow.HTTPMethod = labels["http_method"]
			flow.HTTPPath = labels["http_route"]
			flow.HTTPStatus = parseIntLabel(labels["http_status_code"])
		}

		flows = append(flows, flow)
	}
	return flows
}

func pickLabel(labels map[string]string, keys ...string) string {
	for _, k := range keys {
		if v, ok := labels[k]; ok && v != "" {
			return v
		}
	}
	return ""
}

func parseIntLabel(s string) int {
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func mapBeylaKind(beylaType string) string {
	switch strings.ToLower(beylaType) {
	case "pod":
		return "Pod"
	case "deployment", "replicaset", "statefulset", "daemonset":
		return "Workload"
	case "service":
		return "Service"
	default:
		return "Pod"
	}
}

func mapBeylaTransport(transport string) string {
	switch strings.ToUpper(transport) {
	case "TCP":
		return "tcp"
	case "UDP":
		return "udp"
	default:
		return "tcp"
	}
}

func (s *BeylaSource) StreamFlows(ctx context.Context, opts FlowOptions) (<-chan Flow, error) {
	flowCh := make(chan Flow, 100)
	go func() {
		defer close(flowCh)
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				response, err := s.GetFlows(ctx, opts)
				if err != nil {
					log.Printf("[beyla] Error fetching flows: %v", err)
					continue
				}
				for _, flow := range response.Flows {
					select {
					case flowCh <- flow:
					case <-ctx.Done():
						return
					default:
					}
				}
			}
		}
	}()
	return flowCh, nil
}
