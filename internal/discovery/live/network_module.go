package live

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)
type networkScanner struct {
	ports                       []int
	connectTimeout, hostTimeout time.Duration
	concurrency                 int
	dial                        dialContextFunc
	active, maxActive           atomic.Int64
}
type probeResult struct {
	asset         models.Asset
	evidence      models.Evidence
	relationships []models.Relationship
}

type networkModule struct{ opts Options }

func (m *networkModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.network.probe", Description: "Performs bounded TCP connect reachability checks", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "scope_normalized"}}}
}
func (m *networkModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	if len(m.opts.Ports) == 0 {
		return false, "no probe ports configured"
	}
	return true, ""
}
func (m *networkModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "bounded TCP reachability"})
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	targets := filterLiveTargets(assets)
	d := net.Dialer{Timeout: m.opts.ConnectTimeout}
	scanner := networkScanner{ports: m.opts.Ports, connectTimeout: m.opts.ConnectTimeout, hostTimeout: m.opts.HostTimeout, concurrency: m.opts.Concurrency, dial: d.DialContext}
	results := scanner.probe(ctx, targets, run)
	out := &modules.Result{}
	for _, item := range results {
		out.Assets = append(out.Assets, item.asset)
		out.Evidence = append(out.Evidence, item.evidence)
		out.Relationships = append(out.Relationships, item.relationships...)
	}
	cap := models.Capability{Name: "network_probe_completed", Available: true, Reason: "Safe TCP connect probing completed for normalized scope", Source: m.Metadata().Name}
	cap.Prepare()
	out.Capabilities = []models.Capability{cap}
	return out, ctx.Err()
}
func (s *networkScanner) probe(ctx context.Context, assets []models.Asset, run modules.RunContext) []probeResult {
	var mu sync.Mutex
	var out []probeResult
	parallel(ctx, s.concurrency, len(assets), func(i int) { r := s.probeHost(ctx, assets[i], run); mu.Lock(); out = append(out, r); mu.Unlock() })
	sort.Slice(out, func(i, j int) bool { return out[i].asset.ID < out[j].asset.ID })
	return out
}
func (s *networkScanner) probeHost(parent context.Context, a models.Asset, run modules.RunContext) probeResult {
	target := targetAddress(a)
	run.Emit(progress.Event{Type: progress.TargetStarted, Module: "live.network.probe", Target: target})
	ctx, cancel := context.WithTimeout(parent, s.hostTimeout)
	defer cancel()
	start := time.Now()
	var open, timedout, failed []int
	addresses := append([]string(nil), a.IPAddresses...)
	if len(addresses) == 0 {
		addresses = []string{target}
	}
	for _, port := range s.ports {
		if ctx.Err() != nil {
			timedout = append(timedout, port)
			continue
		}
		opened := false
		timeoutOnly := false
		for _, host := range addresses {
			conn, err := s.callDial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err == nil {
				_ = conn.Close()
				opened = true
				break
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				timeoutOnly = true
			}
		}
		if opened {
			open = append(open, port)
		} else if timeoutOnly {
			timedout = append(timedout, port)
		} else {
			failed = append(failed, port)
		}
	}
	a.Properties = cloneMap(a.Properties)
	a.Properties["open_ports"] = joinPorts(open)
	a.Properties["reachable"] = strconv.FormatBool(len(open) > 0)
	a.Properties["probe_origin"] = "live"
	data := map[string]any{"probe_type": "tcp_connect", "attempted_ports": s.ports, "open_ports": open, "timed_out_ports": timedout, "failed_ports": failed, "duration_ms": time.Since(start).Milliseconds(), "targets": addresses}
	e := models.Evidence{Type: "network_probe", Title: "TCP reachability for " + target, Summary: fmt.Sprintf("Attempted %d ports; %d accepted TCP connections.", len(s.ports), len(open)), Data: data, SourceModule: "live.network.probe", AssetID: a.ID, Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Now())
	var relationships []models.Relationship
	for _, port := range open {
		serviceID := models.StableID("svc", models.StableFingerprint(a.ID, "tcp", strconv.Itoa(port)))
		rel := models.Relationship{FromID: a.ID, ToID: serviceID, Type: models.RelationshipHostExposesService, Properties: map[string]string{"protocol": "tcp", "port": strconv.Itoa(port), "origin": "live"}, EvidenceIDs: []string{e.ID}, Confidence: models.ConfidenceConfirmed}
		rel.Prepare()
		relationships = append(relationships, rel)
	}
	run.Emit(progress.Event{Type: progress.TargetCompleted, Module: "live.network.probe", Target: target, Data: map[string]any{"reachable": len(open) > 0, "open_ports": len(open)}})
	return probeResult{a, e, relationships}
}
func (s *networkScanner) callDial(ctx context.Context, network, address string) (net.Conn, error) {
	n := s.active.Add(1)
	for {
		old := s.maxActive.Load()
		if n <= old || s.maxActive.CompareAndSwap(old, n) {
			break
		}
	}
	defer s.active.Add(-1)
	return s.dial(ctx, network, address)
}
func joinPorts(p []int) string {
	parts := make([]string, len(p))
	for i, v := range p {
		parts[i] = strconv.Itoa(v)
	}
	return strings.Join(parts, ",")
}
func parseOpenPorts(raw string) map[int]bool {
	out := map[int]bool{}
	for _, v := range strings.Split(raw, ",") {
		p, _ := strconv.Atoi(v)
		if p > 0 {
			out[p] = true
		}
	}
	return out
}
func cloneMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}
