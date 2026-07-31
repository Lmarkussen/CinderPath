package live

import (
	"bufio"
	"context"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/progress"
)

type dnsModule struct{ opts Options }

func (m *dnsModule) Metadata() modules.Metadata {
	return modules.Metadata{Name: "live.dns.resolve", Description: "Resolves scoped names with Go-native DNS", Category: modules.CategoryDiscovery, Safety: modules.SafetySafe, Requirements: []modules.Requirement{{Capability: "scope_normalized"}}}
}
func (m *dnsModule) Applicable(context.Context, modules.RunContext, *models.Asset) (bool, string) {
	return true, ""
}
func (m *dnsModule) Run(ctx context.Context, run modules.RunContext, _ *models.Asset) (*modules.Result, error) {
	run.Emit(progress.Event{Type: progress.StageStarted, Module: m.Metadata().Name, Message: "DNS resolution"})
	assets, err := run.Store.ListAssets(ctx)
	if err != nil {
		return nil, err
	}
	r := resolver(m.opts.DNSServer)
	var mu sync.Mutex
	result := &modules.Result{}
	result.Evidence = append(result.Evidence, resolverEnvironmentEvidence(m.opts.DNSServer))
	work := filterLiveTargets(assets)
	parallel(ctx, m.opts.Concurrency, len(work), func(i int) {
		a := work[i]
		lookupCtx, cancel := context.WithTimeout(ctx, m.opts.HostTimeout)
		defer cancel()
		start := time.Now()
		data := map[string]any{"query": targetAddress(a), "resolver": resolverName(m.opts.DNSServer), "answers": []string{}}
		var answers []string
		recordType := "PTR"
		if len(a.IPAddresses) > 0 && a.FQDN == "" {
			names, e := r.LookupAddr(lookupCtx, a.IPAddresses[0])
			if e != nil {
				data["error"] = e.Error()
			} else {
				for _, n := range names {
					answers = append(answers, strings.ToLower(strings.TrimSuffix(n, ".")))
				}
			}
		} else {
			recordType = "A_AAAA"
			query := strings.ToLower(a.FQDN)
			v4, e4 := r.LookupIP(lookupCtx, "ip4", query)
			v6, e6 := r.LookupIP(lookupCtx, "ip6", query)
			for _, ip := range append(v4, v6...) {
				answers = append(answers, ip.String())
			}
			if e4 != nil && e6 != nil {
				data["error"] = e4.Error()
			}
			if cname, e := r.LookupCNAME(lookupCtx, query); e == nil && strings.TrimSuffix(cname, ".") != query {
				data["cname"] = strings.ToLower(strings.TrimSuffix(cname, "."))
			}
			if len(answers) > 0 {
				a.IPAddresses = mergeUnique(a.IPAddresses, answers)
			}
		}
		sort.Strings(answers)
		data["record_type"] = recordType
		data["answers"] = answers
		data["duration_ms"] = time.Since(start).Milliseconds()
		e := models.Evidence{Type: "dns_resolution", Title: "DNS resolution for " + targetAddress(a), Summary: dnsSummary(recordType, answers, data["error"]), Data: data, SourceModule: m.Metadata().Name, AssetID: a.ID, Sensitivity: models.SensitivityInternal}
		e.Prepare(time.Now())
		var relationships []models.Relationship
		for _, answer := range answers {
			to := models.StableID("dns", models.StableFingerprint(answer))
			confidence := models.ConfidenceHigh
			if recordType == "PTR" {
				confidence = models.ConfidenceMedium
			}
			rel := models.Relationship{FromID: a.ID, ToID: to, Type: models.RelationshipResolvesTo, Properties: map[string]string{"answer": answer, "record_type": recordType, "origin": "live"}, EvidenceIDs: []string{e.ID}, Confidence: confidence}
			rel.Prepare()
			relationships = append(relationships, rel)
		}
		mu.Lock()
		result.Assets = append(result.Assets, a)
		result.Evidence = append(result.Evidence, e)
		result.Relationships = append(result.Relationships, relationships...)
		mu.Unlock()
		run.Emit(progress.Event{Type: progress.TargetCompleted, Module: m.Metadata().Name, Target: targetAddress(a), Data: map[string]any{"resolved": len(answers) > 0}})
	})
	cap := models.Capability{Name: "dns_resolution", Available: true, Reason: "Go-native DNS resolution stage completed", Source: m.Metadata().Name}
	cap.Prepare()
	result.Capabilities = []models.Capability{cap}
	return result, ctx.Err()
}
func resolverEnvironmentEvidence(explicit string) models.Evidence {
	servers, search := []string{}, []string{}
	if f, err := os.Open("/etc/resolv.conf"); err == nil {
		servers, search = parseResolverConfig(f)
		_ = f.Close()
	}
	if explicit != "" {
		servers = []string{explicit}
	}
	e := models.Evidence{Type: "dns_environment", Title: "DNS resolver environment", Summary: "Recorded explicitly configured or local resolver metadata without external commands.", Data: map[string]any{"resolver": resolverName(explicit), "name_servers": servers, "search_domains": search}, SourceModule: "live.dns.resolve", Sensitivity: models.SensitivityInternal}
	e.Prepare(time.Now())
	return e
}
func parseResolverConfig(r io.Reader) ([]string, []string) {
	var servers, search []string
	s := bufio.NewScanner(r)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) < 2 || strings.HasPrefix(fields[0], "#") {
			continue
		}
		switch fields[0] {
		case "nameserver":
			servers = append(servers, fields[1])
		case "search":
			search = append(search, fields[1:]...)
		case "domain":
			search = append(search, fields[1])
		}
	}
	return mergeUnique(servers), mergeUnique(search)
}
func parallel(ctx context.Context, limit, count int, fn func(int)) {
	if limit < 1 {
		limit = 1
	}
	if limit > count {
		limit = count
	}
	var wg sync.WaitGroup
	idx := make(chan int)
	for w := 0; w < limit; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case i, ok := <-idx:
					if !ok {
						return
					}
					fn(i)
				}
			}
		}()
	}
loop:
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			break loop
		case idx <- i:
		}
	}
	close(idx)
	wg.Wait()
}
func filterLiveTargets(in []models.Asset) []models.Asset {
	var out []models.Asset
	for _, a := range in {
		if a.Properties["observation_origin"] == "live" && a.Properties["normalized_target"] != "" && a.Kind == models.AssetUnknown {
			out = append(out, a)
		}
	}
	return out
}
func targetAddress(a models.Asset) string {
	if a.FQDN != "" {
		return strings.ToLower(a.FQDN)
	}
	if len(a.IPAddresses) > 0 {
		return a.IPAddresses[0]
	}
	return strings.ToLower(a.Hostname)
}
func resolverName(s string) string {
	if s == "" {
		return "system"
	}
	return s
}
func dnsSummary(rt string, a []string, e any) string {
	if e != nil {
		return rt + " lookup did not resolve"
	}
	if len(a) == 0 {
		return rt + " lookup returned no answers"
	}
	return rt + " lookup returned " + strings.Join(a, ", ")
}
func mergeUnique(groups ...[]string) []string {
	m := map[string]bool{}
	var out []string
	for _, g := range groups {
		for _, v := range g {
			if ip, err := netip.ParseAddr(v); err == nil {
				v = ip.Unmap().String()
			}
			if v != "" && !m[v] {
				m[v] = true
				out = append(out, v)
			}
		}
	}
	sort.Strings(out)
	return out
}
