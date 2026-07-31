package scope

import (
	"bufio"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

type Input struct {
	Targets, TargetFiles, IncludeCIDRs, ExcludeHosts, ExcludeCIDRs []string
	Domain                                                         string
	MaxTargets                                                     int
}
type Target struct {
	Original string `json:"original"`
	Value    string `json:"value"`
	Kind     string `json:"kind"`
}
type Decision struct {
	Targets       []Target `json:"targets"`
	Excluded      []string `json:"excluded"`
	InputCount    int      `json:"input_count"`
	ExpandedCount int      `json:"expanded_count"`
}

func ParseTargetFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open targets file %q: %w", path, err)
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 4096), 1024*1024)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line != "" {
			out = append(out, line)
		}
	}
	if err := s.Err(); err != nil {
		return nil, fmt.Errorf("read targets file %q: %w", path, err)
	}
	return out, nil
}

func Normalize(in Input) (Decision, error) {
	if in.MaxTargets <= 0 {
		return Decision{}, fmt.Errorf("maximum targets must be greater than zero")
	}
	values := append([]string(nil), in.Targets...)
	values = append(values, in.IncludeCIDRs...)
	for _, path := range in.TargetFiles {
		items, err := ParseTargetFile(path)
		if err != nil {
			return Decision{}, err
		}
		values = append(values, items...)
	}
	filtered := values[:0]
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			filtered = append(filtered, value)
		}
	}
	values = filtered
	d := Decision{InputCount: len(values)}
	excludedHosts := map[string]bool{}
	for _, h := range in.ExcludeHosts {
		n, _, err := NormalizeValue(h, in.Domain)
		if err != nil {
			return d, fmt.Errorf("invalid excluded host %q: %w", h, err)
		}
		excludedHosts[n] = true
	}
	var excludedNets []netip.Prefix
	for _, raw := range in.ExcludeCIDRs {
		p, err := netip.ParsePrefix(strings.TrimSpace(raw))
		if err != nil {
			return d, fmt.Errorf("invalid excluded CIDR %q: %w", raw, err)
		}
		excludedNets = append(excludedNets, p.Masked())
	}
	seen := map[string]bool{}
	add := func(t Target) error {
		if seen[t.Value] {
			return nil
		}
		if excludedHosts[t.Value] || excludedTarget(t.Value, excludedNets) {
			d.Excluded = append(d.Excluded, t.Value)
			return nil
		}
		if len(d.Targets) >= in.MaxTargets {
			return fmt.Errorf("normalized scope exceeds maximum of %d targets; narrow scope or increase --max-targets", in.MaxTargets)
		}
		seen[t.Value] = true
		d.Targets = append(d.Targets, t)
		return nil
	}
	for _, raw := range values {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		if p, err := netip.ParsePrefix(raw); err == nil {
			p = p.Masked()
			count, ok := prefixSize(p)
			if !ok || count > uint64(in.MaxTargets) {
				return d, fmt.Errorf("CIDR %s expands beyond maximum of %d targets", p, in.MaxTargets)
			}
			for addr := p.Addr(); p.Contains(addr); addr = addr.Next() {
				if err := add(Target{Original: raw, Value: addr.String(), Kind: "ip"}); err != nil {
					return d, err
				}
				d.ExpandedCount++
			}
			continue
		}
		n, kind, err := NormalizeValue(raw, in.Domain)
		if err != nil {
			return d, fmt.Errorf("invalid target %q: %w", raw, err)
		}
		if err := add(Target{Original: raw, Value: n, Kind: kind}); err != nil {
			return d, err
		}
	}
	sort.Slice(d.Targets, func(i, j int) bool { return d.Targets[i].Value < d.Targets[j].Value })
	sort.Strings(d.Excluded)
	return d, nil
}

func NormalizeValue(raw, domain string) (string, string, error) {
	v := strings.TrimSpace(strings.TrimSuffix(raw, "."))
	if v == "" {
		return "", "", fmt.Errorf("empty value")
	}
	if a, err := netip.ParseAddr(v); err == nil {
		return a.Unmap().String(), "ip", nil
	}
	v = strings.ToLower(v)
	if !validHostname(v) {
		return "", "", fmt.Errorf("invalid hostname")
	}
	if !strings.Contains(v, ".") && domain != "" {
		v += "." + strings.ToLower(strings.Trim(strings.TrimSpace(domain), "."))
	}
	kind := "hostname"
	if strings.Contains(v, ".") {
		kind = "fqdn"
	}
	return v, kind, nil
}
func validHostname(v string) bool {
	if len(v) > 253 {
		return false
	}
	for _, label := range strings.Split(v, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}
func excludedTarget(v string, nets []netip.Prefix) bool {
	a, err := netip.ParseAddr(v)
	if err != nil {
		return false
	}
	for _, p := range nets {
		if p.Contains(a) {
			return true
		}
	}
	return false
}
func prefixSize(p netip.Prefix) (uint64, bool) {
	bits := p.Addr().BitLen() - p.Bits()
	if bits >= 64 {
		return 0, false
	}
	return uint64(1) << bits, true
}
