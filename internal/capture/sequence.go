package capture

import (
	"fmt"
	"sort"
	"strings"
)

type SequenceComparison struct {
	Nodes           []string       `json:"nodes"`
	Edges           []SequenceEdge `json:"edges"`
	Optional        []string       `json:"optional,omitempty"`
	Repeated        []string       `json:"repeated,omitempty"`
	Coverage        map[string]int `json:"coverage"`
	Counterexamples []string       `json:"counterexamples,omitempty"`
	Classification  string         `json:"classification"`
}

func CompareSequences(cs []NormalizedCapture) SequenceComparison {
	r := SequenceComparison{Coverage: map[string]int{}, Classification: "unknown_order"}
	edgeSources := map[string][]string{}
	edgeCount := map[string]int{}
	nodeCount := map[string]int{}
	for _, c := range cs {
		seen := map[string]bool{}
		for _, e := range c.Exchanges {
			n := exchangeShape(e)
			nodeCount[n]++
			if seen[n] {
				r.Repeated = appendUnique(r.Repeated, n)
			}
			seen[n] = true
		}
		for _, e := range c.Sequence.Edges {
			from, to := shapeByID(c, e.From), shapeByID(c, e.To)
			if from == "" || to == "" {
				continue
			}
			k := from + " -> " + to
			edgeCount[k]++
			edgeSources[k] = append(edgeSources[k], c.Source.ID)
		}
	}
	for n, count := range nodeCount {
		r.Nodes = append(r.Nodes, n)
		r.Coverage[n] = count
		if count < len(cs) {
			r.Optional = append(r.Optional, n)
		}
	}
	for k, count := range edgeCount {
		parts := splitArrow(k)
		confidence := "likely_order"
		if count == len(cs) {
			confidence = "strict_order"
		}
		r.Edges = append(r.Edges, SequenceEdge{From: parts[0], To: parts[1], Kind: confidence, Evidence: "normalized sequence graph", Confidence: map[bool]string{true: "high", false: "medium"}[count == len(cs)], Coverage: count, SourceFixtures: edgeSources[k]})
	}
	sort.Strings(r.Nodes)
	sort.Strings(r.Optional)
	sort.Strings(r.Repeated)
	sort.Slice(r.Edges, func(i, j int) bool { return r.Edges[i].From+r.Edges[i].To < r.Edges[j].From+r.Edges[j].To })
	if len(r.Edges) > 0 {
		r.Classification = "partial_order"
	}
	return r
}
func exchangeShape(e Exchange) string {
	if e.Request != nil {
		return e.Request.Method + " " + e.Request.Route
	}
	if e.Response != nil {
		return "HTTP " + fmt.Sprint(e.Response.StatusCode)
	}
	return e.State
}
func shapeByID(c NormalizedCapture, id string) string {
	for _, e := range c.Exchanges {
		if e.ID == id {
			return exchangeShape(e)
		}
	}
	return ""
}
func appendUnique(x []string, v string) []string {
	for _, s := range x {
		if s == v {
			return x
		}
	}
	return append(x, v)
}
func splitArrow(s string) [2]string {
	i := strings.Index(s, " -> ")
	if i >= 0 {
		return [2]string{s[:i], s[i+4:]}
	}
	return [2]string{s, ""}
}
