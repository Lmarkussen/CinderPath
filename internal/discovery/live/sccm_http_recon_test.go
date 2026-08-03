package live

import (
	"context"
	"testing"

	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/modules"
	"github.com/Lmarkussen/CinderPath/internal/scope"
)

func TestSCCMHTTPOnlySelectsOnlyTargetedModule(t *testing.T) {
	list := SCCMHTTPOnly(Options{DC: "mp01.example", Scope: structScope("mp01.example")})
	if len(list) != 1 || list[0].Metadata().Name != "live.sccm.http_recon" {
		t.Fatalf("unexpected modules: %v", list)
	}
	if list[0].Metadata().Safety != modules.SafetySafe {
		t.Fatalf("unexpected safety: %s", list[0].Metadata().Safety)
	}
}

func TestSCCMHTTPReconRequiresOneTarget(t *testing.T) {
	m := &sccmHTTPReconModule{}
	ok, reason := m.Applicable(context.Background(), modules.RunContext{}, &models.Asset{})
	if ok || reason == "" {
		t.Fatalf("missing target should be rejected: ok=%v reason=%q", ok, reason)
	}
}

func TestClassifySCCMHTTPFailure(t *testing.T) {
	if got := classifySCCMHTTPFailure([]routeObservation{{Error: `dial tcp: lookup mecma: no such host`}}); got != "endpoint_resolution_failed" {
		t.Fatalf("resolution classification=%q", got)
	}
	if got := classifySCCMHTTPFailure([]routeObservation{{Error: `dial tcp 10.0.0.1:443: connect: connection refused`}}); got != "connection_failed" {
		t.Fatalf("connection classification=%q", got)
	}
	if got := classifySCCMHTTPFailure([]routeObservation{{Error: "TLS handshake failed"}}); got != "collection_failed" {
		t.Fatalf("generic classification=%q", got)
	}
}

func TestSCCMHTTPReconRequestBound(t *testing.T) {
	if got, want := sccmHTTPReconRequestBound(), len(sccmRouteAllowlist)*maxSCCMOriginsPerHost; got != want {
		t.Fatalf("request bound=%d want=%d", got, want)
	}
	if got, want := sccmHTTPReconRequestBound(), 10; got != want {
		t.Fatalf("declared request bound=%d want=%d", got, want)
	}
	for _, route := range sccmRouteAllowlist {
		if route.Method != "GET" && route.Method != "HEAD" {
			t.Fatalf("unsafe method in route plan: %q", route.Method)
		}
	}
	if planned := len(sccmRouteAllowlist) * len(sccmHTTPReconOrigins("example.test")); planned > sccmHTTPReconRequestBound() {
		t.Fatalf("request plan=%d exceeds bound=%d", planned, sccmHTTPReconRequestBound())
	}
}

func structScope(target string) scope.Input {
	return scope.Input{Targets: []string{target}, MaxTargets: 1}
}
