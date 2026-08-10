package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/cred1"
)

type localPrerequisite struct {
	ID, Name, Status, Reason, Remediation string
	AutoFixSupported                      bool `json:"auto_fix_supported"`
}

func (s *state) localPrerequisites(technique, target string, live bool) []localPrerequisite {
	if !live {
		return nil
	}
	items := []localPrerequisite{{ID: "platform", Name: "Platform", Status: "pass", Reason: runtime.GOOS + "/" + runtime.GOARCH}}
	if technique == "CRED-1" {
		p := cred1.CheckCapturePrerequisites(target)
		if p.Libpcap {
			items = append(items, localPrerequisite{ID: "libpcap", Name: "libpcap", Status: "pass", Reason: "installed"})
		} else {
			items = append(items, localPrerequisite{ID: "libpcap", Name: "libpcap", Status: "blocked", Reason: p.Reason, Remediation: p.Remediation, AutoFixSupported: p.AutoFixSupported})
		}
		if !p.Supported || !p.Libpcap || !p.CaptureAllowed || p.Interface == "" {
			items = append(items, localPrerequisite{ID: "cred1_capture", Name: "Packet capture", Status: "blocked", Reason: p.Reason, Remediation: p.Remediation, AutoFixSupported: p.AutoFixSupported})
		} else {
			items = append(items, localPrerequisite{ID: "capture", Name: "Packet capture", Status: "pass", Reason: "capability available on " + p.Interface})
		}
	}
	return items
}

func blockedLocal(items []localPrerequisite) *localPrerequisite {
	for i := range items {
		if items[i].Status == "blocked" {
			return &items[i]
		}
	}
	return nil
}

func (s *state) printLocalPrerequisites(items []localPrerequisite) {
	if len(items) == 0 {
		return
	}
	fmt.Fprintln(s.stdout, "Prerequisites")
	for _, item := range items {
		mark := s.renderer.Success("✓")
		if item.Status != "pass" {
			mark = s.renderer.Warning("✗")
		}
		fmt.Fprintf(s.stdout, "%s %-24s %s\n", mark, item.Name, s.renderer.Dim(item.Reason))
	}
}

func ldapIdentityConfigured(c config.Config) bool {
	return c.Identity.Username != "" && (c.Identity.PasswordEnv != "" || c.Identity.PasswordFile != "" || c.Identity.KerberosCache != "")
}

func localTechniqueTarget(target string) bool {
	if strings.TrimSpace(target) == "" {
		return false
	}
	host, err := os.Hostname()
	if err != nil {
		return false
	}
	a, b := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(target)), "."), strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	return a == b || strings.Split(a, ".")[0] == strings.Split(b, ".")[0]
}

func (s *state) renderBlocked(technique, target string, item localPrerequisite, format string) error {
	if format == "json" {
		return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": technique, "technique_name": techniqueTitle(technique), "status": "blocked", "target": redactedTarget(target), "prerequisite_id": item.ID, "prerequisite": item.Name, "reason": item.Reason, "remediation": item.Remediation, "auto_fix_supported": item.AutoFixSupported, "redaction": s.outputPolicy().Metadata()})
	}
	fmt.Fprintf(s.stdout, "%s — %s\n\nTarget: %s\nStatus: %s\n\nMissing prerequisite: %s\nReason: %s\n", technique, techniqueTitle(technique), s.renderer.Target(redactedTarget(target)), s.renderer.Warning("BLOCKED"), item.Name, item.Reason)
	if item.Remediation != "" {
		fmt.Fprintf(s.stdout, "Fix: %s\n", item.Remediation)
	}
	if item.AutoFixSupported && s.renderer.Enabled() {
		s.offerCaptureFix(item.Remediation)
	}
	return nil
}

func (s *state) offerCaptureFix(remediation string) {
	if remediation == "" {
		return
	}
	f, ok := s.stdinTTY()
	if !ok {
		return
	}
	fmt.Fprintf(s.stdout, "Fix available: %s\nApply fix? [Y/n] ", remediation)
	answer, _ := bufio.NewReader(f).ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Fprintln(s.stdout, "Fix declined.")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		fmt.Fprintf(s.stdout, "Run manually: %s\n", remediation)
		return
	}
	if filepath.Base(exe) != "cinderpath" {
		fmt.Fprintf(s.stdout, "Automatic fix is available for the installed binary; run manually: %s\n", remediation)
		return
	}
	cmd := exec.Command("sudo", "setcap", "cap_net_raw,cap_net_admin+eip", exe)
	if _, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(s.stdout, "Automatic fix failed; run manually: %s (%v)\n", remediation, err)
		return
	}
	fmt.Fprintln(s.stdout, "Fix applied. Re-run the assessment to verify the capability.")
}

func (s *state) stdinTTY() (*os.File, bool) {
	info, err := os.Stdin.Stat()
	return os.Stdin, err == nil && info.Mode()&os.ModeCharDevice != 0
}
