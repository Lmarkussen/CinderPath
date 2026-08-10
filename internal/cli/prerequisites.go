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
	"syscall"

	"github.com/Lmarkussen/CinderPath/internal/config"
	"github.com/Lmarkussen/CinderPath/internal/cred1"
)

type localPrerequisite struct {
	ID, Name, Status, Reason, Remediation string
	State                                 string `json:"state,omitempty"`
	AutoFixSupported                      bool   `json:"auto_fix_supported"`
	ElevationRequired                     bool   `json:"elevation_required"`
	Persistent                            bool   `json:"persistent"`
	repair                                func() error
}

// Requirement states are deliberately structured internally; terminal text
// is only a rendering of these states.
const (
	requirementSatisfied = "satisfied"
	requirementBlocked   = "blocked"
	requirementError     = "check_error"
	requirementNA        = "not_applicable"
)

func (s *state) localPrerequisites(technique, target string, live bool) []localPrerequisite {
	if !live {
		return nil
	}
	items := []localPrerequisite{{ID: "platform", Name: "Platform", Status: "pass", State: requirementSatisfied, Reason: runtime.GOOS + "/" + runtime.GOARCH}}
	if technique == "CRED-1" {
		p := cred1.CheckCapturePrerequisites(target)
		if p.Libpcap {
			items = append(items, localPrerequisite{ID: "libpcap", Name: "libpcap", Status: "pass", State: requirementSatisfied, Reason: "installed"})
		} else {
			items = append(items, localPrerequisite{ID: "libpcap", Name: "libpcap", Status: "blocked", State: requirementBlocked, Reason: p.Reason, Remediation: p.Remediation, AutoFixSupported: p.AutoFixSupported})
		}
		if !p.Supported || !p.Libpcap || !p.CaptureAllowed || p.Interface == "" {
			item := localPrerequisite{ID: "cred1_capture", Name: "Packet capture", Status: "blocked", State: requirementBlocked, Reason: p.Reason, Remediation: p.Remediation, AutoFixSupported: p.AutoFixSupported, ElevationRequired: p.AutoFixSupported, Persistent: p.AutoFixSupported}
			if p.AutoFixSupported {
				item.repair = captureRepair()
			}
			items = append(items, item)
		} else {
			items = append(items, localPrerequisite{ID: "capture", Name: "Packet capture", Status: "pass", State: requirementSatisfied, Reason: "capability available on " + p.Interface})
		}
	}
	if technique == "CRED-2" || technique == "CRED-3" {
		if localTechniqueTarget(target) {
			items = append(items, localPrerequisite{ID: "sccm_client_context", Name: "SCCM client execution context", Status: "pass", State: requirementSatisfied, Reason: "current host is the requested client"})
		} else {
			items = append(items, localPrerequisite{ID: "sccm_client_context", Name: "SCCM client execution context", Status: "blocked", State: requirementBlocked, Reason: "this technique requires execution on the SCCM client itself", Remediation: "run CinderPath locally as the required SCCM client context"})
		}
	}
	return items
}

// resolveLocalRequirements performs the common pre-execution gate. A repair
// is offered only for an interactive text run and is verified before the
// caller proceeds. The CRED-1 file-capability repair re-execs the same command
// when necessary because Linux loads file capabilities at process exec time.
func (s *state) resolveLocalRequirements(technique, target, format string) bool {
	items := s.localPrerequisites(technique, target, true)
	if format == "text" {
		s.printLocalPrerequisites(items)
	}
	item := blockedLocal(items)
	if item == nil {
		return true
	}
	if format != "text" || os.Getenv("CINDERPATH_PREREQ_REEXEC") == "1" {
		if !s.familyPreflight {
			s.renderBlocked(technique, target, *item, format)
		}
		return false
	}
	if !item.AutoFixSupported || item.repair == nil {
		if !s.familyPreflight {
			s.renderBlocked(technique, target, *item, format)
		}
		return false
	}
	if !s.confirmRepair(*item) {
		if !s.familyPreflight {
			s.renderBlocked(technique, target, *item, format)
		}
		return false
	}
	if err := item.repair(); err != nil {
		item.Status = requirementError
		item.Reason = "automatic prerequisite repair failed: " + err.Error()
		if !s.familyPreflight {
			s.renderBlocked(technique, target, *item, format)
		}
		return false
	}
	updated := s.localPrerequisites(technique, target, true)
	if remaining := blockedLocal(updated); remaining != nil {
		// setcap changes the executable for the next process image. Re-enter
		// the original command automatically; this is not a second operator
		// command and never elevates the assessment itself.
		if technique == "CRED-1" && runtime.GOOS == "linux" && os.Getenv("CINDERPATH_PREREQ_REEXEC") != "1" {
			if format == "text" {
				fmt.Fprintln(s.stdout, "Repair applied. Rechecking capabilities and continuing...")
			}
			if err := reexecAfterPrerequisiteRepair(); err == nil {
				return false
			}
		}
		s.renderBlocked(technique, target, *remaining, format)
		return false
	}
	if format == "text" {
		fmt.Fprintln(s.stdout, "Prerequisites satisfied. Continuing original assessment...")
	}
	return true
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

func configuredIdentityLabel(c config.Config) string {
	if c.Identity.Username == "" {
		return "not configured"
	}
	return c.Identity.Username
}

func (s *state) printIdentitySummary() {
	label := configuredIdentityLabel(s.cfg)
	ldap := ldapIdentityConfigured(s.cfg)
	configmgr := s.cfg.Identity.Username != "" && (s.cfg.Identity.PasswordEnv != "" || s.cfg.Identity.PasswordFile != "" || s.cfg.Identity.KerberosCache != "")
	mark := func(ok bool) string {
		if ok {
			return s.renderer.Success("✓")
		}
		return s.renderer.Warning("✗")
	}
	fmt.Fprintf(s.stdout, "Identities\n  %s Domain / LDAP         %s\n  %s ConfigMgr             %s\n  %s Anonymous              used where supported\n\n", mark(ldap), label, mark(configmgr), label, s.renderer.Dim("○"))
}

func (s *state) printFamilyPlan(family string) {
	if family != "RECON" && family != "CRED" {
		return
	}
	identity := configuredIdentityLabel(s.cfg)
	fmt.Fprintln(s.stdout, "Plan")
	if family == "RECON" {
		transport := os.Getenv("CINDERPATH_CONFIGMGR_TRANSPORT_IP")
		route := "evidenced transport"
		if transport != "" {
			route = transport
		}
		fmt.Fprintf(s.stdout, "  RECON-1  LDAP        directory/site context (%s)\n  RECON-2  SMB         site-system role discovery (%s)\n  RECON-3  HTTP        logical authority → %s (anonymous)\n  RECON-4  CMPivot     client via ConfigMgr authority (%s)\n  RECON-5  Provider    user/device relationships (%s)\n  RECON-6  winreg      site-system registry roles (%s)\n\n", identity, identity, route, identity, identity, identity)
		return
	}
	fmt.Fprintf(s.stdout, "  CRED-1   PXE         anonymous network path\n  CRED-2   NAA         SCCM client context\n  CRED-3   NAA         SCCM client context\n\n")
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
		return json.NewEncoder(s.stdout).Encode(map[string]any{"technique_id": technique, "technique_name": techniqueTitle(technique), "status": "blocked", "target": redactedTarget(target), "prerequisite_id": item.ID, "prerequisite": item.Name, "requirement_state": item.State, "reason": item.Reason, "remediation": item.Remediation, "auto_fix_supported": item.AutoFixSupported, "elevation_required": item.ElevationRequired, "persistent": item.Persistent, "redaction": s.outputPolicy().Metadata()})
	}
	fmt.Fprintf(s.stdout, "%s — %s\n\nTarget: %s\nStatus: %s\n\nMissing prerequisite: %s\nReason: %s\n", technique, techniqueTitle(technique), s.renderer.Target(redactedTarget(target)), s.renderer.Warning("BLOCKED"), item.Name, item.Reason)
	if item.Remediation != "" {
		fmt.Fprintf(s.stdout, "Fix: %s\n", item.Remediation)
	}
	return nil
}

func (s *state) confirmRepair(item localPrerequisite) bool {
	f, ok := s.stdinTTY()
	if !ok {
		return false
	}
	fmt.Fprintf(s.stdout, "Fix available: %s\nApply fix using sudo? [Y/n] ", item.Remediation)
	answer, _ := bufio.NewReader(f).ReadString('\n')
	answer = strings.TrimSpace(strings.ToLower(answer))
	if answer != "" && answer != "y" && answer != "yes" {
		fmt.Fprintln(s.stdout, "Fix declined.")
		return false
	}
	return true
}

func captureRepair() func() error {
	return func() error {
		exe, err := os.Executable()
		if err != nil {
			return err
		}
		exe, err = filepath.EvalSymlinks(exe)
		if err != nil {
			return err
		}
		if filepath.Base(exe) == "" {
			return fmt.Errorf("invalid executable path")
		}
		cmd := exec.Command("sudo", "setcap", "cap_net_raw,cap_net_admin+eip", exe)
		cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
		return cmd.Run()
	}
}

func reexecAfterPrerequisiteRepair() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return err
	}
	env := append([]string{}, os.Environ()...)
	env = append(env, "CINDERPATH_PREREQ_REEXEC=1")
	return syscall.Exec(exe, os.Args, env)
}

func (s *state) stdinTTY() (*os.File, bool) {
	info, err := os.Stdin.Stat()
	return os.Stdin, err == nil && info.Mode()&os.ModeCharDevice != 0
}
