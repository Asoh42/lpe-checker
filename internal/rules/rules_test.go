package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lpe-checker/internal/model"
)

func TestEvaluateSudoContains(t *testing.T) {
	info := model.SystemInfo{SudoList: model.SudoList{Available: true, Raw: "(root) NOPASSWD: /usr/bin/id"}}
	rs := []Rule{{
		ID:          "T-1",
		Name:        "test",
		Severity:    "High",
		Remediation: "fix",
		Match:       MatchCriteria{Type: "sudo_contains", Contains: "NOPASSWD"},
	}}
	got := Evaluate(info, rs)
	if len(got) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(got))
	}
	if got[0].ID != "T-1" || got[0].Reason == "" || got[0].Evidence == "" {
		t.Fatalf("unexpected finding: %+v", got[0])
	}
}

func TestEvaluateSUIDPath(t *testing.T) {
	info := model.SystemInfo{SUIDFiles: []string{"/usr/bin/pkexec"}}
	rs := []Rule{{
		ID:          "T-2",
		Name:        "pkexec",
		Severity:    "Medium",
		Remediation: "patch",
		Match:       MatchCriteria{Type: "suid_path", Path: "/usr/bin/pkexec"},
	}}
	if got := Evaluate(info, rs); len(got) != 1 {
		t.Fatalf("expected SUID finding, got %d", len(got))
	} else if got[0].Evidence == "" {
		t.Fatalf("expected evidence, got %+v", got[0])
	}
}

func TestEvaluateSUIDPathDoesNotMatchEmptyContains(t *testing.T) {
	info := model.SystemInfo{SUIDFiles: []string{"/bin/su"}}
	rs := []Rule{{
		ID:          "T-3",
		Name:        "find",
		Severity:    "High",
		Remediation: "remove suid",
		Match:       MatchCriteria{Type: "suid_path", Path: "/usr/bin/find"},
	}}
	if got := Evaluate(info, rs); len(got) != 0 {
		t.Fatalf("expected no finding when only /bin/su is present, got %+v", got)
	}
}

func TestEvaluateKernelCVELinuxModuleAvailable(t *testing.T) {
	info := model.SystemInfo{
		Platform:      "linux",
		KernelVersion: "6.1.0-test",
		KernelModules: map[string]model.KernelModule{
			"algif_aead": {
				Name:            "algif_aead",
				LoadedStatus:    "not_loaded",
				AvailableStatus: "available",
				Paths:           []string{"/lib/modules/6.1.0-test/kernel/crypto/algif_aead.ko.xz"},
			},
		},
	}
	got := Evaluate(info, []Rule{kernelCVERuleForTest()})
	if len(got) != 1 {
		t.Fatalf("expected suspected kernel CVE finding, got %d", len(got))
	}
	if got[0].ID != "CVE-2026-31431" || got[0].Status != "suspected" || got[0].Category != "kernel-cve" {
		t.Fatalf("unexpected finding: %+v", got[0])
	}
	if !strings.Contains(got[0].Evidence, "module_status=available") {
		t.Fatalf("expected available evidence, got %q", got[0].Evidence)
	}
}

func TestEvaluateKernelCVENonLinuxDoesNotMatch(t *testing.T) {
	info := model.SystemInfo{
		Platform:      "windows",
		KernelVersion: "windows (uname unavailable)",
		KernelModules: map[string]model.KernelModule{
			"algif_aead": {Name: "algif_aead", LoadedStatus: "unknown", AvailableStatus: "unknown"},
		},
	}
	if got := Evaluate(info, []Rule{kernelCVERuleForTest()}); len(got) != 0 {
		t.Fatalf("expected no non-linux finding, got %+v", got)
	}
}

func TestEvaluateKernelCVEModuleUnknownStillSuspected(t *testing.T) {
	info := model.SystemInfo{
		Platform:      "linux",
		KernelVersion: "6.1.0-test",
		KernelModules: map[string]model.KernelModule{
			"algif_aead": {Name: "algif_aead", LoadedStatus: "unknown", AvailableStatus: "unknown", Paths: []string{}, Raw: "lsmod failed"},
		},
	}
	got := Evaluate(info, []Rule{kernelCVERuleForTest()})
	if len(got) != 1 {
		t.Fatalf("expected suspected finding for unknown module status, got %d", len(got))
	}
	if got[0].Status != "suspected" || !strings.Contains(got[0].Evidence, "module_status=unknown") {
		t.Fatalf("expected suspected unknown evidence, got %+v", got[0])
	}
}

func kernelCVERuleForTest() Rule {
	return Rule{
		ID:               "CVE-2026-31431",
		Name:             "test kernel cve",
		Severity:         "high",
		Category:         "kernel-cve",
		Confidence:       "medium",
		Status:           "suspected",
		Description:      "suspected only",
		Affected:         Affected{Component: "Linux kernel", Module: "algif_aead", OS: "linux"},
		Match:            MatchCriteria{Type: "kernel_cve_module", Module: "algif_aead"},
		Reason:           "suspected only",
		EvidenceTemplate: "{{evidence}}",
		Impact:           "possible LPE exposure",
		Condition:        "os=linux; module_status in [loaded, available, unknown]",
		Remediation:      "check vendor advisory and update kernel",
		References:       []string{"https://www.cve.org/CVERecord?id=CVE-2026-31431"},
	}
}

func TestEvaluateWithChecksRecordsNotFoundAndFound(t *testing.T) {
	info := model.SystemInfo{SudoList: model.SudoList{Available: true, Raw: "user may run sudo without NOPASSWD"}}
	rules := []Rule{
		{ID: "CHECK-FOUND", Name: "found", Severity: "High", Remediation: "fix", Match: MatchCriteria{Type: "sudo_contains", Contains: "NOPASSWD"}},
		{ID: "CHECK-NOT-FOUND", Name: "not found", Severity: "High", Remediation: "fix", Match: MatchCriteria{Type: "suid_path", Path: "/usr/bin/not-present"}},
	}
	findings, checks := EvaluateWithChecks(info, rules)
	if len(checks) != 2 {
		t.Fatalf("expected 2 checks, got %d", len(checks))
	}
	if checks[0].Result != "found" || checks[1].Result != "not_found" {
		t.Fatalf("unexpected checks: %+v", checks)
	}
	if len(findings) != 1 || findings[0].CheckID != "CHECK-FOUND" {
		t.Fatalf("unexpected findings: %+v", findings)
	}
}

func TestEvaluateWithChecksRecordsSkippedForNonLinuxKernelCVE(t *testing.T) {
	info := model.SystemInfo{Platform: "windows", KernelModules: map[string]model.KernelModule{}}
	_, checks := EvaluateWithChecks(info, []Rule{kernelCVERuleForTest()})
	if len(checks) != 1 {
		t.Fatalf("expected 1 check, got %d", len(checks))
	}
	if checks[0].Status != "skipped" || checks[0].Result != "not_applicable" {
		t.Fatalf("expected skipped/not_applicable, got %+v", checks[0])
	}
}

func TestLoadDefaultIncludesBuiltinWhenRulesDirMissing(t *testing.T) {
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(oldWD)

	got, err := LoadDefault("")
	if err != nil {
		t.Fatalf("LoadDefault returned error: %v", err)
	}
	if !hasRule(got, "LPE-SUDO-NOPASSWD") || !hasRule(got, "LPE-SUID-PKEXEC") || !hasRule(got, "LPE-SUID-FIND") {
		t.Fatalf("builtin rules not loaded: %+v", got)
	}
}

func TestLoadDefaultExternalOverridesBuiltin(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "override.yaml")
	if err := os.WriteFile(path, []byte(`rules:
  - id: LPE-SUDO-NOPASSWD
    name: external sudo rule
    severity: Low
    remediation: external fix
    match:
      type: sudo_contains
      contains: NOPASSWD
`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := LoadDefault(dir)
	if err != nil {
		t.Fatalf("LoadDefault returned error: %v", err)
	}
	for _, r := range got {
		if r.ID == "LPE-SUDO-NOPASSWD" {
			if r.Name != "external sudo rule" || r.Severity != "Low" {
				t.Fatalf("external rule did not override builtin: %+v", r)
			}
			return
		}
	}
	t.Fatal("overridden rule not found")
}

func hasRule(rs []Rule, id string) bool {
	for _, r := range rs {
		if r.ID == id {
			return true
		}
	}
	return false
}
