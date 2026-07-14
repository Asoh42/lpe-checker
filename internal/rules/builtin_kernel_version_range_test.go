package rules

import (
	"strings"
	"testing"

	"lpe-checker/internal/model"
)

func TestLoadBuiltinKernelVersionRangeRules(t *testing.T) {
	rules, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin returned error: %v", err)
	}

	for _, id := range []string{"CVE-2026-46242", "CVE-2026-31694"} {
		rule, ok := ruleByID(rules, id)
		if !ok {
			t.Fatalf("builtin rule %s was not loaded", id)
		}
		if rule.Match.Type != "kernel_version_range" {
			t.Fatalf("rule %s match type = %q; want kernel_version_range", id, rule.Match.Type)
		}
	}
}

func TestBuiltinKernelVersionRangeMatchesAndClassifies(t *testing.T) {
	rules := mustBuiltinKernelVersionRangeRules(t)
	tests := []struct {
		name    string
		kernel  string
		ruleID  string
		wantRaw string
	}{
		{name: "Bad Epoll", kernel: "6.12.40-generic", ruleID: "CVE-2026-46242", wantRaw: "kernel_version_raw=6.12.40-generic"},
		{name: "FUSE readdir OOB", kernel: "6.16.2-generic", ruleID: "CVE-2026-31694", wantRaw: "kernel_version_raw=6.16.2-generic"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule, _ := ruleByID(rules, tt.ruleID)
			findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: tt.kernel}, []Rule{rule})
			if len(findings) != 1 || len(checks) != 1 {
				t.Fatalf("findings/checks = %d/%d; want 1/1", len(findings), len(checks))
			}
			finding := findings[0]
			if finding.Status != "suspected" || finding.Confidence != "medium" || finding.Severity != "high" {
				t.Fatalf("unexpected classification: %+v", finding)
			}
			if !strings.Contains(finding.Evidence, tt.wantRaw) || !strings.Contains(finding.Evidence, "false_positive_note=") {
				t.Fatalf("unexpected evidence: %q", finding.Evidence)
			}
			if checks[0].Result != "found" || checks[0].Status != "completed" {
				t.Fatalf("unexpected check: %+v", checks[0])
			}
		})
	}
}

func TestBuiltinKernelVersionRangeNotFoundAndBoundaries(t *testing.T) {
	rules := mustBuiltinKernelVersionRangeRules(t)
	badEpoll, _ := ruleByID(rules, "CVE-2026-46242")
	fuse, _ := ruleByID(rules, "CVE-2026-31694")

	for _, kernel := range []string{"3.10.0-1160.el7.x86_64", "5.15.0-91-generic"} {
		t.Run(kernel, func(t *testing.T) {
			findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: kernel}, []Rule{badEpoll, fuse})
			if len(findings) != 0 || len(checks) != 2 {
				t.Fatalf("unexpected findings/checks: %+v %+v", findings, checks)
			}
			for _, check := range checks {
				if check.Status != "completed" || check.Result != "not_found" {
					t.Fatalf("unexpected check for %s: %+v", kernel, check)
				}
			}
		})
	}

	t.Run("fixed excluded", func(t *testing.T) {
		findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: "7.1.0"}, []Rule{badEpoll})
		if len(findings) != 0 || len(checks) != 1 || checks[0].Result != "not_found" {
			t.Fatalf("unexpected fixed-boundary result: %+v %+v", findings, checks)
		}
	})

	t.Run("introduced included", func(t *testing.T) {
		findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: "6.4.0"}, []Rule{badEpoll})
		if len(findings) != 1 || len(checks) != 1 || checks[0].Result != "found" {
			t.Fatalf("unexpected introduced-boundary result: %+v %+v", findings, checks)
		}
	})
}

func mustBuiltinKernelVersionRangeRules(t *testing.T) []Rule {
	t.Helper()
	rules, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin returned error: %v", err)
	}
	return rules
}

func ruleByID(rules []Rule, id string) (Rule, bool) {
	for _, rule := range rules {
		if rule.ID == id {
			return rule, true
		}
	}
	return Rule{}, false
}
