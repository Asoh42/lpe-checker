package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lpe-checker/internal/collector"
	"lpe-checker/internal/rules"
)

type fakeRunner map[string]string

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name
	for _, arg := range args {
		key += " " + arg
	}
	return f[key], nil
}

type scriptedRunner struct {
	outputs map[string]string
	errors  map[string]error
}

type moduleConfigRunner struct {
	modules []string
}

func (r *moduleConfigRunner) Run(context.Context, string, ...string) (string, error) { return "", nil }
func (r *moduleConfigRunner) SetAllowedKernelModules(modules []string) error {
	r.modules = append([]string{}, modules...)
	return nil
}

func (r scriptedRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name
	for _, arg := range args {
		key += " " + arg
	}
	return r.outputs[key], r.errors[key]
}

func TestNewWithRunnerSetsRemoteTarget(t *testing.T) {
	s, err := NewWithRunner("", fakeRunner{
		"uname -r":            "6.1.0-remote",
		"uname -m":            "aarch64",
		"cat /etc/os-release": "ID=debian\nNAME=Debian",
		"id":                  "uid=1000(remote)",
		"hostname":            "remote-node",
	}, "192.0.2.10:22")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := s.Scan(context.Background())
	if r.SystemInfo.KernelVersion != "6.1.0-remote" || r.Target.Host != "192.0.2.10:22" || r.ScanTarget != "192.0.2.10:22" || r.Meta.ScanMode != "remote" || r.Target.Platform != "linux/aarch64" {
		t.Fatalf("unexpected remote report: %+v", r)
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"host":"192.0.2.10:22"`) || !strings.Contains(string(b), `"scan_target":"192.0.2.10:22"`) {
		t.Fatalf("remote host missing from JSON: %s, %v", b, err)
	}
}

func TestNewWithRunnerConfiguresModulesFromLoadedRules(t *testing.T) {
	runner := &moduleConfigRunner{}
	s, err := NewWithRunner("", runner, "192.0.2.10")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"algif_aead": true, "esp4": true, "esp6": true, "rxrpc": true, "espintcp": true, "act_pedit": true, "cifs": true}
	if len(runner.modules) != len(want) || len(s.Collector.KernelModuleNames) != len(want) {
		t.Fatalf("unexpected configured modules: runner=%v collector=%v", runner.modules, s.Collector.KernelModuleNames)
	}
	for _, moduleName := range runner.modules {
		if !want[moduleName] {
			t.Fatalf("unexpected configured module %q in %v", moduleName, runner.modules)
		}
	}
}

func TestScanMapsCollectionFailureToDependentCheckOnly(t *testing.T) {
	s := Scanner{
		Collector: collector.Collector{Runner: scriptedRunner{
			outputs: map[string]string{
				"uname -r":   "6.1.0-test",
				"uname -m":   "x86_64",
				"id":         "",
				"sudo -n -l": "no matching sudo rule",
				"hostname":   "test-host",
			},
			errors: map[string]error{"id": errors.New("id execution failed")},
		}},
		Rules: []rules.Rule{
			{ID: "USER-CHECK", Name: "user", Severity: "low", Remediation: "fix", Match: rules.MatchCriteria{Type: "user_contains", Contains: "root"}},
			{ID: "SUDO-CHECK", Name: "sudo", Severity: "low", Remediation: "fix", Match: rules.MatchCriteria{Type: "sudo_contains", Contains: "NOPASSWD"}},
		},
	}
	report, scanErr := s.Scan(context.Background())
	if scanErr == nil {
		t.Fatal("expected partial collection error")
	}
	if len(report.Checks) != 2 {
		t.Fatalf("unexpected checks: %+v", report.Checks)
	}
	if report.Checks[0].Status != "failed" || report.Checks[0].Result != "unknown" || report.Checks[0].Error == "" {
		t.Fatalf("dependent check was not failed: %+v", report.Checks[0])
	}
	if report.Checks[1].Status != "completed" || report.Checks[1].Result != "not_found" || report.Checks[1].Error != "" {
		t.Fatalf("successful non-match was misclassified: %+v", report.Checks[1])
	}
	if report.Summary.FailedChecks != 1 || report.Summary.CompletedChecks != 1 {
		t.Fatalf("unexpected summary: %+v", report.Summary)
	}
}

func TestLocalScanTargetIsLocalhost(t *testing.T) {
	s := Scanner{Collector: collector.Collector{Runner: fakeRunner{"hostname": "local-node"}}}
	report, _ := s.Scan(context.Background())
	if report.ScanTarget != "localhost" || report.Target.Host != "" || report.Meta.ScanMode != "local" {
		t.Fatalf("unexpected local target fields: %+v", report)
	}
}

func TestLocalTargetHostOmittedFromJSON(t *testing.T) {
	s := Scanner{Collector: collector.Collector{Runner: fakeRunner{"hostname": "local-node"}}}
	r, _ := s.Scan(context.Background())
	if r.Target.Host != "" {
		t.Fatalf("local target host should be empty: %q", r.Target.Host)
	}
	b, err := json.Marshal(r)
	if err != nil || strings.Contains(string(b), `"host":`) {
		t.Fatalf("local host field should be omitted from JSON: %s, %v", b, err)
	}
}

func TestWithRuleIDsFiltersBeforeEvaluation(t *testing.T) {
	s := Scanner{
		Collector: collector.Collector{Runner: fakeRunner{
			"uname -r":   "6.1.0-test",
			"id":         "uid=1000(test)",
			"sudo -n -l": "NOPASSWD: /usr/bin/id",
		}},
		Rules: []rules.Rule{
			{ID: "SELECTED", Name: "selected", Match: rules.MatchCriteria{Type: "sudo_contains", Contains: "NOPASSWD"}},
			{ID: "NOT-SELECTED", Name: "not selected", Match: rules.MatchCriteria{Type: "sudo_contains", Contains: "NOPASSWD"}},
		},
	}
	filtered, err := s.WithRuleIDs([]string{"SELECTED"})
	if err != nil {
		t.Fatal(err)
	}
	report, _ := filtered.Scan(context.Background())
	if len(report.Checks) != 1 || report.Checks[0].ID != "SELECTED" {
		t.Fatalf("unselected rule entered checks: %+v", report.Checks)
	}
	if len(report.Findings) != 1 || report.Findings[0].ID != "SELECTED" {
		t.Fatalf("unselected rule entered findings: %+v", report.Findings)
	}

	allReport, _ := s.Scan(context.Background())
	if len(allReport.Checks) != 2 || len(allReport.Findings) != 2 {
		t.Fatalf("unfiltered scanner should evaluate all rules: checks=%+v findings=%+v", allReport.Checks, allReport.Findings)
	}
}

func TestWithRuleIDsRejectsEmptySelection(t *testing.T) {
	_, err := (Scanner{}).WithRuleIDs(nil)
	if !errors.Is(err, ErrNoRulesSelected) {
		t.Fatalf("expected ErrNoRulesSelected, got %v", err)
	}
}

func TestScan(t *testing.T) {
	s := Scanner{
		Collector: collector.Collector{Runner: fakeRunner{
			"uname -r":   "6.1.0-test",
			"id":         "uid=1000(test)",
			"sudo -n -l": "(root) NOPASSWD: /usr/bin/id",
		}},
		Rules: []rules.Rule{{
			ID:          "T-1",
			Name:        "sudo",
			Severity:    "High",
			Remediation: "fix",
			Match:       rules.MatchCriteria{Type: "sudo_contains", Contains: "NOPASSWD"},
		}},
	}
	r, _ := s.Scan(context.Background())
	if r.SystemInfo.KernelVersion != "6.1.0-test" {
		t.Fatalf("unexpected kernel: %q", r.SystemInfo.KernelVersion)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
}
