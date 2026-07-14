package rules

import (
	"strings"
	"testing"

	"lpe-checker/internal/model"
)

func TestParseUpstreamVersion(t *testing.T) {
	tests := []struct {
		input string
		want  [3]int
		ok    bool
	}{
		{input: "3.10.0-1160.45.1.el7.x86_64", want: [3]int{3, 10, 0}, ok: true},
		{input: "5.15.0-91-generic", want: [3]int{5, 15, 0}, ok: true},
		{input: "5.16.11", want: [3]int{5, 16, 11}, ok: true},
		{input: "5.8", want: [3]int{5, 8, 0}, ok: true},
		{input: "4.18", want: [3]int{4, 18, 0}, ok: true},
		{input: "", ok: false},
		{input: "garbage", ok: false},
	}
	for _, tt := range tests {
		got, ok := parseUpstreamVersion(tt.input)
		if ok != tt.ok || got != tt.want {
			t.Fatalf("parseUpstreamVersion(%q) = %v, %v; want %v, %v", tt.input, got, ok, tt.want, tt.ok)
		}
	}
}

func TestKernelVersionRangeBoundaries(t *testing.T) {
	tests := []struct {
		name       string
		current    string
		introduced string
		fixed      string
		want       bool
	}{
		{name: "inside", current: "5.15.0", introduced: "5.8", fixed: "5.16.11", want: true},
		{name: "fixed excluded", current: "5.16.11", introduced: "5.8", fixed: "5.16.11", want: false},
		{name: "introduced included", current: "5.8.0", introduced: "5.8", fixed: "5.16.11", want: true},
		{name: "below lower", current: "5.7.9", introduced: "5.8", fixed: "5.16.11", want: false},
		{name: "above upper", current: "5.17.0", introduced: "5.8", fixed: "5.16.11", want: false},
		{name: "unrelated old", current: "3.10.0", introduced: "5.8", fixed: "5.16.11", want: false},
		{name: "lower only match", current: "6.0", introduced: "5.8", want: true},
		{name: "lower only miss", current: "5.7", introduced: "5.8", want: false},
		{name: "upper only match", current: "5.0", fixed: "5.16.11", want: true},
		{name: "upper only miss", current: "5.17", fixed: "5.16.11", want: false},
		{name: "bad current", current: "garbage", introduced: "5.8", fixed: "5.16.11", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, got := matchKernelVersionRange(tt.current, MatchCriteria{Introduced: tt.introduced, Fixed: tt.fixed})
			if got != tt.want {
				t.Fatalf("match=%v; want %v", got, tt.want)
			}
		})
	}
}

func TestEvaluateKernelVersionRangeFindingAndCheck(t *testing.T) {
	rule := kernelVersionRangeRuleForTest()
	findings, checks := EvaluateWithChecks(model.SystemInfo{
		Platform:      "linux",
		KernelVersion: "5.15.0-91-generic",
	}, []Rule{rule})
	if len(findings) != 1 || len(checks) != 1 {
		t.Fatalf("unexpected findings/checks: %+v %+v", findings, checks)
	}
	finding := findings[0]
	if finding.Status != "suspected" || finding.Confidence != "medium" || finding.Severity != "critical" {
		t.Fatalf("unexpected forced classification: %+v", finding)
	}
	if checks[0].Result != "found" || checks[0].Status != "completed" {
		t.Fatalf("unexpected check: %+v", checks[0])
	}
	for _, expected := range []string{
		"kernel_version_raw=5.15.0-91-generic",
		"upstream_version=5.15.0",
		"introduced=5.8",
		"fixed=5.16.11",
		"false_positive_note=",
	} {
		if !strings.Contains(finding.Evidence, expected) {
			t.Fatalf("evidence missing %q: %s", expected, finding.Evidence)
		}
	}
	if finding.FalsePositiveNote != kernelVersionRangeFalsePositiveNote {
		t.Fatalf("unexpected false-positive note: %q", finding.FalsePositiveNote)
	}
}

func TestEvaluateKernelVersionRangeNotFoundNonLinuxAndCollectionFailure(t *testing.T) {
	rule := kernelVersionRangeRuleForTest()

	findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: "5.17.0"}, []Rule{rule})
	if len(findings) != 0 || len(checks) != 1 || checks[0].Result != "not_found" || checks[0].Status != "completed" {
		t.Fatalf("unexpected not-found result: %+v %+v", findings, checks)
	}

	findings, checks = EvaluateWithChecks(model.SystemInfo{Platform: "windows", KernelVersion: "5.15.0"}, []Rule{rule})
	if len(findings) != 0 || checks[0].Status != "skipped" || checks[0].Result != "not_applicable" {
		t.Fatalf("unexpected non-linux result: %+v %+v", findings, checks)
	}

	findings, checks = EvaluateWithChecks(model.SystemInfo{
		Platform:         "linux",
		KernelVersion:    "",
		CollectionErrors: map[string]string{"kernel": "uname failed"},
	}, []Rule{rule})
	if len(findings) != 0 || checks[0].Status != "failed" || checks[0].Result != "unknown" || checks[0].Error != "uname failed" {
		t.Fatalf("unexpected collection-failure result: %+v %+v", findings, checks)
	}
}

func TestKernelVersionRangeRuleValidation(t *testing.T) {
	tests := []struct {
		name  string
		match string
		want  string
	}{
		{name: "no bounds", match: "", want: "requires introduced or fixed"},
		{name: "bad introduced", match: "      introduced: garbage\n", want: "introduced"},
		{name: "bad fixed", match: "      fixed: nope\n", want: "fixed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yamlText := "rules:\n" +
				"  - id: TEST-RANGE\n" +
				"    name: test range\n" +
				"    severity: high\n" +
				"    remediation: verify vendor advisory\n" +
				"    match:\n" +
				"      type: kernel_version_range\n" + tt.match
			_, err := parseRules([]byte(yamlText), "inline.yaml")
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected validation error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func kernelVersionRangeRuleForTest() Rule {
	return Rule{
		ID:          "TEST-KERNEL-RANGE",
		Name:        "test upstream kernel range",
		Severity:    "Critical",
		Category:    "kernel-cve",
		Confidence:  "high",
		Status:      "confirmed",
		Description: "test only",
		Match: MatchCriteria{
			Type:       "kernel_version_range",
			Introduced: "5.8",
			Fixed:      "5.16.11",
		},
		Remediation: "verify vendor advisory",
	}
}
