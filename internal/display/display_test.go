package display

import (
	"errors"
	"strings"
	"testing"

	"lpe-checker/internal/collector"
	"lpe-checker/internal/model"
)

func TestGUIErrorMessageClassification(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{err: &collector.ConnectionError{Err: errors.New("timeout")}, want: "无法连接主机"},
		{err: &collector.CommandError{Name: "find", Err: errors.New("exit 1")}, want: "部分采集命令失败"},
		{err: &collector.CommandNotAllowedError{Name: "sh"}, want: "只读白名单拒绝"},
	}
	for _, tt := range tests {
		if got := GUIErrorMessage(tt.err); !strings.Contains(got, tt.want) {
			t.Fatalf("GUIErrorMessage(%T) = %q; want substring %q", tt.err, got, tt.want)
		}
	}
}

func TestFindingStatusZH(t *testing.T) {
	tests := map[string]string{
		"confirmed": "已确认",
		"suspected": "疑似",
		"error":     "错误",
		"future":    "future",
	}
	for input, want := range tests {
		if got := FindingStatusZH(input); got != want {
			t.Errorf("FindingStatusZH(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestConfidenceZH(t *testing.T) {
	tests := map[string]string{
		"high":   "高",
		"medium": "中",
		"low":    "低",
		"future": "future",
	}
	for input, want := range tests {
		if got := ConfidenceZH(input); got != want {
			t.Errorf("ConfidenceZH(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestFindingPresentationLabels(t *testing.T) {
	if got := GUIText("finding_status"); got != "状态" {
		t.Fatalf("GUIText(finding_status) = %q; want 状态", got)
	}
	if got := GUIText("confidence"); got != "置信度" {
		t.Fatalf("GUIText(confidence) = %q; want 置信度", got)
	}
	if got := ReportText("finding_status"); got != "状态" {
		t.Fatalf("ReportText(finding_status) = %q; want 状态", got)
	}
	if got := ReportText("confidence"); got != "置信度" {
		t.Fatalf("ReportText(confidence) = %q; want 置信度", got)
	}
	if got := ReportText("check_error"); got != "错误信息" {
		t.Fatalf("ReportText(check_error) = %q; want 错误信息", got)
	}
}

func TestCheckResultZH(t *testing.T) {
	tests := map[string]string{
		"found":          "命中",
		"not_found":      "未命中",
		"unknown":        "无法判断",
		"not_applicable": "不适用",
		"future":         "future",
	}
	for input, want := range tests {
		if got := CheckResultZH(input); got != want {
			t.Errorf("CheckResultZH(%q) = %q; want %q", input, got, want)
		}
	}
}

func TestCollectionErrorZH(t *testing.T) {
	got := CollectionErrorZH("collection_error:timeout:uname -r")
	if got != "只读采集命令 uname -r 失败：执行超时" {
		t.Fatalf("CollectionErrorZH() = %q", got)
	}
	if got := CollectionErrorZH("legacy safe text"); got != "legacy safe text" {
		t.Fatalf("unknown collection error format changed: %q", got)
	}
}

// Rule descriptions must pass through unchanged for every ID. This preserves
// the architecture rule that adding a CVE is a YAML-only change and never
// requires an ID-specific display mapping.
func TestCheckDescriptionPreservesRuleTextForEveryID(t *testing.T) {
	tests := []model.CheckResult{
		{ID: "CVE-2026-31431", Description: "description from the algif_aead rule"},
		{ID: "LPE-SUDO-NOPASSWD", Description: "description from the sudo rule"},
		{ID: "LPE-SUID-PKEXEC", Description: "description from the pkexec rule"},
		{ID: "LPE-SUID-FIND", Description: "description from the find rule"},
		{ID: "LPE-SUID-BASH", Description: "description from the bash rule"},
		{ID: "LPE-SUID-VIM", Description: "description from the vim rule"},
		{ID: "CVE-FUTURE-YAML-ONLY", Description: "description supplied by a future YAML rule"},
	}
	for _, check := range tests {
		if got := CheckDescriptionZH(check); got != check.Description {
			t.Errorf("CheckDescriptionZH(%q) = %q; want rule description %q", check.ID, got, check.Description)
		}
	}
}

// Finding rule text must pass through unchanged for every ID. Adding a rule is
// a YAML-only operation and must never require an ID-specific display mapping.
func TestFindingRuleTextPreservedForEveryID(t *testing.T) {
	tests := []model.Finding{
		{ID: "LPE-SUDO-NOPASSWD", Impact: "sudo impact", Remediation: "sudo remediation", FalsePositiveNote: "sudo note"},
		{ID: "LPE-SUID-PKEXEC", Impact: "pkexec impact", Remediation: "pkexec remediation", FalsePositiveNote: "pkexec note"},
		{ID: "CVE-2026-31431", Impact: "algif impact", Remediation: "algif remediation", FalsePositiveNote: "algif note"},
		{ID: "CVE-FUTURE-YAML-ONLY", Impact: "future impact", Remediation: "future remediation", FalsePositiveNote: "future note"},
	}
	for _, finding := range tests {
		if got := FindingImpactZH(finding); got != finding.Impact {
			t.Errorf("FindingImpactZH(%q) = %q; want YAML impact %q", finding.ID, got, finding.Impact)
		}
		if got := FindingRemediationZH(finding); got != finding.Remediation {
			t.Errorf("FindingRemediationZH(%q) = %q; want YAML remediation %q", finding.ID, got, finding.Remediation)
		}
		if got := FindingFalsePositiveNoteZH(finding); got != finding.FalsePositiveNote {
			t.Errorf("FindingFalsePositiveNoteZH(%q) = %q; want YAML note %q", finding.ID, got, finding.FalsePositiveNote)
		}
	}
}
