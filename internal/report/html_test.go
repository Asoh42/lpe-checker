package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"lpe-checker/internal/model"
)

func TestWriteHTMLFile(t *testing.T) {
	r := sampleReport()
	path := filepath.Join(t.TempDir(), "report.html")
	if err := WriteHTMLFile(path, r); err != nil {
		t.Fatalf("WriteHTMLFile failed: %v", err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read html: %v", err)
	}
	html := string(b)
	mustContain(t, html, "Linux &#26412;&#22320;&#25552;&#26435;&#39118;&#38505;&#26816;&#27979;&#25253;&#21578;")
	mustContain(t, html, "test-host")
	mustContain(t, html, "6.1.0-test")
	mustContain(t, html, "CHECK-1")
	mustContain(t, html, "FINDING-1")
	mustContain(t, html, "evidence line")
	mustContain(t, html, "\u5df2\u786e\u8ba4\u98ce\u9669")
	mustContain(t, html, "https://example.com/advisory")
	mustContain(t, html, "href=\"https://example.com/advisory\"")
}

func TestGenerateHTMLEmptyFindings(t *testing.T) {
	r := sampleReport()
	r.Findings = nil
	r.Summary.TotalFindings = 0
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, r); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	mustContain(t, buf.String(), "&#26410;&#21457;&#29616;&#39118;&#38505;")
}

func TestScanTargetHTMLAndJSON(t *testing.T) {
	remote := sampleReport()
	remote.ScanTarget = "192.0.2.10:2222"
	var htmlOutput bytes.Buffer
	if err := GenerateHTML(&htmlOutput, remote); err != nil {
		t.Fatal(err)
	}
	mustContain(t, htmlOutput.String(), "扫描目标")
	mustContain(t, htmlOutput.String(), "192.0.2.10:2222")

	local := sampleReport()
	local.ScanTarget = "localhost"
	htmlOutput.Reset()
	if err := GenerateHTML(&htmlOutput, local); err != nil {
		t.Fatal(err)
	}
	mustContain(t, htmlOutput.String(), "本地")

	empty := sampleReport()
	empty.ScanTarget = ""
	encoded, err := json.Marshal(empty)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "scan_target") {
		t.Fatalf("empty scan_target was not omitted: %s", encoded)
	}
	htmlOutput.Reset()
	if err := GenerateHTML(&htmlOutput, empty); err != nil {
		t.Fatalf("empty scan_target HTML failed: %v", err)
	}
}

func TestGenerateHTMLEscapesSpecialChars(t *testing.T) {
	r := sampleReport()
	r.Checks[0].Evidence = `<script>alert("check")</script>`
	r.Findings[0].Evidence = `<script>alert("finding")</script>`
	r.Findings[0].Remediation = `<b>do not render</b>`
	var buf bytes.Buffer
	if err := GenerateHTML(&buf, r); err != nil {
		t.Fatalf("GenerateHTML failed: %v", err)
	}
	html := buf.String()
	mustContain(t, html, "&lt;script&gt;alert")
	mustContain(t, html, "&lt;b&gt;do not render&lt;/b&gt;")
	if strings.Contains(html, `<script>alert("finding")</script>`) || strings.Contains(html, `<b>do not render</b>`) {
		t.Fatalf("html contains unescaped user-controlled content: %s", html)
	}
}

func sampleReport() model.Report {
	return model.Report{
		Meta:       model.Meta{ToolName: "lpe-checker", ToolVersion: "test", ScanTime: "2026-07-09T00:00:00Z", ScanMode: "local", RulesSource: []string{"builtin"}},
		ScanTarget: "localhost",
		Target:     model.Target{Hostname: "test-host", Platform: "linux/amd64", IsRoot: true},
		Summary:    model.Summary{TotalFindings: 1, High: 1, TotalChecks: 1, CompletedChecks: 1},
		SystemInfo: model.SystemInfo{KernelVersion: "6.1.0-test", OSPrettyName: "Test Linux", CurrentUser: model.CurrentUser{Username: "root", Raw: "uid=0(root)"}},
		Checks:     []model.CheckResult{{ID: "CHECK-1", Name: "Check sudo", Category: "sudo", Status: "completed", Result: "found", Description: "check description", Evidence: "evidence line"}},
		Findings:   []model.Finding{{ID: "FINDING-1", CheckID: "CHECK-1", Name: "Finding name", Severity: "high", Category: "sudo", Confidence: "high", Status: "confirmed", Reason: "reason", Evidence: "evidence line", Impact: "impact", Condition: "condition", Remediation: "remediation", FalsePositiveNote: "note", References: []string{"https://example.com/advisory"}}},
	}
}

func mustContain(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Fatalf("expected html to contain %q\nhtml=%s", want, got)
	}
}
