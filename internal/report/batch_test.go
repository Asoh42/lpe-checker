package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"lpe-checker/internal/model"
)

func TestGenerateBatchHTMLSummaryDetailsAndFailure(t *testing.T) {
	first := sampleReport()
	first.Target.Host = "192.0.2.10"
	first.ScanTarget = "192.0.2.10:22"
	first.Target.Hostname = "host-one"
	first.Findings[0].Status = "suspected"
	first.Findings[0].Confidence = "medium"
	second := sampleReport()
	second.Target.Host = "192.0.2.20"
	second.Target.Hostname = "host-two"
	second.Findings[0].ID = "CVE-2026-31431"
	second.Checks[0].ID = "CHECK-TWO"

	batch := NewBatchReport([]model.BatchReportHost{
		{Target: "192.0.2.10:22", Status: BatchStatusSuccess, Report: &first},
		{Target: "192.0.2.20:22", Status: BatchStatusSuccess, Report: &second},
		{Target: "192.0.2.30:22", Status: BatchStatusFailed, ScanError: errors.New("authentication failed: user=root password=example-password")},
	}, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))

	var output bytes.Buffer
	if err := GenerateBatchHTML(&output, batch); err != nil {
		t.Fatalf("GenerateBatchHTML returned error: %v", err)
	}
	html := output.String()
	for _, expected := range []string{
		"<!doctype html>", "<style>", "主机总览",
		"192.0.2.10:22", "192.0.2.20:22", "192.0.2.30:22",
		"认证失败（密码或密钥被拒绝）", "扫描目标", "CVE-2026-31431",
		"host-one", "host-two", "CHECK-1", "CHECK-TWO",
		"<th>置信度</th><td>中</td>", "<th>状态</th><td>疑似</td>",
		`href="#host-1"`, `id="host-1"`, `href="#host-3"`, `id="host-3"`,
	} {
		if !strings.Contains(html, expected) {
			t.Fatalf("batch HTML missing %q:\n%s", expected, html)
		}
	}
	if strings.Contains(html, "example-password") || strings.Contains(html, "user=root") {
		t.Fatalf("batch HTML leaked the raw authentication error: %s", html)
	}
	if strings.Contains(html, "错误信息") || strings.Contains(html, `class="check-error"`) {
		t.Fatalf("batch details with successful checks unexpectedly rendered the check error column: %s", html)
	}
	if strings.Count(strings.ToLower(html), "<html") != 1 {
		t.Fatalf("batch HTML is not one page: %s", html)
	}
}

func TestGenerateBatchHTMLIncludesSharedCheckErrorColumnWhenNeeded(t *testing.T) {
	hostReport := sampleReport()
	hostReport.Checks[0].Status = "failed"
	hostReport.Checks[0].Result = "unknown"
	hostReport.Checks[0].Error = ClassifyScanError(errors.New("unclassified internal detail"))
	batch := NewBatchReport([]model.BatchReportHost{
		{Target: "192.0.2.10:22", Status: BatchStatusSuccess, Report: &hostReport},
	}, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))

	var output bytes.Buffer
	if err := GenerateBatchHTML(&output, batch); err != nil {
		t.Fatalf("GenerateBatchHTML returned error: %v", err)
	}
	html := output.String()
	for _, expected := range []string{`<th class="check-error">错误信息</th>`, "扫描失败（其它错误）"} {
		if !strings.Contains(html, expected) {
			t.Fatalf("batch HTML missing shared check error detail %q: %s", expected, html)
		}
	}
	if strings.Contains(html, "unclassified internal detail") {
		t.Fatalf("batch HTML leaked the raw check error: %s", html)
	}
}

func TestGenerateBatchJSONRoundTrip(t *testing.T) {
	report := sampleReport()
	report.Target.Host = "192.0.2.10"
	batch := NewBatchReport([]model.BatchReportHost{
		{Target: "192.0.2.10:22", Status: BatchStatusSuccess, Report: &report},
		{Target: "192.0.2.30:22", Status: BatchStatusFailed, ScanError: errors.New("dial tcp 192.0.2.30:22: connection refused")},
	}, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))

	var output bytes.Buffer
	if err := GenerateBatchJSON(&output, batch); err != nil {
		t.Fatalf("GenerateBatchJSON returned error: %v", err)
	}
	var decoded model.BatchReport
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil {
		t.Fatalf("batch JSON cannot be decoded: %v\n%s", err, output.String())
	}
	if decoded.Meta.HostCount != 2 || decoded.Meta.SuccessCount != 1 || decoded.Meta.FailedCount != 1 || len(decoded.Hosts) != 2 {
		t.Fatalf("unexpected batch metadata: %+v", decoded)
	}
	if decoded.Hosts[0].Report == nil || decoded.Hosts[0].Report.Target.Host != "192.0.2.10" || len(decoded.Hosts[0].Report.Findings) != 1 {
		t.Fatalf("successful report was not preserved: %+v", decoded.Hosts[0])
	}
	if decoded.Hosts[1].Status != BatchStatusFailed || decoded.Hosts[1].Error != "主机不可达或连接被拒绝" || decoded.Hosts[1].Report != nil {
		t.Fatalf("failed host was not represented correctly: %+v", decoded.Hosts[1])
	}
	if strings.Contains(output.String(), "dial tcp") || strings.Contains(output.String(), "connection refused") {
		t.Fatalf("batch JSON leaked the raw connection error: %s", output.String())
	}
}

func TestGenerateBatchReportsEmptyAndAllFailed(t *testing.T) {
	tests := []struct {
		name  string
		hosts []model.BatchReportHost
	}{
		{name: "empty"},
		{name: "all failed", hosts: []model.BatchReportHost{
			{Target: "192.0.2.30:22", Status: BatchStatusFailed, ScanError: errors.New("timeout")},
			{Target: "192.0.2.31:22", Status: BatchStatusFailed, ScanError: errors.New("authentication failed")},
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			batch := NewBatchReport(tt.hosts, time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC))
			var htmlOutput, jsonOutput bytes.Buffer
			if err := GenerateBatchHTML(&htmlOutput, batch); err != nil {
				t.Fatalf("GenerateBatchHTML returned error: %v", err)
			}
			if err := GenerateBatchJSON(&jsonOutput, batch); err != nil {
				t.Fatalf("GenerateBatchJSON returned error: %v", err)
			}
			if !strings.Contains(htmlOutput.String(), "<html") || !json.Valid(jsonOutput.Bytes()) {
				t.Fatalf("invalid empty/failed batch output: html=%q json=%q", htmlOutput.String(), jsonOutput.String())
			}
		})
	}
}
