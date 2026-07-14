package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"lpe-checker/internal/collector"
	"lpe-checker/internal/model"
)

func TestClassifyScanErrorUsesFixedMessages(t *testing.T) {
	authRaw := "ssh authentication failed for user=root password=example-password: unable to authenticate"
	tests := []struct {
		name string
		err  error
		want string
	}{
		{name: "authentication", err: &collector.ConnectionError{Err: errors.New(authRaw)}, want: "认证失败（密码或密钥被拒绝）"},
		{name: "timeout", err: context.DeadlineExceeded, want: "连接超时"},
		{name: "unreachable", err: errors.New("dial tcp 192.0.2.1:22: connection refused"), want: "主机不可达或连接被拒绝"},
		{name: "other", err: errors.New("private backend detail"), want: "扫描失败（其它错误）"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyScanError(tt.err)
			if got != tt.want {
				t.Fatalf("ClassifyScanError() = %q, want %q", got, tt.want)
			}
			if strings.Contains(got, "example-password") || strings.Contains(got, "user=root") || strings.Contains(got, "private backend detail") {
				t.Fatalf("classification leaked raw error: %q", got)
			}
		})
	}
}

func TestFailedScanReportHTMLAndJSONDoNotLeakRawError(t *testing.T) {
	raw := errors.New("ssh: unable to authenticate user=admin password=example-password")
	failed := NewFailedScanReport("203.0.113.9:22", "2026-07-13T12:34:56Z", raw)
	if failed.Status != "failed" || failed.Error != "认证失败（密码或密钥被拒绝）" {
		t.Fatalf("unexpected failed report: %+v", failed)
	}

	var htmlOutput, jsonOutput bytes.Buffer
	if err := GenerateFailedScanHTML(&htmlOutput, failed); err != nil {
		t.Fatal(err)
	}
	if err := GenerateFailedScanJSON(&jsonOutput, failed); err != nil {
		t.Fatal(err)
	}
	for kind, output := range map[string]string{"HTML": htmlOutput.String(), "JSON": jsonOutput.String()} {
		for _, expected := range []string{"203.0.113.9:22", "2026-07-13T12:34:56Z", "failed", "认证失败（密码或密钥被拒绝）"} {
			if !strings.Contains(output, expected) {
				t.Fatalf("%s failure report missing %q: %s", kind, expected, output)
			}
		}
		if strings.Contains(output, "example-password") || strings.Contains(output, "user=admin") || strings.Contains(output, "finding") {
			t.Fatalf("%s failure report leaked raw/risk detail: %s", kind, output)
		}
	}
	var decoded model.FailedScanReport
	if err := json.Unmarshal(jsonOutput.Bytes(), &decoded); err != nil || decoded != failed {
		t.Fatalf("failed JSON round trip: decoded=%+v err=%v", decoded, err)
	}
}
