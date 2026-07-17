package report

import (
	"bytes"
	"encoding/csv"
	"reflect"
	"strings"
	"testing"

	"lpe-checker/internal/model"
)

func TestGenerateCSVIncludesBOMHeadersAndFullFindingText(t *testing.T) {
	report := sampleReport()
	report.ScanTarget = "192.0.2.10:22"
	report.Findings[0].Name = "complete finding name that must not be truncated"
	report.Findings[0].Reason = "complete reason that must not end with an ellipsis... marker=FULL"
	report.Findings[0].Remediation = "complete remediation marker=FULL"

	var output bytes.Buffer
	if err := GenerateCSV(&output, report); err != nil {
		t.Fatal(err)
	}
	assertUTF8BOM(t, output.Bytes())
	records := readGeneratedCSV(t, output.Bytes())
	wantHeader := findingCSVHeader()
	if !reflect.DeepEqual(records[0], wantHeader) {
		t.Fatalf("CSV header = %#v; want %#v", records[0], wantHeader)
	}
	wantRow := []string{
		"192.0.2.10:22", "FINDING-1", report.Findings[0].Name, "高危", "已确认", "高",
		report.Findings[0].Reason, report.Findings[0].Remediation,
	}
	if len(records) != 2 || !reflect.DeepEqual(records[1], wantRow) {
		t.Fatalf("CSV records = %#v; want header plus %#v", records, wantRow)
	}
}

func TestGenerateCSVRoundTripsCommasQuotesAndNewlines(t *testing.T) {
	report := sampleReport()
	report.ScanTarget = "198.51.100.20:22"
	report.Findings[0].Name = "name, with comma"
	report.Findings[0].Reason = "reason with \"quotes\"\nand newline"
	report.Findings[0].Remediation = "first line, quoted \"value\"\nsecond line"

	var output bytes.Buffer
	if err := GenerateCSV(&output, report); err != nil {
		t.Fatal(err)
	}
	records := readGeneratedCSV(t, output.Bytes())
	if got := records[1]; got[2] != report.Findings[0].Name || got[6] != report.Findings[0].Reason || got[7] != report.Findings[0].Remediation {
		t.Fatalf("CSV round trip changed full text: %#v", got)
	}
}

func TestGenerateBatchCSVPreservesHostOrderAndUsesScanTarget(t *testing.T) {
	first := sampleReport()
	first.ScanTarget = "192.0.2.10:22"
	first.Findings[0].ID = "FIRST"
	second := sampleReport()
	second.ScanTarget = "198.51.100.20:2222"
	second.Findings[0].ID = "SECOND"
	batch := model.BatchReport{Hosts: []model.BatchReportHost{
		{Target: "ignored-first-target", Report: &first},
		{Target: "failed-host-without-report"},
		{Target: "ignored-second-target", Report: &second},
	}}

	var output bytes.Buffer
	if err := GenerateBatchCSV(&output, batch); err != nil {
		t.Fatal(err)
	}
	records := readGeneratedCSV(t, output.Bytes())
	if len(records) != 3 || records[1][0] != first.ScanTarget || records[1][1] != "FIRST" ||
		records[2][0] != second.ScanTarget || records[2][1] != "SECOND" {
		t.Fatalf("batch CSV host order or scan_target changed: %#v", records)
	}
}

func TestSingleAndOneHostBatchCSVShareFindingRows(t *testing.T) {
	report := sampleReport()
	report.ScanTarget = "203.0.113.10:22"
	batch := model.BatchReport{Hosts: []model.BatchReportHost{{Target: "ignored", Report: &report}}}
	var singleOutput, batchOutput bytes.Buffer
	if err := GenerateCSV(&singleOutput, report); err != nil {
		t.Fatal(err)
	}
	if err := GenerateBatchCSV(&batchOutput, batch); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(singleOutput.Bytes(), batchOutput.Bytes()) {
		t.Fatalf("single and one-host batch CSV drifted\nsingle=%q\nbatch=%q", singleOutput.Bytes(), batchOutput.Bytes())
	}
}

func TestGenerateHostCSVTemplateHasBOMAndExpectedHeader(t *testing.T) {
	var output bytes.Buffer
	if err := GenerateHostCSVTemplate(&output); err != nil {
		t.Fatal(err)
	}
	assertUTF8BOM(t, output.Bytes())
	records := readGeneratedCSV(t, output.Bytes())
	want := []string{"主机", "端口", "用户名", "密码"}
	if len(records) != 1 || !reflect.DeepEqual(records[0], want) {
		t.Fatalf("host CSV template = %#v; want %#v", records, want)
	}
}

func findingCSVHeader() []string {
	return []string{"主机 IP", "风险 ID", "风险名称", "风险等级", "状态", "置信度", "命中原因", "修复建议"}
}

func assertUTF8BOM(t *testing.T, data []byte) {
	t.Helper()
	if !bytes.HasPrefix(data, utf8BOM) {
		t.Fatalf("CSV does not start with UTF-8 BOM: % x", data)
	}
}

func readGeneratedCSV(t *testing.T, data []byte) [][]string {
	t.Helper()
	if !bytes.HasPrefix(data, utf8BOM) {
		t.Fatalf("CSV does not start with UTF-8 BOM: % x", data)
	}
	reader := csv.NewReader(strings.NewReader(string(data[len(utf8BOM):])))
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("generated CSV cannot be read back: %v", err)
	}
	return records
}
