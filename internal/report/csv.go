package report

import (
	"encoding/csv"
	"io"
	"strings"

	"lpe-checker/internal/display"
	"lpe-checker/internal/model"
)

var utf8BOM = []byte{0xef, 0xbb, 0xbf}

// GenerateHostCSVTemplate writes an import-compatible, header-only host CSV.
func GenerateHostCSVTemplate(w io.Writer) error {
	return writeCSV(w, [][]string{{
		display.ReportText("csv_template_host"),
		display.ReportText("csv_template_port"),
		display.ReportText("csv_template_user"),
		display.ReportText("csv_template_password"),
	}})
}

// GenerateCSV writes all findings from one report.
func GenerateCSV(w io.Writer, report model.Report) error {
	return generateFindingCSV(w, []model.Report{report})
}

// GenerateBatchCSV writes findings from all successful reports in host order.
func GenerateBatchCSV(w io.Writer, batch model.BatchReport) error {
	reports := make([]model.Report, 0, len(batch.Hosts))
	for _, host := range batch.Hosts {
		if host.Report != nil {
			reports = append(reports, *host.Report)
		}
	}
	return generateFindingCSV(w, reports)
}

func generateFindingCSV(w io.Writer, reports []model.Report) error {
	records := [][]string{{
		display.ReportText("csv_scan_target"),
		display.ReportText("csv_finding_id"),
		display.ReportText("csv_finding_name"),
		display.ReportText("csv_severity"),
		display.ReportText("finding_status"),
		display.ReportText("confidence"),
		display.ReportText("csv_reason"),
		display.ReportText("csv_remediation"),
	}}
	for _, report := range reports {
		for _, finding := range report.Findings {
			records = append(records, []string{
				report.ScanTarget,
				finding.ID,
				finding.Name,
				display.SeverityZH(strings.ToLower(finding.Severity)),
				display.FindingStatusZH(strings.ToLower(finding.Status)),
				display.ConfidenceZH(strings.ToLower(finding.Confidence)),
				finding.Reason,
				display.FindingRemediationZH(finding),
			})
		}
	}
	return writeCSV(w, records)
}

func writeCSV(w io.Writer, records [][]string) error {
	if _, err := w.Write(utf8BOM); err != nil {
		return err
	}
	writer := csv.NewWriter(w)
	if err := writer.WriteAll(records); err != nil {
		return err
	}
	writer.Flush()
	return writer.Error()
}
