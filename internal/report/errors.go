package report

import (
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"net"
	"strings"
	"time"

	"lpe-checker/internal/display"
	"lpe-checker/internal/model"
)

const (
	scanErrorAuthentication = "authentication"
	scanErrorTimeout        = "timeout"
	scanErrorUnreachable    = "unreachable"
	scanErrorOther          = "other"
)

// ClassifyScanError maps an arbitrary underlying error to a fixed report-safe
// description. The original error is inspected only for classification and is
// never included in the returned string.
func ClassifyScanError(err error) string {
	category := scanErrorOther
	if err != nil {
		for _, allowed := range []string{
			display.ScanErrorCategoryText(scanErrorAuthentication),
			display.ScanErrorCategoryText(scanErrorTimeout),
			display.ScanErrorCategoryText(scanErrorUnreachable),
			display.ScanErrorCategoryText(scanErrorOther),
		} {
			if err.Error() == allowed {
				return allowed
			}
		}
		message := strings.ToLower(err.Error())
		switch {
		case containsAny(message,
			"authentication failed", "unable to authenticate", "permission denied",
			"no supported methods remain", "attempted methods", "password rejected",
			"publickey rejected"):
			category = scanErrorAuthentication
		case errors.Is(err, context.DeadlineExceeded), isTimeout(err), containsAny(message,
			"timeout", "timed out", "deadline exceeded", "i/o timeout"):
			category = scanErrorTimeout
		case containsAny(message,
			"connection refused", "no route to host", "network is unreachable",
			"network unreachable", "host is unreachable", "host unreachable",
			"host is down", "no such host", "connection reset by peer", "dial tcp",
			"actively refused", "no connection could be made", "connectex"):
			category = scanErrorUnreachable
		}
	}
	return display.ScanErrorCategoryText(category)
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if strings.Contains(value, candidate) {
			return true
		}
	}
	return false
}

func isTimeout(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}

func NewFailedScanReport(scanTarget, scanTime string, err error) model.FailedScanReport {
	if strings.TrimSpace(scanTime) == "" {
		scanTime = time.Now().UTC().Format(time.RFC3339)
	}
	return model.FailedScanReport{
		ScanTarget: scanTarget,
		ScanTime:   scanTime,
		Status:     "failed",
		Error:      ClassifyScanError(err),
	}
}

func GenerateFailedScanJSON(w io.Writer, failed model.FailedScanReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(failed)
}

func GenerateFailedScanHTML(w io.Writer, failed model.FailedScanReport) error {
	tpl, err := template.New("failed-report").Funcs(template.FuncMap{
		"reportText":   display.ReportText,
		"scanTargetZH": display.ScanTargetZH,
	}).Parse(failedScanHTMLTemplate)
	if err != nil {
		return err
	}
	return tpl.Execute(w, failed)
}

const failedScanHTMLTemplate = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>lpe-checker {{reportText "scan_failed"}}</title>
<style>body{margin:0;background:#f5f7fb;color:#1f2937;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",Arial,sans-serif;line-height:1.55}.wrap{max-width:900px;margin:0 auto;padding:28px}header{background:#991b1b;color:white;border-radius:16px;padding:28px;margin-bottom:20px}.card{background:white;border:1px solid #e5e7eb;border-radius:14px;padding:18px}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #e5e7eb;padding:10px;text-align:left}th{width:160px;background:#f8fafc}.failure{color:#991b1b;font-weight:700}</style></head>
<body><div class="wrap"><header><h1>lpe-checker {{reportText "scan_failed"}}</h1></header><section class="card"><table>
<tr><th>{{reportText "scan_target"}}</th><td>{{scanTargetZH .ScanTarget}}</td></tr>
<tr><th>{{reportText "scan_time"}}</th><td>{{.ScanTime}}</td></tr>
<tr><th>{{reportText "scan_failed"}}</th><td>{{.Status}}</td></tr>
<tr><th>{{reportText "failure_reason"}}</th><td class="failure">{{.Error}}</td></tr>
</table></section></div></body></html>`
