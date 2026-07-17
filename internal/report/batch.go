package report

import (
	"encoding/json"
	"errors"
	"html/template"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"lpe-checker/internal/display"
	"lpe-checker/internal/model"
)

const (
	BatchStatusSuccess = "success"
	BatchStatusFailed  = "failed"
)

// NewBatchReport creates a normalized aggregate around existing per-host
// reports. Any status other than success is represented as failed.
func NewBatchReport(hosts []model.BatchReportHost, generatedAt time.Time) model.BatchReport {
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	batch := model.BatchReport{
		Meta:  model.BatchReportMeta{GeneratedAt: generatedAt.UTC().Format(time.RFC3339), HostCount: len(hosts)},
		Hosts: append([]model.BatchReportHost{}, hosts...),
	}
	for index := range batch.Hosts {
		if batch.Hosts[index].Status == BatchStatusSuccess && batch.Hosts[index].Report != nil {
			batch.Hosts[index].Error = ""
			batch.Hosts[index].ScanError = nil
			batch.Meta.SuccessCount++
		} else {
			batch.Hosts[index].Status = BatchStatusFailed
			scanErr := batch.Hosts[index].ScanError
			if scanErr == nil && strings.TrimSpace(batch.Hosts[index].Error) != "" {
				scanErr = errors.New(batch.Hosts[index].Error)
			}
			batch.Hosts[index].Error = ClassifyScanError(scanErr)
			batch.Hosts[index].ScanError = nil
			batch.Meta.FailedCount++
		}
	}
	return batch
}

func WriteBatchHTMLFile(path string, batch model.BatchReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return GenerateBatchHTML(f, batch)
}

func GenerateBatchHTML(w io.Writer, batch model.BatchReport) error {
	tpl, err := template.New("report").Funcs(htmlTemplateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	if _, err = tpl.Parse(batchHTMLTemplate); err != nil {
		return err
	}
	return tpl.ExecuteTemplate(w, "batch", buildBatchHTMLView(batch))
}

func WriteBatchJSONFile(path string, batch model.BatchReport) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return GenerateBatchJSON(f, batch)
}

func GenerateBatchJSON(w io.Writer, batch model.BatchReport) error {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(batch)
}

type batchHTMLView struct {
	Batch model.BatchReport
	Hosts []batchHostHTMLView
}

type batchHostHTMLView struct {
	Item       model.BatchReportHost
	Anchor     string
	StatusZH   string
	RiskCount  int
	HighestZH  string
	FindingIDs string
	HasReport  bool
	Detail     htmlView
}

func buildBatchHTMLView(batch model.BatchReport) batchHTMLView {
	view := batchHTMLView{Batch: batch, Hosts: make([]batchHostHTMLView, 0, len(batch.Hosts))}
	for index, item := range batch.Hosts {
		host := batchHostHTMLView{
			Item:      item,
			Anchor:    "host-" + strconv.Itoa(index+1),
			StatusZH:  "失败",
			HighestZH: "-",
		}
		if item.Status == BatchStatusSuccess {
			host.StatusZH = "成功"
		}
		if item.Report != nil {
			host.HasReport = true
			host.Detail = buildHTMLView(*item.Report)
			host.RiskCount = item.Report.Summary.TotalFindings
			host.HighestZH = highestSeverityZH(item.Report.Findings)
			host.FindingIDs = findingIDSummary(item.Report.Findings)
		}
		view.Hosts = append(view.Hosts, host)
	}
	return view
}

func highestSeverityZH(findings []model.Finding) string {
	rank := map[string]int{"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
	highest := ""
	for _, finding := range findings {
		severity := strings.ToLower(finding.Severity)
		if rank[severity] > rank[highest] {
			highest = severity
		}
	}
	if highest == "" {
		return "-"
	}
	return display.SeverityZH(highest)
}

func findingIDSummary(findings []model.Finding) string {
	const maximum = 5
	seen := make(map[string]struct{})
	ids := make([]string, 0, len(findings))
	for _, finding := range findings {
		if finding.ID == "" {
			continue
		}
		if _, ok := seen[finding.ID]; ok {
			continue
		}
		seen[finding.ID] = struct{}{}
		ids = append(ids, finding.ID)
	}
	if len(ids) == 0 {
		return "-"
	}
	if len(ids) > maximum {
		return strings.Join(ids[:maximum], ", ") + ", ..."
	}
	return strings.Join(ids, ", ")
}

const batchHTMLTemplate = `{{define "batch"}}<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>lpe-checker 批量扫描汇总报告</title>
<style>` + reportCSS + `</style></head>
<body class="batch-report"><div class="wrap"><header><h1>lpe-checker 批量扫描汇总报告</h1><div>生成时间：{{.Batch.Meta.GeneratedAt}}　主机数：{{.Batch.Meta.HostCount}}　成功：{{.Batch.Meta.SuccessCount}}　失败：{{.Batch.Meta.FailedCount}}</div></header>
<section class="card summary"><h2>主机总览</h2>{{if .Hosts}}<table><thead><tr><th>目标主机</th><th>状态</th><th>风险数</th><th>最高风险</th><th>命中概览</th><th>错误</th></tr></thead><tbody>{{range .Hosts}}<tr><td><a href="#{{.Anchor}}">{{.Item.Target}}</a></td><td>{{.StatusZH}}</td><td>{{.RiskCount}}</td><td>{{.HighestZH}}</td><td>{{.FindingIDs}}</td><td>{{.Item.Error}}</td></tr>{{end}}</tbody></table>{{else}}<div class="empty">没有可导出的主机结果。</div>{{end}}</section>
{{range .Hosts}}<section id="{{.Anchor}}" class="host-detail"><h2>{{.Item.Target}} — {{.StatusZH}}</h2>{{if .Item.Error}}<div class="failure">{{.Item.Error}}</div>{{end}}{{if .HasReport}}{{template "single-detail" .Detail}}{{else if not .Item.Error}}<div class="empty">该主机没有可用的扫描明细。</div>{{end}}</section>{{end}}
<div class="footer">免责声明：本报告由 lpe-checker 基于只读方式生成，不包含漏洞利用或破坏性验证。检测结果仅作为安全排查参考，最终结论需结合厂商公告和人工复核确认。</div></div></body></html>{{end}}`
