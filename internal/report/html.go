package report

import (
	"html/template"
	"io"
	"net/url"
	"os"
	"strings"

	"lpe-checker/internal/display"
	"lpe-checker/internal/model"
)

type htmlView struct {
	Report         model.Report
	OSName         string
	User           string
	ConfirmedTitle string
	SuspectedTitle string
	ErrorsTitle    string
	HasCheckErrors bool
	Confirmed      []model.Finding
	Suspected      []model.Finding
	Errors         []model.Finding
}

type refLink struct {
	Text string
	Href string
}

func WriteHTMLFile(path string, r model.Report) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return GenerateHTML(f, r)
}

func GenerateHTML(w io.Writer, r model.Report) error {
	tpl, err := template.New("report").Funcs(htmlTemplateFuncs()).Parse(htmlTemplate)
	if err != nil {
		return err
	}
	return tpl.Execute(w, buildHTMLView(r))
}

func htmlTemplateFuncs() template.FuncMap {
	return template.FuncMap{
		"severityZH":         display.SeverityZH,
		"findingStatusZH":    display.FindingStatusZH,
		"confidenceZH":       display.ConfidenceZH,
		"categoryZH":         display.CategoryZH,
		"checkStatusZH":      display.CheckStatusZH,
		"checkResultZH":      display.CheckResultZH,
		"checkDescriptionZH": display.CheckDescriptionZH,
		"impactZH":           display.FindingImpactZH,
		"remediationZH":      display.FindingRemediationZH,
		"falsePositiveZH":    display.FindingFalsePositiveNoteZH,
		"severityClass":      severityClass,
		"findingStatusClass": findingStatusClass,
		"refs":               referenceLinks,
		"join":               strings.Join,
		"dict":               dict,
		"reportText":         display.ReportText,
		"scanTargetZH":       display.ScanTargetZH,
	}
}

func buildHTMLView(r model.Report) htmlView {
	v := htmlView{
		Report:         r,
		ConfirmedTitle: "\u5df2\u786e\u8ba4\u98ce\u9669",
		SuspectedTitle: "\u7591\u4f3c\u98ce\u9669",
		ErrorsTitle:    "\u68c0\u6d4b\u5931\u8d25\u9879",
	}
	v.OSName = r.SystemInfo.OSPrettyName
	if v.OSName == "" {
		v.OSName = strings.TrimSpace(r.SystemInfo.OSName + " " + r.SystemInfo.OSVersionID)
	}
	v.User = r.SystemInfo.CurrentUser.Username
	if v.User == "" {
		v.User = r.SystemInfo.CurrentUser.Raw
	}
	for _, check := range r.Checks {
		if strings.TrimSpace(check.Error) != "" {
			v.HasCheckErrors = true
			break
		}
	}
	for _, f := range r.Findings {
		switch strings.ToLower(f.Status) {
		case "confirmed":
			v.Confirmed = append(v.Confirmed, f)
		case "error":
			v.Errors = append(v.Errors, f)
		default:
			v.Suspected = append(v.Suspected, f)
		}
	}
	return v
}

func severityClass(sev string) string {
	switch strings.ToLower(sev) {
	case "critical":
		return "sev-critical"
	case "high":
		return "sev-high"
	case "medium":
		return "sev-medium"
	case "low":
		return "sev-low"
	default:
		return "sev-info"
	}
}

func findingStatusClass(status string) string {
	switch strings.ToLower(status) {
	case "confirmed":
		return "status-confirmed"
	case "error":
		return "status-error"
	default:
		return "status-suspected"
	}
}

func referenceLinks(values []string) []refLink {
	links := make([]refLink, 0, len(values))
	for _, v := range values {
		item := refLink{Text: v}
		if u, err := url.Parse(v); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
			item.Href = v
		}
		links = append(links, item)
	}
	return links
}

func dict(values ...any) map[string]any {
	m := make(map[string]any, len(values)/2)
	for i := 0; i+1 < len(values); i += 2 {
		if k, ok := values[i].(string); ok {
			m[k] = values[i+1]
		}
	}
	return m
}

const htmlTemplate = `<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>Linux &#26412;&#22320;&#25552;&#26435;&#39118;&#38505;&#26816;&#27979;&#25253;&#21578;</title>
<style>body{margin:0;background:#f5f7fb;color:#1f2937;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",Arial,sans-serif;line-height:1.55}.wrap{max-width:1180px;margin:0 auto;padding:28px}header{background:#1e40af;color:white;border-radius:16px;padding:28px;margin-bottom:20px}h1{margin:0}h2{border-left:4px solid #2563eb;padding-left:10px}.card{background:white;border:1px solid #e5e7eb;border-radius:14px;padding:18px;margin:16px 0}table{width:100%;border-collapse:collapse}th,td{border-bottom:1px solid #e5e7eb;padding:9px;text-align:left;vertical-align:top}th{background:#f8fafc}.checks thead th{white-space:nowrap}.checks th:nth-child(1),.checks td:nth-child(1){white-space:nowrap;min-width:120px}.checks th:nth-child(3),.checks td:nth-child(3){white-space:nowrap;min-width:64px}.checks th:nth-child(4),.checks td:nth-child(4),.checks th:nth-child(5),.checks td:nth-child(5){white-space:nowrap;min-width:72px}.checks th.check-error{white-space:nowrap;min-width:72px}.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}.pill{display:inline-block;border-radius:999px;padding:2px 9px;font-size:12px;font-weight:700}.sev-critical{background:#7f1d1d;color:white}.sev-high{background:#fee2e2;color:#991b1b}.sev-medium{background:#ffedd5;color:#9a3412}.sev-low{background:#fef9c3;color:#854d0e}.sev-info{background:#dbeafe;color:#1e40af}.status-confirmed{background:#fee2e2;color:#991b1b}.status-suspected{background:#fef3c7;color:#92400e}.status-error{background:#e5e7eb;color:#374151}pre{white-space:pre-wrap;word-break:break-word;background:#0f172a;color:#e2e8f0;border-radius:10px;padding:12px}.finding{border:1px solid #e5e7eb;border-radius:14px;padding:16px;margin:14px 0}.finding table th{white-space:nowrap;min-width:72px}.finding-title{display:flex;gap:8px;align-items:center;flex-wrap:wrap}.note{background:#fff7ed;border:1px solid #fed7aa;color:#9a3412;border-radius:12px;padding:12px}.empty{padding:18px;border:1px dashed #e5e7eb;border-radius:12px;color:#6b7280}.footer{margin-top:24px;color:#475569;font-size:13px;border-top:1px solid #e5e7eb;padding-top:16px}.refs a{color:#2563eb;text-decoration:none}@media(max-width:760px){.grid{grid-template-columns:1fr}}</style></head>
<body><div class="wrap"><header><h1>Linux &#26412;&#22320;&#25552;&#26435;&#39118;&#38505;&#26816;&#27979;&#25253;&#21578;</h1><div>&#30001; lpe-checker &#22522;&#20110;&#21482;&#35835;&#26041;&#24335;&#29983;&#25104;</div></header>
{{template "single-detail" .}}
{{define "single-detail"}}<section class="card"><h2>&#19968;&#12289;&#25195;&#25551;&#20449;&#24687;</h2><table><tr><th>&#24037;&#20855;&#21517;&#31216;</th><td>{{.Report.Meta.ToolName}}</td><th>&#24037;&#20855;&#29256;&#26412;</th><td>{{.Report.Meta.ToolVersion}}</td></tr><tr><th>&#25195;&#25551;&#26102;&#38388;</th><td>{{.Report.Meta.ScanTime}}</td><th>&#25195;&#25551;&#27169;&#24335;</th><td>{{.Report.Meta.ScanMode}}</td></tr>{{if .Report.ScanTarget}}<tr><th>{{reportText "scan_target"}}</th><td colspan="3">{{scanTargetZH .Report.ScanTarget}}</td></tr>{{end}}<tr><th>&#35268;&#21017;&#26469;&#28304;</th><td colspan="3">{{join .Report.Meta.RulesSource ", "}}</td></tr></table></section>
<section class="card"><h2>&#20108;&#12289;&#20027;&#26426;&#20449;&#24687;</h2><table><tr><th>&#20027;&#26426;&#21517;</th><td>{{.Report.Target.Hostname}}</td><th>&#24179;&#21488;</th><td>{{.Report.Target.Platform}}</td></tr><tr><th>&#25805;&#20316;&#31995;&#32479;</th><td>{{.OSName}}</td><th>&#20869;&#26680;&#29256;&#26412;</th><td>{{.Report.SystemInfo.KernelVersion}}</td></tr><tr><th>&#24403;&#21069;&#29992;&#25143;</th><td>{{.User}}</td><th>&#26159;&#21542; root</th><td>{{if .Report.Target.IsRoot}}&#26159;{{else}}&#21542;{{end}}</td></tr></table></section>
<div class="grid"><section class="card"><h2>&#19977;&#12289;&#39118;&#38505;&#32479;&#35745;</h2><table><tr><th>&#39118;&#38505;&#24635;&#25968;</th><td>{{.Report.Summary.TotalFindings}}</td></tr><tr><th>&#20005;&#37325;&#25968;&#37327;</th><td>{{.Report.Summary.Critical}}</td></tr><tr><th>&#39640;&#21361;&#25968;&#37327;</th><td>{{.Report.Summary.High}}</td></tr><tr><th>&#20013;&#21361;&#25968;&#37327;</th><td>{{.Report.Summary.Medium}}</td></tr><tr><th>&#20302;&#21361;&#25968;&#37327;</th><td>{{.Report.Summary.Low}}</td></tr><tr><th>&#20449;&#24687;&#25968;&#37327;</th><td>{{.Report.Summary.Info}}</td></tr></table></section><section class="card"><h2>&#22235;&#12289;&#26816;&#27979;&#39033;&#32479;&#35745;</h2><table><tr><th>&#26816;&#27979;&#39033;&#24635;&#25968;</th><td>{{.Report.Summary.TotalChecks}}</td></tr><tr><th>&#24050;&#23436;&#25104;&#25968;&#37327;</th><td>{{.Report.Summary.CompletedChecks}}</td></tr><tr><th>&#24050;&#36339;&#36807;&#25968;&#37327;</th><td>{{.Report.Summary.SkippedChecks}}</td></tr><tr><th>&#26816;&#27979;&#22833;&#36133;&#25968;&#37327;</th><td>{{.Report.Summary.FailedChecks}}</td></tr></table></section></div>
<section class="card"><h2>&#20116;&#12289;&#26816;&#27979;&#39033;&#26126;&#32454;</h2>{{if .Report.Checks}}<table class="checks"><thead><tr><th>&#26816;&#27979;&#39033; ID</th><th>&#26816;&#27979;&#39033;&#21517;&#31216;</th><th>&#20998;&#31867;</th><th>&#25191;&#34892;&#29366;&#24577;</th><th>&#26816;&#27979;&#32467;&#26524;</th><th>&#35828;&#26126;</th><th>&#35777;&#25454;</th>{{if .HasCheckErrors}}<th class="check-error">{{reportText "check_error"}}</th>{{end}}</tr></thead><tbody>{{range .Report.Checks}}<tr><td>{{.ID}}</td><td>{{.Name}}</td><td>{{categoryZH .Category}}</td><td>{{checkStatusZH .Status}}</td><td>{{checkResultZH .Result}}</td><td>{{checkDescriptionZH .}}</td><td><pre>{{.Evidence}}</pre></td>{{if $.HasCheckErrors}}<td>{{.Error}}</td>{{end}}</tr>{{end}}</tbody></table>{{else}}<div class="empty">&#26410;&#35760;&#24405;&#26816;&#27979;&#39033;&#26126;&#32454;&#12290;</div>{{end}}</section>
<section class="card"><h2>&#20845;&#12289;&#39118;&#38505;&#35814;&#24773;</h2><div class="note">CVE &#26816;&#27979;&#32467;&#26524;&#36890;&#24120;&#22522;&#20110;&#29256;&#26412;&#12289;&#27169;&#22359;&#29366;&#24577;&#25110;&#37197;&#32622;&#36827;&#34892;&#21482;&#35835;&#21028;&#26029;&#65292;&#19981;&#33021;&#23436;&#20840;&#26367;&#20195;&#21378;&#21830;&#23433;&#20840;&#20844;&#21578;&#30830;&#35748;&#12290;&#21457;&#34892;&#29256;&#21487;&#33021;&#23384;&#22312; backport &#20462;&#22797;&#65292;&#38656;&#35201;&#32467;&#21512;&#21378;&#21830;&#20844;&#21578;&#25110;&#36719;&#20214;&#21253; changelog &#36827;&#34892;&#26368;&#32456;&#30830;&#35748;&#12290;</div>{{if .Report.Findings}}{{template "group" dict "Title" .ConfirmedTitle "Items" .Confirmed}}{{template "group" dict "Title" .SuspectedTitle "Items" .Suspected}}{{template "group" dict "Title" .ErrorsTitle "Items" .Errors}}{{else}}<div class="empty">&#26410;&#21457;&#29616;&#39118;&#38505;&#12290;&#35831;&#32467;&#21512;&#8220;&#26816;&#27979;&#39033;&#26126;&#32454;&#8221;&#30830;&#35748;&#26412;&#27425;&#25195;&#25551;&#35206;&#30422;&#33539;&#22260;&#12290;</div>{{end}}</section>
{{end}}<div class="footer">&#20813;&#36131;&#22768;&#26126;&#65306;&#26412;&#25253;&#21578;&#30001; lpe-checker &#22522;&#20110;&#21482;&#35835;&#26041;&#24335;&#29983;&#25104;&#65292;&#19981;&#21253;&#21547;&#28431;&#27934;&#21033;&#29992;&#25110;&#30772;&#22351;&#24615;&#39564;&#35777;&#12290;&#26816;&#27979;&#32467;&#26524;&#20165;&#20316;&#20026;&#23433;&#20840;&#25490;&#26597;&#21442;&#32771;&#65292;&#26368;&#32456;&#32467;&#35770;&#38656;&#32467;&#21512;&#19994;&#21153;&#29615;&#22659;&#12289;&#21378;&#21830;&#20844;&#21578;&#21644;&#20154;&#24037;&#22797;&#26680;&#30830;&#35748;&#12290;</div></div></body></html>
{{define "group"}}{{if .Items}}<h3>{{.Title}}</h3>{{range .Items}}<article class="finding"><div class="finding-title"><span class="pill {{severityClass .Severity}}">{{severityZH .Severity}}</span><span class="pill {{findingStatusClass .Status}}">{{findingStatusZH .Status}}</span><span class="pill sev-info">{{categoryZH .Category}}</span><strong>{{.Name}}</strong></div><table><tr><th>&#32534;&#21495;</th><td>{{.ID}}</td><th>&#20851;&#32852;&#26816;&#27979;&#39033;</th><td>{{.CheckID}}</td></tr><tr><th>&#39118;&#38505;&#31561;&#32423;</th><td>{{severityZH .Severity}}</td><th>{{reportText "confidence"}}</th><td>{{confidenceZH .Confidence}}</td></tr><tr><th>{{reportText "finding_status"}}</th><td>{{findingStatusZH .Status}}</td><th>&#39118;&#38505;&#20998;&#31867;</th><td>{{categoryZH .Category}}</td></tr><tr><th>&#21629;&#20013;&#21407;&#22240;</th><td colspan="3">{{.Reason}}</td></tr><tr><th>&#21407;&#22987;&#35777;&#25454;</th><td colspan="3"><pre>{{.Evidence}}</pre></td></tr><tr><th>&#24433;&#21709;&#35828;&#26126;</th><td colspan="3">{{impactZH .}}</td></tr><tr><th>&#21033;&#29992;&#26465;&#20214;</th><td colspan="3">{{.Condition}}</td></tr><tr><th>&#20462;&#22797;&#24314;&#35758;</th><td colspan="3">{{remediationZH .}}</td></tr><tr><th>&#35823;&#25253;&#35828;&#26126;</th><td colspan="3">{{falsePositiveZH .}}</td></tr><tr><th>&#21442;&#32771;&#38142;&#25509;</th><td colspan="3">{{if .References}}<ul class="refs">{{range refs .References}}<li>{{if .Href}}<a href="{{.Href}}" target="_blank" rel="noopener noreferrer">{{.Text}}</a>{{else}}{{.Text}}{{end}}</li>{{end}}</ul>{{else}}-{{end}}</td></tr></table></article>{{end}}{{end}}{{end}}`
