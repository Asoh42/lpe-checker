package display

import (
	"errors"
	"fmt"
	"strings"

	"lpe-checker/internal/collector"
	"lpe-checker/internal/model"
)

var guiText = map[string]string{
	"window_title":         "lpe-checker 远程扫描",
	"host":                 "主机 IP/Host",
	"port":                 "端口",
	"user":                 "用户名",
	"password":             "密码",
	"scan":                 "扫描",
	"scanning":             "扫描中...",
	"export_html":          "导出 HTML",
	"export_json":          "导出 JSON",
	"batch_export_html":    "导出批量 HTML",
	"batch_export_json":    "导出批量 JSON",
	"export_scope":         "批量导出范围",
	"export_all_hosts":     "全部扫描主机",
	"export_selected_host": "仅选中主机",
	"ready":                "请输入 Linux 主机 SSH 信息。",
	"system_placeholder":   "扫描后显示远程系统信息。",
	"scan_no_result":       "本次扫描未成功，无可显示的结果。",
	"finding_id":           "风险 ID",
	"finding_name":         "风险名称",
	"severity":             "风险等级",
	"finding_status":       "状态",
	"confidence":           "置信度",
	"reason":               "命中原因",
	"remediation":          "修复建议",
	"invalid_host_user":    "主机和用户名不能为空。",
	"invalid_port":         "端口必须是 1-65535 之间的整数。",
	"no_report":            "尚无可导出的扫描报告。",
	"no_batch_report":      "尚无可导出的批量扫描结果。",
	"save_failed":          "导出失败",
	"saved":                "报告已导出",
	"scan_init_failed":     "扫描器初始化失败",
	"detection_rules":      "检测规则",
	"select_all":           "全选",
	"select_none":          "全不选",
	"select_one_rule":      "请至少选择一项检测规则。",
	"add_host":             "添加主机",
	"delete_host":          "删除",
	"batch_scan":           "批量扫描",
	"stop_scan":            "停止扫描",
	"host_overview":        "主机总览",
	"host_details":         "主机详情",
	"no_hosts":             "请至少添加一台主机。",
	"invalid_host_row":     "每台主机的地址、端口和用户名都必须有效。",
	"waiting":              "等待",
	"scan_success":         "成功",
	"connection_failed":    "连接失败",
	"command_failed":       "部分采集失败",
	"scan_canceled":        "已取消",
	"scan_panicked":        "扫描异常",
	"no_host_selected":     "请从左侧选择一台主机查看详情。",
	"no_risk":              "未发现风险",
	"import_csv":           "导入 CSV",
	"csv_security":         "CSV 含明文密码，请妥善保管该文件。",
	"csv_open_failed":      "CSV 导入失败",
	"credential_groups":    "凭据组",
	"add_credential":       "添加凭据组",
	"credential_name":      "组名",
	"own_password":         "自己填",
	"password_source":      "密码来源",
	"credential_duplicate": "凭据组名已存在。",
	"credential_required":  "凭据组名和密码不能为空。",
	"confirm":              "确定",
	"cancel":               "取消",
}

func GUIText(key string) string {
	switch key {
	case "export_host_selection_title":
		return "\u9009\u62e9\u8981\u5bfc\u51fa\u7684\u4e3b\u673a"
	case "select_one_export_host":
		return "\u8bf7\u81f3\u5c11\u9009\u62e9\u4e00\u53f0\u4e3b\u673a"
	case "single_report_group":
		return "\u5355\u53f0\u62a5\u544a\uff08\u5f53\u524d\u4e3b\u673a\uff09"
	case "batch_report_group":
		return "\u6279\u91cf\u6c47\u603b"
	case "export_all_html":
		return "\u5bfc\u51fa\u5168\u90e8 HTML"
	case "export_all_json":
		return "\u5bfc\u51fa\u5168\u90e8 JSON"
	case "export_selected_html":
		return "\u5bfc\u51fa\u9009\u4e2d HTML\u2026"
	case "export_selected_json":
		return "\u5bfc\u51fa\u9009\u4e2d JSON\u2026"
	case "export_csv":
		return "\u5bfc\u51fa CSV"
	case "export_all_csv":
		return "\u5bfc\u51fa\u5168\u90e8 CSV"
	case "export_selected_csv":
		return "\u5bfc\u51fa\u9009\u4e2d CSV\u2026"
	case "export_csv_template":
		return "\u5bfc\u51fa CSV \u6a21\u677f"
	default:
		return guiText[key]
	}
}

func GUIExportHostOption(target, scanStatus string, riskCount int) string {
	return fmt.Sprintf("%s | %s | %d \u9879\u98ce\u9669", target, BatchStatusZH(scanStatus), riskCount)
}

func GUIScanSuccess(count int) string {
	return fmt.Sprintf("扫描完成，发现 %d 项风险。", count)
}

func GUIBatchProgress(done, total int) string {
	return fmt.Sprintf("扫描中 %d/%d", done, total)
}

func GUIBatchFinished(total int) string {
	return fmt.Sprintf("批量扫描完成，已处理 %d 台主机。", total)
}

func GUICSVImportResult(imported, skipped int) string {
	return fmt.Sprintf("成功导入 %d 台，跳过 %d 行（无效）。%s", imported, skipped, GUIText("csv_security"))
}

func GUICredentialValidation(host, kind, group string) string {
	switch kind {
	case "own_password_empty":
		return fmt.Sprintf("主机 %s 的自填密码为空。", host)
	case "credential_group_missing":
		return fmt.Sprintf("主机 %s 选择的凭据组 %q 不存在。", host, group)
	case "credential_group_password_empty":
		return fmt.Sprintf("主机 %s 选择的凭据组 %q 密码为空。", host, group)
	default:
		return fmt.Sprintf("主机 %s 的密码配置无效。", host)
	}
}

func BatchStatusZH(status string) string {
	switch status {
	case "waiting":
		return GUIText("waiting")
	case "scanning":
		return GUIText("scanning")
	case "success":
		return GUIText("scan_success")
	case "connection_error":
		return GUIText("connection_failed")
	case "command_error":
		return GUIText("command_failed")
	case "rejected":
		return GUIText("connection_failed")
	case "canceled":
		return GUIText("scan_canceled")
	case "panic":
		return GUIText("scan_panicked")
	default:
		return status
	}
}

func RiskSummaryZH(r model.Report) string {
	if len(r.Findings) == 0 {
		return GUIText("no_risk")
	}
	order := map[string]int{"info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
	highest, rank := "info", 0
	for _, finding := range r.Findings {
		severity := strings.ToLower(finding.Severity)
		if order[severity] > rank {
			highest, rank = severity, order[severity]
		}
	}
	return fmt.Sprintf("%d 项风险（最高：%s）", len(r.Findings), SeverityZH(highest))
}

func GUIErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	var connectionErr *collector.ConnectionError
	if errors.As(err, &connectionErr) {
		return "无法连接主机：" + connectionErr.Err.Error()
	}
	var rejectedErr *collector.CommandNotAllowedError
	if errors.As(err, &rejectedErr) {
		return "命令被只读白名单拒绝：" + rejectedErr.Name
	}
	var commandErr *collector.CommandError
	if errors.As(err, &commandErr) {
		return "扫描完成，但部分采集命令失败：" + commandErr.Error()
	}
	return "扫描失败：" + err.Error()
}

// ReportText returns fixed presentation labels used by exported reports.
func ReportText(key string) string {
	switch key {
	case "scan_target":
		return "\u626b\u63cf\u76ee\u6807"
	case "local":
		return "\u672c\u5730"
	case "scan_failed":
		return "\u626b\u63cf\u5931\u8d25"
	case "scan_time":
		return "\u626b\u63cf\u65f6\u95f4"
	case "failure_reason":
		return "\u5931\u8d25\u539f\u56e0"
	case "check_error":
		return "\u9519\u8bef\u4fe1\u606f"
	case "finding_status":
		return "\u72b6\u6001"
	case "confidence":
		return "\u7f6e\u4fe1\u5ea6"
	case "csv_scan_target":
		return "\u4e3b\u673a IP"
	case "csv_finding_id":
		return "\u98ce\u9669 ID"
	case "csv_finding_name":
		return "\u98ce\u9669\u540d\u79f0"
	case "csv_severity":
		return "\u98ce\u9669\u7b49\u7ea7"
	case "csv_reason":
		return "\u547d\u4e2d\u539f\u56e0"
	case "csv_remediation":
		return "\u4fee\u590d\u5efa\u8bae"
	case "csv_template_host":
		return "\u4e3b\u673a"
	case "csv_template_port":
		return "\u7aef\u53e3"
	case "csv_template_user":
		return "\u7528\u6237\u540d"
	case "csv_template_password":
		return "\u5bc6\u7801"
	default:
		return key
	}
}

func ScanTargetZH(target string) string {
	if strings.EqualFold(strings.TrimSpace(target), "localhost") {
		return ReportText("local")
	}
	return target
}

// ScanErrorCategoryText contains the only error descriptions allowed in an
// exported report. Callers must never append the underlying error text.
func ScanErrorCategoryText(category string) string {
	switch category {
	case "authentication":
		return "\u8ba4\u8bc1\u5931\u8d25\uff08\u5bc6\u7801\u6216\u5bc6\u94a5\u88ab\u62d2\u7edd\uff09"
	case "timeout":
		return "\u8fde\u63a5\u8d85\u65f6"
	case "unreachable":
		return "\u4e3b\u673a\u4e0d\u53ef\u8fbe\u6216\u8fde\u63a5\u88ab\u62d2\u7edd"
	default:
		return "\u626b\u63cf\u5931\u8d25\uff08\u5176\u5b83\u9519\u8bef\uff09"
	}
}

func SystemInfoText(info model.SystemInfo) string {
	return fmt.Sprintf("内核版本: %s\n系统 ID: %s\n系统名称: %s\n系统版本: %s\n系统完整名称: %s\n当前用户: %s\nsudo -l 可用: %t\nsudo -l 原始输出:\n%s\n\nSUID 文件:\n%s",
		info.KernelVersion, info.OSID, info.OSName, info.OSVersionID, info.OSPrettyName,
		info.CurrentUser.Raw, info.SudoList.Available, info.SudoList.Raw, strings.Join(info.SUIDFiles, "\n"))
}

func SeverityZH(v string) string {
	switch v {
	case "critical":
		return "\u4e25\u91cd"
	case "high":
		return "\u9ad8\u5371"
	case "medium":
		return "\u4e2d\u5371"
	case "low":
		return "\u4f4e\u5371"
	case "info":
		return "\u4fe1\u606f"
	default:
		return v
	}
}

func FindingStatusZH(v string) string {
	switch v {
	case "confirmed":
		return "\u5df2\u786e\u8ba4"
	case "suspected":
		return "\u7591\u4f3c"
	case "error":
		return "\u9519\u8bef"
	default:
		return v
	}
}

func ConfidenceZH(v string) string {
	switch v {
	case "high":
		return "\u9ad8"
	case "medium":
		return "\u4e2d"
	case "low":
		return "\u4f4e"
	default:
		return v
	}
}

func CategoryZH(v string) string {
	switch v {
	case "sudo":
		return "sudo \u6743\u9650"
	case "suid":
		return "SUID \u6743\u9650"
	case "path":
		return "PATH \u73af\u5883\u53d8\u91cf"
	case "file-permission":
		return "\u6587\u4ef6\u6743\u9650"
	case "capability":
		return "Linux capabilities"
	case "cron":
		return "\u5b9a\u65f6\u4efb\u52a1"
	case "docker":
		return "Docker \u6743\u9650"
	case "lxd":
		return "LXD \u6743\u9650"
	case "kernel-cve":
		return "Linux \u5185\u6838 CVE"
	case "package-cve":
		return "\u8f6f\u4ef6\u5305 CVE"
	case "os":
		return "\u64cd\u4f5c\u7cfb\u7edf"
	case "kernel":
		return "Linux \u5185\u6838"
	case "user":
		return "\u7528\u6237\u4fe1\u606f"
	default:
		return v
	}
}

func CheckStatusZH(v string) string {
	switch v {
	case "completed":
		return "\u5df2\u5b8c\u6210"
	case "skipped":
		return "\u5df2\u8df3\u8fc7"
	case "failed":
		return "\u68c0\u6d4b\u5931\u8d25"
	default:
		return v
	}
}

func CheckResultZH(v string) string {
	switch v {
	case "found":
		return "\u547d\u4e2d"
	case "not_found":
		return "\u672a\u547d\u4e2d"
	case "unknown":
		return "\u65e0\u6cd5\u5224\u65ad"
	case "not_applicable":
		return "\u4e0d\u9002\u7528"
	default:
		return v
	}
}

// CollectionErrorZH renders the collector's stable, report-safe error code.
// Raw runner errors are deliberately never accepted as part of this format.
func CollectionErrorZH(v string) string {
	command, reason, ok := collector.ParseSafeCollectionError(v)
	if !ok {
		return v
	}
	reasonText := map[string]string{
		collector.CollectionErrorReasonNotFound:   "命令不存在",
		collector.CollectionErrorReasonPermission: "权限不足",
		collector.CollectionErrorReasonTimeout:    "执行超时",
		collector.CollectionErrorReasonCanceled:   "已取消",
		collector.CollectionErrorReasonLocalExit:  "本地命令返回非零状态",
		collector.CollectionErrorReasonRemoteExit: "远程命令返回非零状态",
		collector.CollectionErrorReasonConnection: "连接失败",
		collector.CollectionErrorReasonNotAllowed: "只读白名单拒绝",
		collector.CollectionErrorReasonOther:      "其它错误",
	}[reason]
	if reasonText == "" {
		reasonText = "其它错误"
	}
	return fmt.Sprintf("只读采集命令 %s 失败：%s", command, reasonText)
}

// CheckDescriptionZH preserves the rule-provided description verbatim. Rule
// descriptions are data, so adding a rule must not require an ID-specific
// presentation mapping.
func CheckDescriptionZH(c model.CheckResult) string {
	return c.Description
}

// FindingImpactZH preserves the rule-provided impact verbatim. Rule text is
// data, so adding a rule must not require an ID-specific display mapping.
func FindingImpactZH(f model.Finding) string {
	return f.Impact
}

// FindingRemediationZH preserves the rule-provided remediation verbatim. Rule
// text is data, so adding a rule must not require an ID-specific display map.
func FindingRemediationZH(f model.Finding) string {
	return f.Remediation
}

// FindingFalsePositiveNoteZH preserves the rule-provided note verbatim. Rule
// text is data, so adding a rule must not require an ID-specific display map.
func FindingFalsePositiveNoteZH(f model.Finding) string {
	return f.FalsePositiveNote
}
