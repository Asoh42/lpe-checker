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
		return "\u68c0\u6d4b\u5931\u8d25"
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
		return "\u53d1\u73b0\u98ce\u9669"
	case "not_found":
		return "\u672a\u53d1\u73b0"
	case "unknown":
		return "\u65e0\u6cd5\u5224\u65ad"
	case "not_applicable":
		return "\u4e0d\u9002\u7528"
	default:
		return v
	}
}

// CheckDescriptionZH returns the Chinese presentation text for built-in checks.
// External rules keep their original description so the report does not alter
// user-provided rule content.
func CheckDescriptionZH(c model.CheckResult) string {
	switch c.ID {
	case "CVE-2026-31431":
		return "\u4f7f\u7528\u53ea\u8bfb\u65b9\u5f0f\u542f\u53d1\u5f0f\u68c0\u67e5 Linux \u5185\u6838 algif_aead \u6a21\u5757\u4e0e CVE-2026-31431 \u7684\u7591\u4f3c\u66b4\u9732\u6761\u4ef6\u3002\u8be5\u7ed3\u679c\u4ec5\u7528\u4e8e\u63d0\u793a\u8fdb\u4e00\u6b65\u6838\u5bf9\uff0c\u4e0d\u4ee3\u8868\u786e\u8ba4\u5b58\u5728\u53ef\u5229\u7528\u6f0f\u6d1e\u3002"
	case "LPE-SUDO-NOPASSWD":
		return "\u68c0\u67e5\u5f53\u524d\u7528\u6237\u662f\u5426\u53ef\u4ee5\u901a\u8fc7 sudo \u514d\u5bc6\u6267\u884c\u547d\u4ee4\uff0c\u8be5\u914d\u7f6e\u53ef\u80fd\u5f62\u6210\u672c\u5730\u63d0\u6743\u8def\u5f84\u3002"
	case "LPE-SUID-PKEXEC":
		return "\u68c0\u67e5 pkexec \u662f\u5426\u5b58\u5728 SUID \u6743\u9650\u3002pkexec \u662f\u5e38\u89c1\u7684\u672c\u5730\u63d0\u6743\u653b\u51fb\u9762\uff0c\u9700\u7ee7\u7eed\u6838\u5bf9\u5df2\u5b89\u88c5\u7684 polkit \u7248\u672c\u3002"
	case "LPE-SUID-FIND":
		return "\u68c0\u67e5 find \u662f\u5426\u5b58\u5728 SUID \u6743\u9650\u3002\u5177\u6709 SUID \u6743\u9650\u7684 find \u53ef\u80fd\u88ab\u7528\u4e8e\u6267\u884c\u9ad8\u6743\u9650\u547d\u4ee4\u3002"
	case "LPE-SUID-BASH":
		return "\u68c0\u67e5 bash \u662f\u5426\u5b58\u5728 SUID \u6743\u9650\u3002\u8be5\u914d\u7f6e\u53ef\u80fd\u4f7f\u4ea4\u4e92\u5f0f shell \u4fdd\u7559\u9ad8\u6743\u9650\uff0c\u5c5e\u4e8e\u4e25\u91cd\u7684\u672c\u5730\u63d0\u6743\u98ce\u9669\u3002"
	case "LPE-SUID-VIM":
		return "\u68c0\u67e5 vim \u662f\u5426\u5b58\u5728 SUID \u6743\u9650\u3002\u5177\u6709 SUID \u6743\u9650\u7684 vim \u53ef\u80fd\u901a\u8fc7\u7f16\u8f91\u5668\u547d\u4ee4\u6267\u884c\u5916\u90e8\u7a0b\u5e8f\u3002"
	default:
		return c.Description
	}
}

func FindingImpactZH(f model.Finding) string {
	switch f.ID {
	case "LPE-SUDO-NOPASSWD":
		return "sudoers \u4e2d\u5b58\u5728\u514d\u5bc6 sudo \u914d\u7f6e\u65f6\uff0c\u5f53\u524d\u7528\u6237\u53ef\u80fd\u901a\u8fc7\u5141\u8bb8\u7684\u547d\u4ee4\u63d0\u5347\u5230 root \u6216\u5176\u4ed6\u9ad8\u6743\u9650\u8d26\u6237\u3002"
	case "LPE-SUID-PKEXEC":
		return "pkexec \u5177\u6709 SUID \u4f4d\u65f6\u4f1a\u589e\u52a0\u672c\u5730\u63d0\u6743\u653b\u51fb\u9762\uff1b\u5982\u679c polkit \u7248\u672c\u5b58\u5728\u5df2\u77e5\u6f0f\u6d1e\u6216\u914d\u7f6e\u4e0d\u5f53\uff0c\u53ef\u80fd\u88ab\u672c\u5730\u7528\u6237\u5229\u7528\u3002"
	case "CVE-2026-31431":
		return "\u5982\u679c\u8fd0\u884c\u4e2d\u7684 Linux \u5185\u6838\u786e\u5b9e\u53d7 CVE-2026-31431 \u5f71\u54cd\uff0c\u76f8\u5173\u5185\u6838\u914d\u7f6e\u53ef\u80fd\u66b4\u9732\u672c\u5730\u63d0\u6743\u653b\u51fb\u9762\uff1b\u5f53\u524d\u7ed3\u679c\u4ec5\u4e3a\u7591\u4f3c\u5224\u65ad\u3002"
	default:
		if f.Impact != "" {
			return f.Impact
		}
		return "\u6682\u65e0\u989d\u5916\u5f71\u54cd\u8bf4\u660e\u3002"
	}
}

func FindingRemediationZH(f model.Finding) string {
	switch f.ID {
	case "LPE-SUDO-NOPASSWD":
		return "\u6700\u5c0f\u5316 sudoers \u6743\u9650\uff0c\u79fb\u9664\u4e0d\u5fc5\u8981\u7684 NOPASSWD \u914d\u7f6e\uff0c\u5e76\u9650\u5236\u5141\u8bb8\u6267\u884c\u7684\u547d\u4ee4\u8303\u56f4\u3002"
	case "LPE-SUID-PKEXEC":
		return "\u786e\u8ba4 polkit \u5df2\u5347\u7ea7\u5230\u5382\u5546\u4fee\u590d\u7248\u672c\uff1b\u5982\u679c\u4e1a\u52a1\u4e0d\u9700\u8981 pkexec\uff0c\u53ef\u8bc4\u4f30\u79fb\u9664 SUID \u4f4d\u6216\u7981\u7528\u76f8\u5173\u7ec4\u4ef6\u3002"
	case "CVE-2026-31431":
		return "\u7ed3\u5408\u5382\u5546\u516c\u544a\u548c\u5f53\u524d\u5185\u6838\u5305\u7248\u672c\u786e\u8ba4\u662f\u5426\u53d7\u5f71\u54cd\uff1b\u5982\u786e\u8ba4\u53d7\u5f71\u54cd\uff0c\u8bf7\u5b89\u88c5\u5382\u5546\u63d0\u4f9b\u7684\u5185\u6838\u5b89\u5168\u66f4\u65b0\u5e76\u91cd\u542f\u8fdb\u5165\u4fee\u590d\u540e\u7684\u5185\u6838\u3002\u4e0d\u8981\u4ec5\u51ed\u8be5\u542f\u53d1\u5f0f\u7ed3\u679c\u5224\u65ad\u6700\u7ec8\u98ce\u9669\u3002"
	default:
		return f.Remediation
	}
}

func FindingFalsePositiveNoteZH(f model.Finding) string {
	switch f.ID {
	case "LPE-SUDO-NOPASSWD":
		return "\u90e8\u5206\u81ea\u52a8\u5316\u8d26\u6237\u53ef\u80fd\u786e\u5b9e\u9700\u8981\u53d7\u9650\u7684 NOPASSWD \u914d\u7f6e\uff1b\u8bf7\u6838\u5bf9\u5141\u8bb8\u6267\u884c\u7684\u547d\u4ee4\u8303\u56f4\u548c\u4e1a\u52a1\u5fc5\u8981\u6027\u3002"
	case "LPE-SUID-PKEXEC":
		return "pkexec \u5728\u5f88\u591a\u53d1\u884c\u7248\u4e2d\u9ed8\u8ba4\u5177\u6709 SUID \u4f4d\uff1b\u8be5\u7ed3\u679c\u63d0\u793a\u9700\u8981\u7ee7\u7eed\u6838\u5bf9 polkit \u7248\u672c\u548c\u5382\u5546\u4fee\u590d\u72b6\u6001\uff0c\u4e0d\u7b49\u540c\u4e8e\u786e\u8ba4\u5b58\u5728\u53ef\u5229\u7528\u6f0f\u6d1e\u3002"
	case "CVE-2026-31431":
		return "\u8be5\u89c4\u5219\u4e0d\u6267\u884c\u6f0f\u6d1e\u5229\u7528\uff0c\u4e5f\u4e0d\u8bc1\u660e\u5185\u6838\u4e00\u5b9a\u5b58\u5728\u6f0f\u6d1e\uff1b\u6a21\u5757\u5b58\u5728\u6216\u72b6\u6001 unknown \u4ec5\u8868\u793a\u9700\u8981\u7ed3\u5408\u5382\u5546\u516c\u544a\u8fdb\u4e00\u6b65\u786e\u8ba4\u3002"
	default:
		return f.FalsePositiveNote
	}
}
