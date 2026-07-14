package model

// ToolVersion is the report schema/tool version shown in scan metadata.
const ToolVersion = "0.3.0"

// Meta contains scan metadata useful for reports and integrations.
type Meta struct {
	ToolName    string   `json:"tool_name"`
	ToolVersion string   `json:"tool_version"`
	ScanTime    string   `json:"scan_time"`
	ScanMode    string   `json:"scan_mode"`
	RulesSource []string `json:"rules_source"`
}

// Target describes the scanned host.
type Target struct {
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	IsRoot   bool   `json:"is_root"`
	Host     string `json:"host,omitempty"`
}

// Summary contains severity counters for findings.
type Summary struct {
	TotalFindings   int `json:"total_findings"`
	Critical        int `json:"critical"`
	High            int `json:"high"`
	Medium          int `json:"medium"`
	Low             int `json:"low"`
	Info            int `json:"info"`
	TotalChecks     int `json:"total_checks"`
	CompletedChecks int `json:"completed_checks"`
	SkippedChecks   int `json:"skipped_checks"`
	FailedChecks    int `json:"failed_checks"`
}

// UserGroup is one group membership parsed from id output.
type UserGroup struct {
	GID   string `json:"gid"`
	Group string `json:"group"`
}

// CurrentUser is structured current-user information with the raw id output.
type CurrentUser struct {
	UID      string      `json:"uid"`
	Username string      `json:"username"`
	GID      string      `json:"gid"`
	Group    string      `json:"group"`
	Groups   []UserGroup `json:"groups"`
	Raw      string      `json:"raw"`
}

// SudoList is structured sudo -l information with the raw output.
type SudoList struct {
	Available bool   `json:"available"`
	Raw       string `json:"raw"`
}

// KernelModule contains read-only kernel module observations.
type KernelModule struct {
	Name            string   `json:"name"`
	LoadedStatus    string   `json:"loaded_status"`
	AvailableStatus string   `json:"available_status"`
	Paths           []string `json:"paths"`
	Raw             string   `json:"raw"`
}

// SystemInfo contains host facts collected from the local machine.
type SystemInfo struct {
	Platform         string                  `json:"-"`
	Architecture     string                  `json:"architecture,omitempty"`
	CollectionErrors map[string]string       `json:"collection_errors,omitempty"`
	KernelVersion    string                  `json:"kernel_version"`
	OSID             string                  `json:"os_id"`
	OSName           string                  `json:"os_name"`
	OSVersionID      string                  `json:"os_version_id"`
	OSPrettyName     string                  `json:"os_pretty_name"`
	CurrentUser      CurrentUser             `json:"current_user"`
	SudoList         SudoList                `json:"sudo_list"`
	SUIDFiles        []string                `json:"suid_files"`
	KernelModules    map[string]KernelModule `json:"kernel_modules"`
}

// CheckResult describes one detection item that was executed, skipped, or failed.
type CheckResult struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Category    string `json:"category"`
	Status      string `json:"status"`
	Result      string `json:"result"`
	Description string `json:"description"`
	Evidence    string `json:"evidence"`
	Error       string `json:"error"`
}

// Finding is a normalized vulnerability or hardening finding.
type Finding struct {
	ID                string   `json:"id"`
	CheckID           string   `json:"check_id"`
	Name              string   `json:"name"`
	Severity          string   `json:"severity"`
	Category          string   `json:"category"`
	Confidence        string   `json:"confidence"`
	Status            string   `json:"status"`
	Reason            string   `json:"reason"`
	Evidence          string   `json:"evidence"`
	Impact            string   `json:"impact"`
	Condition         string   `json:"condition"`
	Remediation       string   `json:"remediation"`
	FalsePositiveNote string   `json:"false_positive_note"`
	References        []string `json:"references"`
}

// Report is the full scan output.
type Report struct {
	Meta       Meta          `json:"meta"`
	ScanTarget string        `json:"scan_target,omitempty"`
	Target     Target        `json:"target"`
	Summary    Summary       `json:"summary"`
	SystemInfo SystemInfo    `json:"system_info"`
	Checks     []CheckResult `json:"checks"`
	Findings   []Finding     `json:"findings"`
}

// BatchReportMeta summarizes one exported batch without changing the schema of
// the individual reports it contains.
type BatchReportMeta struct {
	GeneratedAt  string `json:"generated_at"`
	HostCount    int    `json:"host_count"`
	SuccessCount int    `json:"success_count"`
	FailedCount  int    `json:"failed_count"`
}

// BatchReportHost wraps one batch target. Report is present whenever scanning
// produced usable per-host details, including partial command-error reports.
type BatchReportHost struct {
	Target    string  `json:"target"`
	Status    string  `json:"status"`
	Error     string  `json:"error,omitempty"`
	Report    *Report `json:"report,omitempty"`
	ScanError error   `json:"-"`
}

// BatchReport is the top-level JSON/HTML export model for multiple hosts.
type BatchReport struct {
	Meta  BatchReportMeta   `json:"meta"`
	Hosts []BatchReportHost `json:"hosts"`
}

// FailedScanReport is the exportable record for a scan that could not produce
// trustworthy risk details. Status uses the existing check status value failed.
type FailedScanReport struct {
	ScanTarget string `json:"scan_target"`
	ScanTime   string `json:"scan_time"`
	Status     string `json:"status"`
	Error      string `json:"error"`
}
