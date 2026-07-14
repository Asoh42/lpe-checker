package rules

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"lpe-checker/internal/model"
)

//go:embed builtin/*.yaml
var builtinFS embed.FS

// Rule describes a simple local LPE detection rule loaded from YAML.
type Rule struct {
	ID                string        `yaml:"id"`
	Name              string        `yaml:"name"`
	Severity          string        `yaml:"severity"`
	Category          string        `yaml:"category"`
	Confidence        string        `yaml:"confidence"`
	Status            string        `yaml:"status"`
	Description       string        `yaml:"description"`
	Affected          Affected      `yaml:"affected"`
	Match             MatchCriteria `yaml:"match"`
	Reason            string        `yaml:"reason"`
	EvidenceTemplate  string        `yaml:"evidence_template"`
	Impact            string        `yaml:"impact"`
	Condition         string        `yaml:"condition"`
	Remediation       string        `yaml:"remediation"`
	FalsePositiveNote string        `yaml:"false_positive_note"`
	References        []string      `yaml:"references"`
}

type Affected struct {
	Component string `yaml:"component"`
	Module    string `yaml:"module"`
	OS        string `yaml:"os"`
}

type MatchCriteria struct {
	Type       string   `yaml:"type"`
	Contains   string   `yaml:"contains"`
	Path       string   `yaml:"path"`
	OSID       string   `yaml:"os_id"`
	Module     string   `yaml:"module"`
	Modules    []string `yaml:"modules"`
	Introduced string   `yaml:"introduced"`
	Fixed      string   `yaml:"fixed"`
}

const kernelVersionRangeFalsePositiveNote = "This assessment is based only on the upstream kernel version and does not account for distribution backports of fixes or vulnerable code; verify vendor/distribution security advisories and the actual patch level manually, and do not treat it as confirmed."

var kernelModuleNamePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// LoadResult contains loaded rules and human-readable rule sources.
type LoadResult struct {
	Rules   []Rule
	Sources []string
}

// LoadDefault loads embedded builtin rules first, then optional external YAML rules.
// If extraDir is empty, ./rules is loaded only when it exists. If extraDir is set,
// that directory must exist and be readable. Duplicate IDs are resolved by letting
// the external rule override the builtin rule.
func LoadDefault(extraDir string) ([]Rule, error) {
	result, err := LoadDefaultWithSources(extraDir)
	if err != nil {
		return nil, err
	}
	return result.Rules, nil
}

func LoadDefaultWithSources(extraDir string) (LoadResult, error) {
	builtin, err := LoadBuiltin()
	if err != nil {
		return LoadResult{}, err
	}
	result := LoadResult{Rules: builtin, Sources: []string{"builtin"}}

	externalDir := extraDir
	optional := false
	if externalDir == "" {
		externalDir = "rules"
		optional = true
	}

	external, err := LoadDirOptional(externalDir, optional)
	if err != nil {
		return LoadResult{}, err
	}
	if len(external) > 0 {
		result.Rules = mergeByID(builtin, external)
		result.Sources = append(result.Sources, externalDir)
	}
	return result, nil
}

func LoadBuiltin() ([]Rule, error) {
	return loadDirFS(builtinFS, "builtin")
}

func LoadDirOptional(dir string, optional bool) ([]Rule, error) {
	if dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if optional && os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []Rule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		rules, err := LoadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

func LoadDir(dir string) ([]Rule, error) {
	return LoadDirOptional(dir, false)
}

func LoadFile(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return parseRules(b, path)
}

func loadDirFS(fsys fs.FS, dir string) ([]Rule, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, err
	}
	var out []Rule
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := strings.ToLower(e.Name())
		if !strings.HasSuffix(name, ".yaml") && !strings.HasSuffix(name, ".yml") {
			continue
		}
		path := filepath.ToSlash(filepath.Join(dir, e.Name()))
		b, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil, err
		}
		rules, err := parseRules(b, path)
		if err != nil {
			return nil, err
		}
		out = append(out, rules...)
	}
	return out, nil
}

func parseRules(b []byte, source string) ([]Rule, error) {
	var wrapper struct {
		Rules []Rule `yaml:"rules"`
	}
	if err := yaml.Unmarshal(b, &wrapper); err != nil {
		return nil, err
	}
	if len(wrapper.Rules) == 0 {
		var single Rule
		if err := yaml.Unmarshal(b, &single); err != nil {
			return nil, err
		}
		if single.ID != "" {
			wrapper.Rules = []Rule{single}
		}
	}
	for _, r := range wrapper.Rules {
		if r.ID == "" || r.Name == "" || r.Severity == "" || r.Remediation == "" || r.Match.Type == "" {
			return nil, fmt.Errorf("invalid rule in %s: id, name, severity, remediation and match.type are required", source)
		}
		if r.Match.Type == "kernel_version_range" {
			if strings.TrimSpace(r.Match.Introduced) == "" && strings.TrimSpace(r.Match.Fixed) == "" {
				return nil, fmt.Errorf("invalid rule %s in %s: kernel_version_range requires introduced or fixed", r.ID, source)
			}
			if err := validateUpstreamVersionBounds(r.Match); err != nil {
				return nil, fmt.Errorf("invalid rule %s in %s: %w", r.ID, source, err)
			}
		}
		if r.Match.Type == "kernel_cve_module" {
			if _, err := kernelCVEModuleNamesForRule(r); err != nil {
				return nil, fmt.Errorf("invalid rule %s in %s: %w", r.ID, source, err)
			}
			if err := validateUpstreamVersionBounds(r.Match); err != nil {
				return nil, fmt.Errorf("invalid rule %s in %s: %w", r.ID, source, err)
			}
		}
	}
	return wrapper.Rules, nil
}

func validateUpstreamVersionBounds(criteria MatchCriteria) error {
	if criteria.Introduced != "" {
		if _, ok := parseUpstreamVersion(criteria.Introduced); !ok {
			return fmt.Errorf("introduced %q is not a valid upstream kernel version", criteria.Introduced)
		}
	}
	if criteria.Fixed != "" {
		if _, ok := parseUpstreamVersion(criteria.Fixed); !ok {
			return fmt.Errorf("fixed %q is not a valid upstream kernel version", criteria.Fixed)
		}
	}
	return nil
}

// KernelCVEModuleNames returns the validated union of module names declared by
// kernel_cve_module rules, preserving first declaration order.
func KernelCVEModuleNames(ruleSet []Rule) ([]string, error) {
	seen := make(map[string]struct{})
	var names []string
	for _, rule := range ruleSet {
		if rule.Match.Type != "kernel_cve_module" {
			continue
		}
		declared, err := kernelCVEModuleNamesForRule(rule)
		if err != nil {
			return nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		for _, name := range declared {
			if _, ok := seen[name]; ok {
				continue
			}
			seen[name] = struct{}{}
			names = append(names, name)
		}
	}
	return names, nil
}

func kernelCVEModuleNamesForRule(rule Rule) ([]string, error) {
	names := append([]string{}, rule.Match.Modules...)
	if rule.Match.Module != "" {
		names = append(names, rule.Match.Module)
	}
	if len(names) == 0 && rule.Affected.Module != "" {
		names = append(names, rule.Affected.Module)
	}
	if len(names) == 0 {
		return nil, errors.New("kernel_cve_module requires module or modules")
	}
	seen := make(map[string]struct{}, len(names))
	validated := make([]string, 0, len(names))
	for _, name := range names {
		if !kernelModuleNamePattern.MatchString(name) {
			return nil, fmt.Errorf("module name %q must match [a-z0-9_-]+", name)
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		validated = append(validated, name)
	}
	return validated, nil
}

func mergeByID(base, override []Rule) []Rule {
	merged := make([]Rule, 0, len(base)+len(override))
	index := make(map[string]int, len(base)+len(override))
	for _, r := range base {
		index[r.ID] = len(merged)
		merged = append(merged, r)
	}
	for _, r := range override {
		if i, ok := index[r.ID]; ok {
			merged[i] = r
			continue
		}
		index[r.ID] = len(merged)
		merged = append(merged, r)
	}
	return merged
}

func Evaluate(info model.SystemInfo, rs []Rule) []model.Finding {
	findings, _ := EvaluateWithChecks(info, rs)
	return findings
}

func EvaluateWithChecks(info model.SystemInfo, rs []Rule) ([]model.Finding, []model.CheckResult) {
	findings := make([]model.Finding, 0)
	checks := make([]model.CheckResult, 0, len(rs))
	for _, r := range rs {
		check := newCheckResult(r)
		if skipped, reason := skipReason(info, r); skipped {
			check.Status = "skipped"
			check.Result = "not_applicable"
			check.Evidence = reason
			checks = append(checks, check)
			continue
		}
		if collectionErr := collectionErrorForRule(info, r); collectionErr != "" {
			check.Status = "failed"
			check.Result = "unknown"
			check.Error = collectionErr
			check.Evidence = "required collection data unavailable"
			checks = append(checks, check)
			continue
		}

		match, ok := matchRule(info, r)
		if ok {
			check.Status = "completed"
			check.Result = "found"
			check.Evidence = renderEvidence(r, match)
			checks = append(checks, check)
			findingStatus := normalizeStatus(defaultString(r.Status, "confirmed"))
			findingConfidence := normalizeConfidence(defaultString(r.Confidence, "high"))
			falsePositiveNote := r.FalsePositiveNote
			if r.Match.Type == "kernel_version_range" {
				findingStatus = "suspected"
				findingConfidence = "medium"
				falsePositiveNote = kernelVersionRangeFalsePositiveNote
			} else if r.Match.Type == "kernel_cve_module" {
				findingStatus = "suspected"
				findingConfidence = "medium"
			}
			findings = append(findings, model.Finding{
				ID:                r.ID,
				CheckID:           check.ID,
				Name:              r.Name,
				Severity:          normalizeSeverity(r.Severity),
				Category:          defaultString(r.Category, categoryForRule(r)),
				Confidence:        findingConfidence,
				Status:            findingStatus,
				Reason:            defaultString(r.Reason, match.reason),
				Evidence:          check.Evidence,
				Impact:            defaultString(r.Impact, r.Description),
				Condition:         defaultString(r.Condition, conditionForRule(r)),
				Remediation:       r.Remediation,
				FalsePositiveNote: falsePositiveNote,
				References:        nonNilStrings(r.References),
			})
			continue
		}

		check.Status = "completed"
		check.Result = "not_found"
		check.Evidence = "condition not met: " + conditionForRule(r)
		checks = append(checks, check)
	}
	return findings, checks
}

func collectionErrorForRule(info model.SystemInfo, r Rule) string {
	key := ""
	switch r.Match.Type {
	case "kernel_contains", "kernel_version_range":
		key = "kernel"
	case "os_id", "os_release_contains":
		key = "os_release"
	case "sudo_contains":
		key = "sudo"
	case "suid_path":
		key = "suid"
	case "user_contains":
		key = "user"
	}
	if key == "" || info.CollectionErrors == nil {
		return ""
	}
	return info.CollectionErrors[key]
}

func newCheckResult(r Rule) model.CheckResult {
	return model.CheckResult{
		ID:          r.ID,
		Name:        checkName(r),
		Category:    defaultString(r.Category, categoryForRule(r)),
		Status:      "completed",
		Result:      "unknown",
		Description: defaultString(r.Description, r.Name),
		Evidence:    "",
		Error:       "",
	}
}

func checkName(r Rule) string {
	if r.Category == "kernel-cve" || r.Match.Type == "kernel_cve_module" || r.Match.Type == "kernel_version_range" {
		return "Check " + r.ID + " exposure conditions"
	}
	return "Check " + r.Name
}

func skipReason(info model.SystemInfo, r Rule) (bool, string) {
	if (r.Match.Type == "kernel_cve_module" || r.Match.Type == "kernel_version_range") && info.Platform != "linux" {
		return true, "skipped because target platform is not Linux"
	}
	return false, ""
}

type ruleMatch struct {
	reason   string
	evidence string
}

func matchRule(info model.SystemInfo, r Rule) (ruleMatch, bool) {
	contains := strings.ToLower(r.Match.Contains)
	switch r.Match.Type {
	case "kernel_contains":
		return containsMatch("kernel version", info.KernelVersion, contains)
	case "kernel_version_range":
		return matchKernelVersionRange(info.KernelVersion, r.Match)
	case "kernel_cve_module":
		return matchKernelCVEModule(info, r)
	case "os_id":
		expected := defaultString(r.Match.OSID, r.Match.Contains)
		if expected != "" && info.OSID != "" && strings.EqualFold(info.OSID, expected) {
			return ruleMatch{reason: "OS ID matched: " + info.OSID, evidence: "os_id=" + info.OSID}, true
		}
	case "sudo_contains":
		return containsMatch("sudo -l output", info.SudoList.Raw, contains)
	case "suid_path":
		for _, p := range info.SUIDFiles {
			if r.Match.Path != "" && p == r.Match.Path {
				return ruleMatch{reason: "SUID file present: " + p, evidence: p}, true
			}
			if contains != "" && strings.Contains(strings.ToLower(p), contains) {
				return ruleMatch{reason: "SUID file present: " + p, evidence: p}, true
			}
		}
	case "user_contains":
		return containsMatch("id output", info.CurrentUser.Raw, contains)
	case "os_release_contains":
		osText := strings.Join([]string{info.OSID, info.OSName, info.OSVersionID, info.OSPrettyName}, " ")
		return containsMatch("OS release", osText, contains)
	}
	return ruleMatch{}, false
}

func parseUpstreamVersion(value string) ([3]int, bool) {
	var version [3]int
	upstream := strings.TrimSpace(value)
	if upstream == "" {
		return version, false
	}
	if index := strings.IndexByte(upstream, '-'); index >= 0 {
		upstream = upstream[:index]
	}
	parts := strings.Split(upstream, ".")
	if len(parts) < 2 {
		return version, false
	}
	major, ok := parseLeadingDecimal(parts[0])
	if !ok {
		return version, false
	}
	minor, ok := parseLeadingDecimal(parts[1])
	if !ok {
		return version, false
	}
	version[0], version[1] = major, minor
	if len(parts) >= 3 {
		patch, ok := parseLeadingDecimal(parts[2])
		if !ok {
			return [3]int{}, false
		}
		version[2] = patch
	}
	return version, true
}

func parseLeadingDecimal(value string) (int, bool) {
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	parsed, err := strconv.Atoi(value[:end])
	return parsed, err == nil
}

func matchKernelVersionRange(current string, criteria MatchCriteria) (ruleMatch, bool) {
	currentVersion, parsed, within := upstreamVersionInRange(current, criteria)
	if !parsed || !within {
		return ruleMatch{}, false
	}
	introduced := strings.TrimSpace(criteria.Introduced)
	fixed := strings.TrimSpace(criteria.Fixed)
	evidence := strings.Join([]string{
		"kernel_version_raw=" + current,
		fmt.Sprintf("upstream_version=%d.%d.%d", currentVersion[0], currentVersion[1], currentVersion[2]),
		"introduced=" + introduced,
		"fixed=" + fixed,
		"false_positive_note=" + kernelVersionRangeFalsePositiveNote,
	}, "\n")
	return ruleMatch{
		reason:   fmt.Sprintf("upstream kernel version %d.%d.%d is within the configured suspected range", currentVersion[0], currentVersion[1], currentVersion[2]),
		evidence: evidence,
	}, true
}

// upstreamVersionInRange is the shared parser and [introduced,fixed) boundary
// evaluator used by version-only and module-plus-version rules.
func upstreamVersionInRange(current string, criteria MatchCriteria) ([3]int, bool, bool) {
	currentVersion, ok := parseUpstreamVersion(current)
	if !ok {
		return [3]int{}, false, false
	}
	if strings.TrimSpace(criteria.Introduced) != "" {
		introduced, valid := parseUpstreamVersion(criteria.Introduced)
		if !valid || compareUpstreamVersions(currentVersion, introduced) < 0 {
			return currentVersion, true, false
		}
	}
	if strings.TrimSpace(criteria.Fixed) != "" {
		fixed, valid := parseUpstreamVersion(criteria.Fixed)
		if !valid || compareUpstreamVersions(currentVersion, fixed) >= 0 {
			return currentVersion, true, false
		}
	}
	return currentVersion, true, true
}

func compareUpstreamVersions(left, right [3]int) int {
	for index := range left {
		if left[index] < right[index] {
			return -1
		}
		if left[index] > right[index] {
			return 1
		}
	}
	return 0
}

func matchKernelCVEModule(info model.SystemInfo, r Rule) (ruleMatch, bool) {
	if info.Platform != "linux" {
		return ruleMatch{}, false
	}
	moduleNames, err := kernelCVEModuleNamesForRule(r)
	if err != nil {
		return ruleMatch{}, false
	}
	type matchedModule struct {
		name   string
		module model.KernelModule
		status string
	}
	matched := make([]matchedModule, 0, len(moduleNames))
	for _, moduleName := range moduleNames {
		module, ok := info.KernelModules[moduleName]
		if !ok {
			module = model.KernelModule{Name: moduleName, LoadedStatus: "unknown", AvailableStatus: "unknown", Paths: []string{}}
		}
		moduleStatus := kernelModuleStatus(module)
		if moduleStatus == "not_found" || moduleStatus == "not_loaded" {
			continue
		}
		matched = append(matched, matchedModule{name: moduleName, module: module, status: moduleStatus})
	}
	if len(matched) == 0 {
		return ruleMatch{}, false
	}
	versionEvidence := ""
	if strings.TrimSpace(r.Match.Introduced) != "" || strings.TrimSpace(r.Match.Fixed) != "" {
		currentVersion, parsed, within := upstreamVersionInRange(info.KernelVersion, r.Match)
		if parsed && !within {
			return ruleMatch{}, false
		}
		parts := []string{
			"introduced=" + strings.TrimSpace(r.Match.Introduced),
			"fixed=" + strings.TrimSpace(r.Match.Fixed),
		}
		if parsed {
			parts = append(parts,
				fmt.Sprintf("upstream_version=%d.%d.%d", currentVersion[0], currentVersion[1], currentVersion[2]),
				"version_range_status=matched",
			)
		} else {
			parts = append(parts,
				"version_range_status=undetermined",
				"version_note=current kernel version could not be parsed; module presence remains suspected",
			)
		}
		versionEvidence = strings.Join(parts, "\n")
	}
	if len(moduleNames) == 1 {
		item := matched[0]
		evidence := kernelModuleEvidence(info, item.name, item.module, item.status)
		if versionEvidence != "" {
			evidence += "\n" + versionEvidence
		}
		return ruleMatch{
			reason:   fmt.Sprintf("Linux host has kernel module %s status %s; CVE rule is suspected and requires vendor confirmation", item.name, item.status),
			evidence: evidence,
		}, true
	}
	statuses := make([]string, 0, len(matched))
	evidence := make([]string, 0, len(matched))
	for _, item := range matched {
		statuses = append(statuses, item.name+"="+item.status)
		evidence = append(evidence, kernelModuleEvidence(info, item.name, item.module, item.status))
	}
	joinedEvidence := strings.Join(evidence, "\n")
	if versionEvidence != "" {
		joinedEvidence += "\n" + versionEvidence
	}
	return ruleMatch{
		reason:   fmt.Sprintf("Linux host has matching kernel module status %s; CVE family rule is suspected and requires vendor confirmation", strings.Join(statuses, ", ")),
		evidence: joinedEvidence,
	}, true
}

func kernelModuleStatus(module model.KernelModule) string {
	if module.LoadedStatus == "loaded" {
		return "loaded"
	}
	if module.AvailableStatus == "available" {
		return "available"
	}
	if module.LoadedStatus == "unknown" || module.AvailableStatus == "unknown" {
		return "unknown"
	}
	if module.AvailableStatus == "not_found" {
		return "not_found"
	}
	return "not_loaded"
}

func kernelModuleEvidence(info model.SystemInfo, moduleName string, module model.KernelModule, moduleStatus string) string {
	parts := []string{
		"os=linux",
		"kernel_version=" + info.KernelVersion,
		"module=" + moduleName,
		"module_status=" + moduleStatus,
		"loaded_status=" + module.LoadedStatus,
		"available_status=" + module.AvailableStatus,
	}
	if len(module.Paths) > 0 {
		parts = append(parts, "module_paths="+strings.Join(module.Paths, ","))
	}
	if moduleStatus == "unknown" && module.Raw != "" {
		parts = append(parts, "note="+module.Raw)
	}
	return strings.Join(parts, "\n")
}

func containsMatch(label, value, needle string) (ruleMatch, bool) {
	if needle == "" {
		return ruleMatch{}, false
	}
	if strings.Contains(strings.ToLower(value), needle) {
		return ruleMatch{reason: fmt.Sprintf("%s contains %q", label, needle), evidence: value}, true
	}
	return ruleMatch{}, false
}

func conditionForRule(r Rule) string {
	parts := []string{"type=" + r.Match.Type}
	if r.Match.Path != "" {
		parts = append(parts, "path="+r.Match.Path)
	}
	if r.Match.Contains != "" {
		parts = append(parts, "contains="+r.Match.Contains)
	}
	if r.Match.OSID != "" {
		parts = append(parts, "os_id="+r.Match.OSID)
	}
	if r.Match.Module != "" {
		parts = append(parts, "module="+r.Match.Module)
	}
	if len(r.Match.Modules) > 0 {
		parts = append(parts, "modules="+strings.Join(r.Match.Modules, ","))
	}
	if r.Match.Introduced != "" {
		parts = append(parts, "introduced="+r.Match.Introduced)
	}
	if r.Match.Fixed != "" {
		parts = append(parts, "fixed="+r.Match.Fixed)
	}
	if r.Affected.Component != "" {
		parts = append(parts, "affected.component="+r.Affected.Component)
	}
	if r.Affected.Module != "" {
		parts = append(parts, "affected.module="+r.Affected.Module)
	}
	if r.Affected.OS != "" {
		parts = append(parts, "affected.os="+r.Affected.OS)
	}
	return strings.Join(parts, "; ")
}

func categoryForRule(r Rule) string {
	switch r.Match.Type {
	case "sudo_contains":
		return "sudo"
	case "suid_path":
		return "suid"
	case "kernel_cve_module", "kernel_version_range":
		return "kernel-cve"
	case "kernel_contains":
		return "kernel"
	case "os_id", "os_release_contains":
		return "os"
	case "user_contains":
		return "user"
	default:
		return "local-privesc"
	}
}

func normalizeSeverity(sev string) string {
	switch strings.ToLower(strings.TrimSpace(sev)) {
	case "critical", "high", "medium", "low", "info":
		return strings.ToLower(strings.TrimSpace(sev))
	default:
		return "info"
	}
}

func normalizeStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed", "suspected", "error":
		return strings.ToLower(strings.TrimSpace(status))
	default:
		return "confirmed"
	}
}

func normalizeConfidence(confidence string) string {
	switch strings.ToLower(strings.TrimSpace(confidence)) {
	case "high", "medium", "low":
		return strings.ToLower(strings.TrimSpace(confidence))
	default:
		return "high"
	}
}

func renderEvidence(r Rule, match ruleMatch) string {
	if strings.TrimSpace(r.EvidenceTemplate) == "" {
		return match.evidence
	}
	replacer := strings.NewReplacer(
		"{{evidence}}", match.evidence,
		"{{reason}}", match.reason,
	)
	evidence := replacer.Replace(r.EvidenceTemplate)
	if r.Match.Type == "kernel_version_range" && !strings.Contains(evidence, "false_positive_note=") {
		evidence = strings.TrimSpace(evidence) + "\nfalse_positive_note=" + kernelVersionRangeFalsePositiveNote
	}
	return evidence
}

func defaultString(value, fallback string) string {
	if strings.TrimSpace(value) == "" {
		return fallback
	}
	return value
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}
