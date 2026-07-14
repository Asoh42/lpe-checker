package scanner

import (
	"context"
	"errors"
	"runtime"
	"strings"
	"time"

	"lpe-checker/internal/collector"
	"lpe-checker/internal/model"
	"lpe-checker/internal/rules"
)

type Scanner struct {
	Collector   collector.Collector
	Rules       []rules.Rule
	RuleSources []string
	TargetHost  string
}

var ErrNoRulesSelected = errors.New("no rules selected")

// New creates a scanner using builtin rules plus optional external rules.
// Pass an empty ruleDir to load ./rules only when it exists.
func New(ruleDir string) (Scanner, error) {
	return newScanner(ruleDir, collector.New(), "")
}

// NewWithRunner creates a remote Linux scanner using the supplied command runner.
func NewWithRunner(ruleDir string, runner collector.CommandRunner, targetHost string) (Scanner, error) {
	if runner == nil {
		return Scanner{}, errors.New("runner is nil")
	}
	return newScanner(ruleDir, collector.Collector{Runner: runner, Platform: "linux"}, targetHost)
}

func newScanner(ruleDir string, c collector.Collector, targetHost string) (Scanner, error) {
	result, err := rules.LoadDefaultWithSources(ruleDir)
	if err != nil {
		return Scanner{}, err
	}
	moduleNames, err := rules.KernelCVEModuleNames(result.Rules)
	if err != nil {
		return Scanner{}, err
	}
	c.KernelModuleNames = append([]string{}, moduleNames...)
	if configurer, ok := c.Runner.(interface{ SetAllowedKernelModules([]string) error }); ok {
		if err := configurer.SetAllowedKernelModules(moduleNames); err != nil {
			return Scanner{}, err
		}
	}
	return Scanner{Collector: c, Rules: result.Rules, RuleSources: result.Sources, TargetHost: targetHost}, nil
}

// WithRuleIDs returns a scanner whose evaluation set contains only selected IDs.
// Filtering happens before Scan calls rules.EvaluateWithChecks.
func (s Scanner) WithRuleIDs(selected []string) (Scanner, error) {
	if len(selected) == 0 {
		return Scanner{}, ErrNoRulesSelected
	}
	allowed := make(map[string]struct{}, len(selected))
	for _, id := range selected {
		allowed[id] = struct{}{}
	}
	filtered := make([]rules.Rule, 0, len(s.Rules))
	for _, rule := range s.Rules {
		if _, ok := allowed[rule.ID]; ok {
			filtered = append(filtered, rule)
		}
	}
	s.Rules = filtered
	return s, nil
}

func (s Scanner) Scan(ctx context.Context) (model.Report, error) {
	info, err := s.Collector.Collect(ctx)
	hostname, hostnameErr := s.Collector.Hostname(ctx)
	err = errors.Join(err, hostnameErr)
	findings, checks := rules.EvaluateWithChecks(info, s.Rules)
	scanMode := "local"
	scanTarget := "localhost"
	if s.TargetHost != "" {
		scanMode = "remote"
		scanTarget = s.TargetHost
	}
	report := model.Report{
		Meta: model.Meta{
			ToolName:    "lpe-checker",
			ToolVersion: model.ToolVersion,
			ScanTime:    time.Now().UTC().Format(time.RFC3339),
			ScanMode:    scanMode,
			RulesSource: s.RuleSources,
		},
		ScanTarget: scanTarget,
		Target: model.Target{
			Hostname: hostname,
			Platform: targetPlatform(info),
			IsRoot:   info.CurrentUser.UID == "0",
			Host:     s.TargetHost,
		},
		Summary:    summarize(findings, checks),
		SystemInfo: info,
		Checks:     checks,
		Findings:   findings,
	}
	return report, err
}

func targetPlatform(info model.SystemInfo) string {
	arch := strings.TrimSpace(info.Architecture)
	if arch == "" {
		arch = runtime.GOARCH
	}
	if info.Platform != "" {
		return info.Platform + "/" + arch
	}
	return runtime.GOOS + "/" + arch
}

func summarize(findings []model.Finding, checks []model.CheckResult) model.Summary {
	s := model.Summary{TotalFindings: len(findings), TotalChecks: len(checks)}
	for _, c := range checks {
		switch strings.ToLower(c.Status) {
		case "completed":
			s.CompletedChecks++
		case "skipped":
			s.SkippedChecks++
		case "failed":
			s.FailedChecks++
		}
	}
	for _, f := range findings {
		switch strings.ToLower(f.Severity) {
		case "critical":
			s.Critical++
		case "high":
			s.High++
		case "medium":
			s.Medium++
		case "low":
			s.Low++
		case "info":
			s.Info++
		}
	}
	return s
}
