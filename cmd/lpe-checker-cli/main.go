package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"lpe-checker/internal/display"
	"lpe-checker/internal/model"
	htmlreport "lpe-checker/internal/report"
	"lpe-checker/internal/scanner"
)

func main() {
	if len(os.Args) < 2 || os.Args[1] != "scan" {
		usage()
		os.Exit(2)
	}

	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	jsonOut := fs.Bool("json", false, "output JSON report")
	htmlPath := fs.String("html", "", "write single-file HTML report")
	outputPath := fs.String("output", "", "write JSON report to file")
	rulesDir := fs.String("rules", "", "extra rules directory; defaults to ./rules when present")
	_ = fs.Parse(os.Args[2:])

	s, err := scanner.New(*rulesDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "load rules: %v\n", err)
		os.Exit(1)
	}
	report, scanErr := s.Scan(context.Background())

	if *htmlPath != "" {
		if err := htmlreport.WriteHTMLFile(*htmlPath, report); err != nil {
			fmt.Fprintf(os.Stderr, "write html report: %v\n", err)
			os.Exit(1)
		}
	}
	if *outputPath != "" {
		if err := writeJSONFile(*outputPath, report); err != nil {
			fmt.Fprintf(os.Stderr, "write json report: %v\n", err)
			os.Exit(1)
		}
	}

	if *jsonOut {
		if *outputPath == "" {
			printJSON(report)
		}
	} else {
		printText(report)
	}
	if scanErr != nil {
		fmt.Fprintf(os.Stderr, "warning: partial collection errors: %v\n", scanErr)
	}
}

func usage() {
	fmt.Println("Usage: lpe-checker-cli scan [--json] [--output result.json] [--html report.html] [--rules <dir>]")
}

func printJSON(r model.Report) {
	b, _ := json.MarshalIndent(r, "", "  ")
	fmt.Println(string(b))
}

func writeJSONFile(path string, r model.Report) error {
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o600)
}

func printText(r model.Report) {
	user := r.SystemInfo.CurrentUser.Username
	if user == "" {
		user = r.SystemInfo.CurrentUser.Raw
	}
	osName := r.SystemInfo.OSPrettyName
	if osName == "" {
		osName = strings.TrimSpace(r.SystemInfo.OSName + " " + r.SystemInfo.OSVersionID)
	}

	fmt.Println("== \u626b\u63cf\u6982\u89c8 ==")
	fmt.Println("\u4e3b\u673a\u540d\uff1a", r.Target.Hostname)
	fmt.Println("\u64cd\u4f5c\u7cfb\u7edf\uff1a", osName)
	fmt.Println("\u5185\u6838\u7248\u672c\uff1a", r.SystemInfo.KernelVersion)
	fmt.Println("\u5f53\u524d\u7528\u6237\uff1a", user)
	fmt.Println("\u68c0\u6d4b\u9879\u603b\u6570\uff1a", r.Summary.TotalChecks)
	fmt.Println("\u5df2\u5b8c\u6210\uff1a", r.Summary.CompletedChecks)
	fmt.Println("\u5df2\u8df3\u8fc7\uff1a", r.Summary.SkippedChecks)
	fmt.Println("\u68c0\u6d4b\u5931\u8d25\uff1a", r.Summary.FailedChecks)
	fmt.Println("\u98ce\u9669\u603b\u6570\uff1a", r.Summary.TotalFindings)
	fmt.Printf("\u98ce\u9669\u7edf\u8ba1\uff1a\u4e25\u91cd/\u9ad8\u5371/\u4e2d\u5371/\u4f4e\u5371/\u4fe1\u606f = %d/%d/%d/%d/%d\n",
		r.Summary.Critical, r.Summary.High, r.Summary.Medium, r.Summary.Low, r.Summary.Info)

	fmt.Println("\n== \u68c0\u6d4b\u9879\u660e\u7ec6 ==")
	if len(r.Checks) == 0 {
		fmt.Println("\u6682\u65e0\u68c0\u6d4b\u9879\u8bb0\u5f55\u3002")
	} else {
		for _, c := range r.Checks {
			fmt.Printf("[%s][%s][%s] %s\n", display.CheckStatusZH(c.Status), display.CheckResultZH(c.Result), display.CategoryZH(c.Category), c.Name)
			if c.Result == "not_applicable" || c.Status == "skipped" {
				fmt.Println("\u8bf4\u660e\uff1a")
				fmt.Println(indent(firstNonEmpty(c.Evidence, c.Description)))
			} else if c.Status == "failed" {
				fmt.Println("\u9519\u8bef\uff1a")
				fmt.Println(indent(display.CollectionErrorZH(c.Error)))
			} else {
				fmt.Println("\u8bc1\u636e\uff1a")
				fmt.Println(indent(c.Evidence))
			}
			fmt.Println()
		}
	}

	fmt.Println("== \u98ce\u9669\u8be6\u60c5 ==")
	if len(r.Findings) == 0 {
		fmt.Println("\u672a\u53d1\u73b0\u98ce\u9669\u3002\u6ce8\u610f\uff1a\u6ca1\u6709 finding \u4e0d\u4ee3\u8868\u6ca1\u6709\u6267\u884c\u68c0\u6d4b\uff0c\u8bf7\u7ed3\u5408\u201c\u68c0\u6d4b\u9879\u660e\u7ec6\u201d\u67e5\u770b\u626b\u63cf\u8986\u76d6\u8303\u56f4\u3002")
		return
	}
	for _, f := range r.Findings {
		fmt.Printf("[%s][%s][%s] %s\n", display.SeverityZH(f.Severity), display.FindingStatusZH(f.Status), display.CategoryZH(f.Category), f.Name)
		fmt.Println("\u7f16\u53f7\uff1a", f.ID)
		fmt.Println("\u68c0\u6d4b\u9879\uff1a", f.CheckID)
		fmt.Println("\u7f6e\u4fe1\u5ea6\uff1a", display.ConfidenceZH(f.Confidence))
		fmt.Println("\u547d\u4e2d\u539f\u56e0\uff1a")
		fmt.Println(indent(f.Reason))
		fmt.Println("\u539f\u59cb\u8bc1\u636e\uff1a")
		fmt.Println(indent(f.Evidence))
		fmt.Println("\u5f71\u54cd\u8bf4\u660e\uff1a")
		fmt.Println(indent(display.FindingImpactZH(f)))
		fmt.Println("\u5229\u7528\u6761\u4ef6\uff1a")
		fmt.Println(indent(f.Condition))
		fmt.Println("\u4fee\u590d\u5efa\u8bae\uff1a")
		fmt.Println(indent(display.FindingRemediationZH(f)))
		fmt.Println("\u8bef\u62a5\u8bf4\u660e\uff1a")
		fmt.Println(indent(display.FindingFalsePositiveNoteZH(f)))
		fmt.Println("\u53c2\u8003\u94fe\u63a5\uff1a")
		if len(f.References) == 0 {
			fmt.Println("  -")
		} else {
			for _, ref := range f.References {
				fmt.Println("  - " + ref)
			}
		}
		fmt.Println()
	}
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return "-"
}

func indent(s string) string {
	if strings.TrimSpace(s) == "" {
		return "  -"
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "  " + line
	}
	return strings.Join(lines, "\n")
}
