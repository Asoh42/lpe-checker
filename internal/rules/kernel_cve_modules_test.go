package rules

import (
	"strings"
	"testing"

	"lpe-checker/internal/model"
)

func TestKernelCVEModuleMultipleModulesOR(t *testing.T) {
	rule := Rule{
		ID: "TEST-MODULE-FAMILY", Name: "module family", Severity: "high", Remediation: "verify vendor advisory",
		Match: MatchCriteria{Type: "kernel_cve_module", Modules: []string{"esp4", "esp6", "rxrpc", "espintcp"}},
	}
	tests := []struct {
		name       string
		moduleName string
		module     model.KernelModule
		want       bool
		status     string
	}{
		{name: "loaded", moduleName: "esp4", module: model.KernelModule{Name: "esp4", LoadedStatus: "loaded", AvailableStatus: "not_found"}, want: true, status: "loaded"},
		{name: "available", moduleName: "esp6", module: model.KernelModule{Name: "esp6", LoadedStatus: "not_loaded", AvailableStatus: "available"}, want: true, status: "available"},
		{name: "unknown", moduleName: "rxrpc", module: model.KernelModule{Name: "rxrpc", LoadedStatus: "unknown", AvailableStatus: "unknown"}, want: true, status: "unknown"},
		{name: "all not found", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			modules := notFoundModules(rule.Match.Modules)
			if tt.moduleName != "" {
				modules[tt.moduleName] = tt.module
			}
			findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: "6.12.0", KernelModules: modules}, []Rule{rule})
			if tt.want {
				if len(findings) != 1 || checks[0].Result != "found" || findings[0].Status != "suspected" || findings[0].Confidence != "medium" {
					t.Fatalf("unexpected match result: %+v %+v", findings, checks)
				}
				if !strings.Contains(findings[0].Evidence, "module="+tt.moduleName) || !strings.Contains(findings[0].Evidence, "module_status="+tt.status) {
					t.Fatalf("evidence does not identify matched module/status: %q", findings[0].Evidence)
				}
			} else if len(findings) != 0 || checks[0].Result != "not_found" {
				t.Fatalf("unexpected not-found result: %+v %+v", findings, checks)
			}
		})
	}
}

func TestKernelCVEModuleSingleModuleRegression(t *testing.T) {
	rule := kernelCVERuleForTest()
	info := model.SystemInfo{Platform: "linux", KernelVersion: "6.1.0-test", KernelModules: map[string]model.KernelModule{
		"algif_aead": {Name: "algif_aead", LoadedStatus: "unknown", AvailableStatus: "unknown", Raw: "lsmod failed"},
	}}
	findings, checks := EvaluateWithChecks(info, []Rule{rule})
	if len(findings) != 1 || findings[0].Status != "suspected" || checks[0].Result != "found" || !strings.Contains(findings[0].Evidence, "module_status=unknown") {
		t.Fatalf("algif_aead regression: %+v %+v", findings, checks)
	}
	wantEvidence := "os=linux\nkernel_version=6.1.0-test\nmodule=algif_aead\nmodule_status=unknown\nloaded_status=unknown\navailable_status=unknown\nnote=lsmod failed"
	if findings[0].Evidence != wantEvidence {
		t.Fatalf("algif_aead evidence changed:\n got: %q\nwant: %q", findings[0].Evidence, wantEvidence)
	}
}

func TestLoadBuiltinKernelCVEModuleFamilyRules(t *testing.T) {
	builtin, err := LoadBuiltin()
	if err != nil {
		t.Fatalf("LoadBuiltin returned error: %v", err)
	}
	tests := []struct {
		id      string
		modules []string
		refs    []string
	}{
		{id: "LPE-XFRM-ESP-FAMILY", modules: []string{"esp4", "esp6", "rxrpc", "espintcp"}, refs: []string{"CVE-2026-43284", "CVE-2026-43500", "CVE-2026-46300", "CVE-2026-43503"}},
		{id: "CVE-2026-46331", modules: []string{"act_pedit"}, refs: []string{"CVE-2026-46331"}},
		{id: "CVE-2026-46243", modules: []string{"cifs"}, refs: []string{"CVE-2026-46243", "RHSB-2026-005"}},
	}
	for _, tt := range tests {
		rule, ok := ruleByID(builtin, tt.id)
		if !ok {
			t.Fatalf("builtin rule %s was not loaded", tt.id)
		}
		if rule.Match.Type != "kernel_cve_module" || rule.Category != "kernel-cve" || strings.Join(rule.Match.Modules, ",") != strings.Join(tt.modules, ",") {
			t.Fatalf("unexpected builtin rule %s: %+v", tt.id, rule)
		}
		if tt.id == "CVE-2026-46331" && (rule.Match.Introduced != "5.18" || rule.Match.Fixed != "7.1") {
			t.Fatalf("unexpected pedit version gate: %+v", rule.Match)
		}
		joinedReferences := strings.Join(rule.References, "\n")
		for _, expected := range tt.refs {
			if !strings.Contains(joinedReferences, expected) {
				t.Fatalf("rule %s references missing %s: %#v", tt.id, expected, rule.References)
			}
		}
	}
}

func TestBuiltinCIFSwitchRuleLoadAndEvaluation(t *testing.T) {
	builtin, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	rule, ok := ruleByID(builtin, "CVE-2026-46243")
	if !ok {
		t.Fatal("CVE-2026-46243 was not loaded")
	}
	if rule.Match.Type != "kernel_cve_module" || strings.Join(rule.Match.Modules, ",") != "cifs" ||
		rule.Category != "kernel-cve" || rule.Severity != "high" || rule.Match.Introduced != "" || rule.Match.Fixed != "" {
		t.Fatalf("unexpected CIFSwitch rule fields: %+v", rule)
	}

	info := model.SystemInfo{Platform: "linux", KernelVersion: "6.12.0", KernelModules: map[string]model.KernelModule{
		"cifs": {Name: "cifs", LoadedStatus: "loaded", AvailableStatus: "not_found"},
	}}
	findings, checks := EvaluateWithChecks(info, []Rule{rule})
	if len(findings) != 1 || len(checks) != 1 || checks[0].Result != "found" ||
		findings[0].Status != "suspected" || findings[0].Confidence != "medium" || findings[0].Severity != "high" {
		t.Fatalf("unexpected CIFSwitch match: findings=%+v checks=%+v", findings, checks)
	}
	if !strings.Contains(findings[0].Evidence, "module=cifs") || !strings.Contains(findings[0].Evidence, "module_status=loaded") {
		t.Fatalf("CIFSwitch evidence missing module/status: %q", findings[0].Evidence)
	}
	note := strings.ToLower(findings[0].FalsePositiveNote)
	for _, expected := range []string{"cifs-utils", "user namespaces", "selinux", "apparmor", "cifs.spnego", "rhsb-2026-005"} {
		if !strings.Contains(note, expected) {
			t.Fatalf("CIFSwitch false_positive_note missing %q: %q", expected, findings[0].FalsePositiveNote)
		}
	}

	findings, checks = EvaluateWithChecks(model.SystemInfo{
		Platform: "linux", KernelVersion: "6.12.0",
		KernelModules: notFoundModules([]string{"cifs"}),
	}, []Rule{rule})
	if len(findings) != 0 || len(checks) != 1 || checks[0].Result != "not_found" {
		t.Fatalf("not-found cifs unexpectedly matched: findings=%+v checks=%+v", findings, checks)
	}
}

func TestPeditModuleVersionGateBoundaries(t *testing.T) {
	builtin, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	pedit, ok := ruleByID(builtin, "CVE-2026-46331")
	if !ok {
		t.Fatal("CVE-2026-46331 was not loaded")
	}
	tests := []struct {
		name   string
		kernel string
		want   bool
	}{
		{name: "6.0 inside", kernel: "6.0", want: true},
		{name: "CentOS 7 below introduced", kernel: "3.10.0-1160.el7.x86_64", want: false},
		{name: "Ubuntu 22.04 below introduced", kernel: "5.15.0-91-generic", want: false},
		{name: "fixed excluded", kernel: "7.1", want: false},
		{name: "introduced included", kernel: "5.18", want: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := model.SystemInfo{
				Platform: "linux", KernelVersion: tt.kernel,
				KernelModules: map[string]model.KernelModule{
					"act_pedit": {Name: "act_pedit", LoadedStatus: "not_loaded", AvailableStatus: "available"},
				},
			}
			findings, checks := EvaluateWithChecks(info, []Rule{pedit})
			if tt.want {
				if len(findings) != 1 || checks[0].Result != "found" || findings[0].Status != "suspected" || findings[0].Confidence != "medium" {
					t.Fatalf("unexpected match for %s: %+v %+v", tt.kernel, findings, checks)
				}
				for _, expected := range []string{"module=act_pedit", "module_status=available", "kernel_version=" + tt.kernel, "introduced=5.18", "fixed=7.1", "version_range_status=matched"} {
					if !strings.Contains(findings[0].Evidence, expected) {
						t.Fatalf("evidence for %s missing %q: %q", tt.kernel, expected, findings[0].Evidence)
					}
				}
			} else if len(findings) != 0 || len(checks) != 1 || checks[0].Result != "not_found" {
				t.Fatalf("unexpected not-found result for %s: %+v %+v", tt.kernel, findings, checks)
			}
		})
	}
}

func TestPeditModuleVersionGateUnparseableStillSuspected(t *testing.T) {
	builtin, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	pedit, _ := ruleByID(builtin, "CVE-2026-46331")
	findings, checks := EvaluateWithChecks(model.SystemInfo{
		Platform: "linux", KernelVersion: "kernel-version-unavailable",
		CollectionErrors: map[string]string{"kernel": "uname -r failed"},
		KernelModules: map[string]model.KernelModule{
			"act_pedit": {Name: "act_pedit", LoadedStatus: "loaded", AvailableStatus: "unknown"},
		},
	}, []Rule{pedit})
	if len(findings) != 1 || checks[0].Result != "found" || findings[0].Status != "suspected" {
		t.Fatalf("unparseable version should remain suspected: %+v %+v", findings, checks)
	}
	if !strings.Contains(findings[0].Evidence, "version_range_status=undetermined") ||
		!strings.Contains(findings[0].Evidence, "current kernel version could not be parsed") {
		t.Fatalf("unparseable version evidence missing: %q", findings[0].Evidence)
	}
}

func TestModuleRuleFalsePositiveNotesAreSpecific(t *testing.T) {
	builtin, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"CVE-2026-46331", "LPE-XFRM-ESP-FAMILY"} {
		rule, _ := ruleByID(builtin, id)
		note := strings.ToLower(rule.FalsePositiveNote)
		if !strings.Contains(note, "backport") || !strings.Contains(note, "older kernel") || !strings.Contains(note, "unprivileged user namespaces") {
			t.Fatalf("rule %s false_positive_note lacks required detail: %q", id, rule.FalsePositiveNote)
		}
	}
}

func TestBuiltinKernelCVEModuleFamilyEvaluation(t *testing.T) {
	builtin, err := LoadBuiltin()
	if err != nil {
		t.Fatal(err)
	}
	xfrm, _ := ruleByID(builtin, "LPE-XFRM-ESP-FAMILY")
	pedit, _ := ruleByID(builtin, "CVE-2026-46331")

	modules := notFoundModules([]string{"esp4", "esp6", "rxrpc", "espintcp", "act_pedit"})
	modules["esp4"] = model.KernelModule{Name: "esp4", LoadedStatus: "loaded", AvailableStatus: "not_found"}
	modules["act_pedit"] = model.KernelModule{Name: "act_pedit", LoadedStatus: "not_loaded", AvailableStatus: "available"}
	findings, checks := EvaluateWithChecks(model.SystemInfo{Platform: "linux", KernelVersion: "6.12.0", KernelModules: modules}, []Rule{xfrm, pedit})
	if len(findings) != 2 || len(checks) != 2 {
		t.Fatalf("unexpected builtin family evaluation: %+v %+v", findings, checks)
	}
	for index := range findings {
		if findings[index].Status != "suspected" || findings[index].Confidence != "medium" || checks[index].Result != "found" {
			t.Fatalf("unexpected classification: %+v %+v", findings[index], checks[index])
		}
	}

	for _, kernel := range []string{"3.10.0-1160.el7.x86_64", "5.15.0-91-generic"} {
		findings, checks = EvaluateWithChecks(model.SystemInfo{
			Platform: "linux", KernelVersion: kernel,
			KernelModules: notFoundModules([]string{"esp4", "esp6", "rxrpc", "espintcp", "act_pedit"}),
		}, []Rule{xfrm, pedit})
		if len(findings) != 0 || len(checks) != 2 || checks[0].Result != "not_found" || checks[1].Result != "not_found" {
			t.Fatalf("old kernel %s unexpectedly matched: %+v %+v", kernel, findings, checks)
		}
	}
}

func TestKernelCVEModuleRuleRejectsInvalidNames(t *testing.T) {
	for _, moduleName := range []string{"esp4;rm", "esp4 -exec", "../esp4", `esp4'quote`} {
		yamlText := "rules:\n  - id: TEST-BAD-MODULE\n    name: bad module\n    severity: high\n    remediation: none\n    match:\n      type: kernel_cve_module\n      modules: [\"" + moduleName + "\"]\n"
		if _, err := parseRules([]byte(yamlText), "inline.yaml"); err == nil {
			t.Fatalf("invalid module name %q was accepted", moduleName)
		}
	}
}

func TestKernelCVEModuleRuleRejectsInvalidVersionBounds(t *testing.T) {
	for _, bound := range []string{"      introduced: garbage\n", "      fixed: not-a-version\n"} {
		yamlText := "rules:\n  - id: TEST-BAD-MODULE-RANGE\n    name: bad module range\n    severity: high\n    remediation: none\n    match:\n      type: kernel_cve_module\n      modules: [act_pedit]\n" + bound
		if _, err := parseRules([]byte(yamlText), "inline.yaml"); err == nil {
			t.Fatalf("invalid module version bound was accepted: %q", bound)
		}
	}
}

func notFoundModules(names []string) map[string]model.KernelModule {
	modules := make(map[string]model.KernelModule, len(names))
	for _, name := range names {
		modules[name] = model.KernelModule{Name: name, LoadedStatus: "not_loaded", AvailableStatus: "not_found", Paths: []string{}}
	}
	return modules
}
