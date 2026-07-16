package collector

import (
	"context"
	"errors"
	"strings"
	"testing"

	"lpe-checker/internal/rules"
)

func TestCurrentUserRawKeepsOutputButNeverStoresErrors(t *testing.T) {
	const idOutput = "uid=1000(test) gid=1000(test) groups=1000(test)"
	successOutputs := rawSafetyBaseOutputs()
	successOutputs["id"] = idOutput
	info, err := (Collector{Runner: fakeRunner{outputs: successOutputs}}).Collect(context.Background())
	if err != nil {
		t.Fatalf("successful collection returned error: %v", err)
	}
	if info.CurrentUser.Raw != idOutput || info.CurrentUser.UID != "1000" || info.CurrentUser.Username != "test" {
		t.Fatalf("successful id output was not preserved and parsed: %+v", info.CurrentUser)
	}

	const marker = "SENTINEL-LEAK-raw-id-001"
	failureOutputs := rawSafetyBaseOutputs()
	info, err = (Collector{Runner: fakeRunner{
		outputs: failureOutputs,
		errors:  map[string]error{"id": errors.New(marker + " private id detail")},
	}}).Collect(context.Background())
	if info.CurrentUser.Raw != "" || strings.Contains(info.CurrentUser.Raw, marker) {
		t.Fatalf("id error was stored in CurrentUser.Raw: %q", info.CurrentUser.Raw)
	}
	if safe := info.CollectionErrors["user"]; safe == "" || strings.Contains(safe, marker) {
		t.Fatalf("user collection error is missing or unsafe: %q", safe)
	}
	if err == nil || !strings.Contains(err.Error(), marker) {
		t.Fatalf("returned diagnostic error lost raw id marker: %v", err)
	}
}

func TestKernelModuleRawKeepsLSModOutputWhenFileCheckFails(t *testing.T) {
	const (
		moduleName  = "act_pedit"
		lsmodOutput = "Module Size Used by\nact_pedit 16384 0\n"
		marker      = "SENTINEL-LEAK-raw-module-file-001"
	)
	outputs := rawSafetyBaseOutputs()
	outputs["lsmod"] = lsmodOutput
	findKey := "find /lib/modules/6.12.0-test -name act_pedit.ko* -type f"
	info, err := (Collector{
		Runner:            fakeRunner{outputs: outputs, errors: map[string]error{findKey: errors.New(marker + " private find detail")}},
		Platform:          "linux",
		KernelModuleNames: []string{moduleName},
	}).Collect(context.Background())

	module := info.KernelModules[moduleName]
	if module.Raw != lsmodOutput {
		t.Fatalf("successful lsmod output changed after module file failure: got %q want %q", module.Raw, lsmodOutput)
	}
	if strings.Contains(module.Raw, marker) {
		t.Fatalf("module file error leaked into module.Raw: %q", module.Raw)
	}
	if safe := info.CollectionErrors["kernel_module:"+moduleName]; safe == "" || strings.Contains(safe, marker) {
		t.Fatalf("module collection error is missing or unsafe: %q", safe)
	}
	if err == nil || !strings.Contains(err.Error(), marker) {
		t.Fatalf("returned diagnostic error lost module file marker: %v", err)
	}
}

func TestKernelModuleRawPreservesSuccessfulLSModOutput(t *testing.T) {
	const (
		moduleName  = "esp4"
		lsmodOutput = "Module Size Used by\nesp4 20480 1\n"
	)
	outputs := rawSafetyBaseOutputs()
	outputs["lsmod"] = lsmodOutput
	outputs["find /lib/modules/6.12.0-test -name esp4.ko* -type f"] = "/lib/modules/6.12.0-test/esp4.ko.xz"
	info, err := (Collector{
		Runner:            fakeRunner{outputs: outputs},
		Platform:          "linux",
		KernelModuleNames: []string{moduleName},
	}).Collect(context.Background())
	if err != nil {
		t.Fatalf("successful module collection returned error: %v", err)
	}
	if got := info.KernelModules[moduleName].Raw; got != lsmodOutput {
		t.Fatalf("successful lsmod output changed: got %q want %q", got, lsmodOutput)
	}
}

func TestKernelModuleFailuresStaySuspectedWithoutRawErrorLeak(t *testing.T) {
	const (
		moduleName  = "esp4"
		lsmodMarker = "SENTINEL-LEAK-raw-lsmod-001"
		fileMarker  = "SENTINEL-LEAK-raw-module-file-002"
	)
	outputs := rawSafetyBaseOutputs()
	findKey := "find /lib/modules/6.12.0-test -name esp4.ko* -type f"
	info, collectErr := (Collector{
		Runner: fakeRunner{
			outputs: outputs,
			errors: map[string]error{
				"lsmod": errors.New(lsmodMarker + " private lsmod detail"),
				findKey: errors.New(fileMarker + " private module file detail"),
			},
		},
		Platform:          "linux",
		KernelModuleNames: []string{moduleName},
	}).Collect(context.Background())

	module := info.KernelModules[moduleName]
	if module.Raw != "" || strings.Contains(module.Raw, lsmodMarker) || strings.Contains(module.Raw, fileMarker) {
		t.Fatalf("module errors leaked into module.Raw: %q", module.Raw)
	}
	for _, key := range []string{"kernel_modules:lsmod", "kernel_module:" + moduleName} {
		safe := info.CollectionErrors[key]
		if safe == "" || strings.Contains(safe, lsmodMarker) || strings.Contains(safe, fileMarker) {
			t.Fatalf("collection error %q is missing or unsafe: %q", key, safe)
		}
	}
	if collectErr == nil || !strings.Contains(collectErr.Error(), lsmodMarker) || !strings.Contains(collectErr.Error(), fileMarker) {
		t.Fatalf("returned diagnostic error lost module markers: %v", collectErr)
	}

	findings, checks := rules.EvaluateWithChecks(info, []rules.Rule{{
		ID: "MODULE-UNKNOWN-REGRESSION", Name: "module unknown regression",
		Severity: "high", Match: rules.MatchCriteria{Type: "kernel_cve_module", Modules: []string{moduleName}},
	}})
	if len(findings) != 1 || len(checks) != 1 || checks[0].Status != "completed" || checks[0].Result != "found" ||
		findings[0].Status != "suspected" || findings[0].Confidence != "medium" {
		t.Fatalf("module unknown semantics changed: findings=%+v checks=%+v", findings, checks)
	}
	if strings.Contains(findings[0].Evidence, lsmodMarker) || strings.Contains(findings[0].Evidence, fileMarker) {
		t.Fatalf("raw module error leaked into finding evidence: %q", findings[0].Evidence)
	}
}

func rawSafetyBaseOutputs() map[string]string {
	return map[string]string{
		"uname -r":            "6.12.0-test",
		"uname -m":            "x86_64",
		"cat /etc/os-release": "ID=test",
		"id":                  "uid=1000(test)",
		"sudo -n -l":          "",
	}
}
