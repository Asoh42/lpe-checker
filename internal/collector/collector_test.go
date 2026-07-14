package collector

import (
	"context"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

type fakeRunner struct {
	outputs map[string]string
	errors  map[string]error
}

type countingRunner struct {
	fakeRunner
	calls map[string]int
}

func (r *countingRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	key := commandKey(name, args...)
	r.calls[key]++
	return r.fakeRunner.Run(ctx, name, args...)
}

func commandKey(name string, args ...string) string {
	return strings.Join(append([]string{name}, args...), " ")
}

func (f fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := commandKey(name, args...)
	return f.outputs[key], f.errors[key]
}

func TestCollectorParsesCommandBackedFileFacts(t *testing.T) {
	suidArgs := append([]string{}, commonSUIDCandidates()...)
	suidArgs = append(suidArgs, "-perm", "-4000", "-type", "f")
	runner := fakeRunner{outputs: map[string]string{
		"uname -r":                      "6.1.0-test",
		"cat /etc/os-release":           "ID=debian\nNAME=\"Debian GNU/Linux\"\nVERSION_ID='12'\nPRETTY_NAME=\"Debian GNU/Linux 12\"",
		"id":                            "uid=1000(test) gid=1000(test) groups=1000(test)",
		"sudo -n -l":                    "",
		commandKey("find", suidArgs...): "/usr/bin/passwd\nfind: '/missing': No such file or directory\n/usr/bin/pkexec\n",
		"hostname":                      "test-host\n",
	}}
	c := Collector{Runner: runner}

	info, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if info.OSID != "debian" || info.OSName != "Debian GNU/Linux" || info.OSVersionID != "12" || info.OSPrettyName != "Debian GNU/Linux 12" {
		t.Fatalf("unexpected os-release parse: %+v", info)
	}
	if len(info.SUIDFiles) != 2 || info.SUIDFiles[0] != "/usr/bin/passwd" || info.SUIDFiles[1] != "/usr/bin/pkexec" {
		t.Fatalf("unexpected SUID files: %#v", info.SUIDFiles)
	}
	hostname, err := c.Hostname(context.Background())
	if err != nil || hostname != "test-host" {
		t.Fatalf("unexpected hostname: %q, %v", hostname, err)
	}
}

func TestCollectorParsesModuleFindOutput(t *testing.T) {
	key := "find /lib/modules/6.1.0-test -name algif_aead.ko* -type f"
	c := Collector{Runner: fakeRunner{outputs: map[string]string{
		key: "/lib/modules/6.1.0-test/kernel/crypto/algif_aead.ko.xz\n/lib/modules/6.1.0-test/extra/algif_aead.ko\n",
	}}}
	paths, err := c.collectModuleFiles(context.Background(), "6.1.0-test", "algif_aead")
	if err != nil {
		t.Fatalf("collectModuleFiles returned error: %v", err)
	}
	if len(paths) != 2 || paths[0] != "/lib/modules/6.1.0-test/kernel/crypto/algif_aead.ko.xz" || paths[1] != "/lib/modules/6.1.0-test/extra/algif_aead.ko" {
		t.Fatalf("unexpected module paths: %#v", paths)
	}
}

func TestCollectorCollectsConfiguredKernelModulesWithOneLSMod(t *testing.T) {
	runner := &countingRunner{
		fakeRunner: fakeRunner{outputs: map[string]string{
			"uname -r":            "6.12.0-test",
			"uname -m":            "x86_64",
			"cat /etc/os-release": "ID=linux",
			"id":                  "uid=1000(test)",
			"lsmod":               "Module Size Used by\nesp4 123 0\n",
			"find /lib/modules/6.12.0-test -name esp4.ko* -type f":      "",
			"find /lib/modules/6.12.0-test -name act_pedit.ko* -type f": "/lib/modules/6.12.0-test/act_pedit.ko.xz",
		}},
		calls: map[string]int{},
	}
	c := Collector{Runner: runner, Platform: "linux", KernelModuleNames: []string{"esp4", "act_pedit"}}
	info, err := c.Collect(context.Background())
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}
	if runner.calls["lsmod"] != 1 {
		t.Fatalf("lsmod calls = %d; want 1", runner.calls["lsmod"])
	}
	if info.KernelModules["esp4"].LoadedStatus != "loaded" || info.KernelModules["act_pedit"].AvailableStatus != "available" {
		t.Fatalf("unexpected module observations: %+v", info.KernelModules)
	}
}

func TestSUIDFindOutputRejectsStderrLines(t *testing.T) {
	candidates := commonSUIDCandidates()
	args := append([]string{}, candidates...)
	args = append(args, "-perm", "-4000", "-type", "f")
	key := commandKey("find", args...)
	c := Collector{Runner: fakeRunner{
		outputs: map[string]string{
			key: "find: '/missing': No such file or directory\n/usr/bin/passwd\nfind: Permission denied\n/not/a/candidate\n",
		},
		errors: map[string]error{key: &exec.ExitError{}},
	}}

	paths, err := c.collectSUIDFiles(context.Background())
	if err != nil {
		t.Fatalf("collectSUIDFiles returned error: %v", err)
	}
	if len(paths) != 1 || paths[0] != "/usr/bin/passwd" {
		t.Fatalf("stderr or non-candidate line was accepted: %#v", paths)
	}
}

func TestCommandFailuresDoNotStopCollection(t *testing.T) {
	suidArgs := append([]string{}, commonSUIDCandidates()...)
	suidArgs = append(suidArgs, "-perm", "-4000", "-type", "f")
	runner := fakeRunner{
		outputs: map[string]string{"uname -r": "6.1.0-test", "id": "uid=1000(test)"},
		errors: map[string]error{
			"cat /etc/os-release":           errors.New("cat failed"),
			commandKey("find", suidArgs...): errors.New("find failed"),
			"hostname":                      errors.New("hostname failed"),
		},
	}
	c := Collector{Runner: runner}
	info, err := c.Collect(context.Background())
	if err == nil || info.KernelVersion != "6.1.0-test" || len(info.SUIDFiles) != 0 {
		t.Fatalf("collection did not continue as expected: info=%+v err=%v", info, err)
	}
	hostname, err := c.Hostname(context.Background())
	if err == nil || hostname != "unknown" {
		t.Fatalf("unexpected hostname failure result: %q, %v", hostname, err)
	}
}

func TestSudoExecutionFailureAndExpectedPasswordDenial(t *testing.T) {
	base := map[string]string{
		"uname -r":            "6.1.0-test",
		"uname -m":            "x86_64",
		"cat /etc/os-release": "ID=debian",
		"id":                  "uid=1000(test)",
		"hostname":            "test-host",
	}

	failure := fakeRunner{outputs: base, errors: map[string]error{"sudo -n -l": errors.New("sudo executable failed")}}
	info, err := (Collector{Runner: failure}).Collect(context.Background())
	if err == nil || info.CollectionErrors["sudo"] == "" {
		t.Fatalf("sudo execution failure was not recorded: info=%+v err=%v", info, err)
	}

	denialOutputs := make(map[string]string, len(base)+1)
	for key, value := range base {
		denialOutputs[key] = value
	}
	denialOutputs["sudo -n -l"] = "sudo: a password is required"
	denial := fakeRunner{outputs: denialOutputs, errors: map[string]error{"sudo -n -l": errors.New("exit status 1")}}
	info, err = (Collector{Runner: denial}).Collect(context.Background())
	if err != nil || info.CollectionErrors["sudo"] != "" || info.SudoList.Available {
		t.Fatalf("expected password denial was misclassified: info=%+v err=%v", info, err)
	}
}
