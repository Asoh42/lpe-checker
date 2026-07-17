package collector

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

var testAllowedKernelModules = map[string]struct{}{
	"algif_aead": {}, "esp4": {}, "esp6": {}, "rxrpc": {}, "espintcp": {}, "act_pedit": {}, "cifs": {},
}

type mockSSHSession struct {
	command string
	output  []byte
	err     error
}

func (s *mockSSHSession) CombinedOutput(command string) ([]byte, error) {
	s.command = command
	return s.output, s.err
}
func (s *mockSSHSession) Close() error { return nil }

type mockSSHClient struct {
	session         sshSession
	err             error
	newSessionCount int
	closeCount      int
}

func (c *mockSSHClient) NewSession() (sshSession, error) {
	c.newSessionCount++
	return c.session, c.err
}
func (c *mockSSHClient) Close() error {
	c.closeCount++
	return nil
}

func TestBuildSSHCommandAllowsReadOnlyCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{name: "uname", args: []string{"-r"}, want: "'uname' '-r'"},
		{name: "uname", args: []string{"-m"}, want: "'uname' '-m'"},
		{name: "/sbin/lsmod", want: "'/sbin/lsmod'"},
		{name: "find", args: []string{"/lib/modules/6.1.0-test", "-name", "algif_aead.ko*", "-type", "f"}, want: "'find' '/lib/modules/6.1.0-test' '-name' 'algif_aead.ko*' '-type' 'f'"},
	}
	for _, tt := range tests {
		got, err := buildSSHCommand(testAllowedKernelModules, tt.name, tt.args...)
		if err != nil || got != tt.want {
			t.Fatalf("buildSSHCommand(%q, %#v) = %q, %v; want %q", tt.name, tt.args, got, err, tt.want)
		}
	}
}

func TestBuildSSHCommandAllowsAllCollectorCommandShapes(t *testing.T) {
	suidArgs := append([]string{}, commonSUIDCandidates()...)
	suidArgs = append(suidArgs, "-perm", "-4000", "-type", "f")
	tests := []struct {
		name string
		args []string
	}{
		{name: "uname", args: []string{"-r"}},
		{name: "uname", args: []string{"-m"}},
		{name: "id"},
		{name: "sudo", args: []string{"-n", "-l"}},
		{name: "/sbin/lsmod"},
		{name: "cat", args: []string{"/etc/os-release"}},
		{name: "hostname"},
		{name: "find", args: suidArgs},
		{name: "find", args: []string{"/lib/modules/6.1.0-test", "-name", "algif_aead.ko*", "-type", "f"}},
	}
	for _, tt := range tests {
		if _, err := buildSSHCommand(testAllowedKernelModules, tt.name, tt.args...); err != nil {
			t.Fatalf("collector command %s %#v was rejected: %v", tt.name, tt.args, err)
		}
	}
}

func TestSSHRunnerMapsLSModToAbsoluteRemotePath(t *testing.T) {
	session := &mockSSHSession{output: []byte("Module Size Used by\n")}
	runner := &SSHRunner{
		Config: SSHConfig{Host: "example", User: "tester", Password: "example-password"},
		dial: func(context.Context, SSHConfig) (sshClient, error) {
			return &mockSSHClient{session: session}, nil
		},
	}
	if _, err := runner.Run(context.Background(), "lsmod"); err != nil {
		t.Fatal(err)
	}
	if session.command != "'/sbin/lsmod'" {
		t.Fatalf("remote lsmod command = %q; want %q", session.command, "'/sbin/lsmod'")
	}
}

func TestSSHRunnerKeepsLogicalLSModNameInCommandErrors(t *testing.T) {
	session := &mockSSHSession{err: errors.New("exit status 1")}
	runner := &SSHRunner{
		Config: SSHConfig{Host: "example", User: "tester", Password: "example-password"},
		dial: func(context.Context, SSHConfig) (sshClient, error) {
			return &mockSSHClient{session: session}, nil
		},
	}
	_, err := runner.Run(context.Background(), "lsmod")
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || commandErr.Name != "lsmod" {
		t.Fatalf("lsmod command error lost logical name: %v", err)
	}
	if session.command != "'/sbin/lsmod'" {
		t.Fatalf("remote lsmod command = %q; want %q", session.command, "'/sbin/lsmod'")
	}
}

func TestBuildSSHCommandRejectsBareRemoteLSMod(t *testing.T) {
	_, err := buildSSHCommand(testAllowedKernelModules, "lsmod")
	var rejected *CommandNotAllowedError
	if !errors.As(err, &rejected) || rejected.Name != "lsmod" {
		t.Fatalf("bare remote lsmod was not rejected: %v", err)
	}
}

func TestSSHRunnerValidatesMappedLSModBeforeDial(t *testing.T) {
	dialed := false
	runner := &SSHRunner{dial: func(context.Context, SSHConfig) (sshClient, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}}
	_, err := runner.Run(context.Background(), "lsmod", "unexpected-argument")
	var rejected *CommandNotAllowedError
	if !errors.As(err, &rejected) || rejected.Name != "/sbin/lsmod" || dialed {
		t.Fatalf("mapped lsmod was not rejected before dial: err=%v dialed=%v", err, dialed)
	}
}

func TestBuildSSHCommandAllowsOnlyDeclaredModuleFinds(t *testing.T) {
	for _, moduleName := range []string{"esp4", "act_pedit", "algif_aead", "cifs"} {
		got, err := buildSSHCommand(testAllowedKernelModules, "find", "/lib/modules/6.12.0-test", "-name", moduleName+".ko*", "-type", "f")
		want := "'find' '/lib/modules/6.12.0-test' '-name' '" + moduleName + ".ko*' '-type' 'f'"
		if err != nil || got != want {
			t.Fatalf("declared module %q command = %q, %v; want %q", moduleName, got, err, want)
		}
	}
}

func TestSSHRunnerRejectsUndeclaredAndInvalidModulesBeforeDial(t *testing.T) {
	tests := []string{"not_declared", "esp4;rm", "esp4 -exec", "../esp4", `esp4'quote`}
	for _, moduleName := range tests {
		t.Run(moduleName, func(t *testing.T) {
			dialed := false
			runner := &SSHRunner{dial: func(context.Context, SSHConfig) (sshClient, error) {
				dialed = true
				return nil, errors.New("must not dial")
			}}
			if err := runner.SetAllowedKernelModules([]string{"esp4", "act_pedit", "algif_aead"}); err != nil {
				t.Fatal(err)
			}
			_, err := runner.Run(context.Background(), "find", "/lib/modules/6.12.0-test", "-name", moduleName+".ko*", "-type", "f")
			var rejected *CommandNotAllowedError
			if !errors.As(err, &rejected) || dialed {
				t.Fatalf("module %q was not rejected before dial: err=%v dialed=%v", moduleName, err, dialed)
			}
		})
	}
}

func TestSSHRunnerRejectsInvalidConfiguredModuleName(t *testing.T) {
	for _, moduleName := range []string{"esp4;rm", "esp4 -exec", "../esp4", `esp4'quote`} {
		runner := &SSHRunner{}
		err := runner.SetAllowedKernelModules([]string{moduleName})
		var rejected *CommandNotAllowedError
		if !errors.As(err, &rejected) {
			t.Fatalf("configured module %q was not rejected: %v", moduleName, err)
		}
	}
}

func TestBuildSSHCommandRejectsCommandsOutsideAllowlist(t *testing.T) {
	for _, name := range []string{"sh", "bash", "rm", "python"} {
		_, err := buildSSHCommand(testAllowedKernelModules, name, "-c", "id")
		var rejected *CommandNotAllowedError
		if !errors.As(err, &rejected) || rejected.Name != name {
			t.Fatalf("command %q was not rejected by allowlist: %v", name, err)
		}
	}
}

func TestBuildSSHCommandRejectsRemovedProbeCommands(t *testing.T) {
	// ls and test used to be allowed with arbitrary arguments, contrary to the
	// exact-shape allowlist boundary. If a future feature needs file-existence
	// checks, it must define and validate that exact shape instead of restoring
	// either bare command.
	for _, tt := range []struct {
		name string
		args []string
	}{
		{name: "ls", args: []string{"/etc"}},
		{name: "test", args: []string{"-e", "/etc/passwd"}},
	} {
		_, err := buildSSHCommand(testAllowedKernelModules, tt.name, tt.args...)
		var rejected *CommandNotAllowedError
		if !errors.As(err, &rejected) || rejected.Name != tt.name {
			t.Fatalf("removed probe command %q was not rejected: %v", tt.name, err)
		}
	}
}

// This test calls shellQuote directly because, after removing ls and test, all
// allowed commands accept only exact argument shapes: uname has -r/-m, cat has
// /etc/os-release, sudo has -n -l, and both find forms are validated. No valid
// command shape can carry spaces, quotes, $, backticks, or semicolons. That is
// the allowlist working correctly, not a reduction in quoting coverage.
func TestShellQuoteProtectsSpecialArguments(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "space here", want: "'space here'"},
		{input: "single'quote", want: "'single'\"'\"'quote'"},
		{input: "$HOME", want: "'$HOME'"},
		{input: "`id`", want: "'`id`'"},
		{input: "x;y", want: "'x;y'"},
		{input: "algif_aead.ko*", want: "'algif_aead.ko*'"},
	}
	for _, tt := range tests {
		if got := shellQuote(tt.input); got != tt.want {
			t.Errorf("shellQuote(%q) = %q; want %q", tt.input, got, tt.want)
		}
	}
}

func TestSSHRunnerRejectsDangerousAllowedCommandArgumentsBeforeDial(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "find", args: []string{"/tmp", "-delete"}},
		{name: "find", args: []string{".", "-exec", "rm", "{}", ";"}},
		{name: "find", args: []string{".", "-fprint", "/tmp/output"}},
		{name: "find", args: []string{"/lib/modules/6.12.0-test", "-name", "algif_aead.ko*", "-type", "f", "|", "id"}},
		{name: "find", args: []string{"/lib/modules/6.12.0-test", "-name", "algif_aead.ko*", "-type", "f", ">", "/tmp/output"}},
		{name: "find", args: []string{"/lib/modules/6.12.0-test/extra", "-name", "algif_aead.ko*", "-type", "f"}},
		{name: "sudo", args: []string{"rm", "-rf", "/tmp/value"}},
		{name: "cat", args: []string{"/etc/shadow"}},
	}
	for _, tt := range tests {
		dialed := false
		runner := &SSHRunner{dial: func(context.Context, SSHConfig) (sshClient, error) {
			dialed = true
			return nil, errors.New("must not dial")
		}}
		if err := runner.SetAllowedKernelModules([]string{"algif_aead"}); err != nil {
			t.Fatal(err)
		}
		_, err := runner.Run(context.Background(), tt.name, tt.args...)
		var rejected *CommandNotAllowedError
		if !errors.As(err, &rejected) || dialed {
			t.Fatalf("%s %#v was not rejected before dial: err=%v dialed=%v", tt.name, tt.args, err, dialed)
		}
	}
}

func TestSSHRunnerErrorClassificationAndCommandExecution(t *testing.T) {
	connectionCause := errors.New("authentication failed")
	connectionRunner := &SSHRunner{
		Config: SSHConfig{Host: "example", User: "tester", Password: "example-password"},
		dial: func(context.Context, SSHConfig) (sshClient, error) {
			return nil, connectionCause
		},
	}
	_, err := connectionRunner.Run(context.Background(), "uname", "-r")
	var connectionErr *ConnectionError
	if !errors.As(err, &connectionErr) || !errors.Is(err, connectionCause) {
		t.Fatalf("expected ConnectionError, got %T: %v", err, err)
	}

	commandCause := errors.New("exit status 1")
	session := &mockSSHSession{output: []byte("remote stderr\n"), err: commandCause}
	commandRunner := &SSHRunner{
		Config: SSHConfig{Host: "example", User: "tester", Password: "example-password"},
		dial: func(_ context.Context, got SSHConfig) (sshClient, error) {
			want := SSHConfig{Host: "example", Port: 22, User: "tester", Password: "example-password", ConnectTimeout: defaultSSHConnectTimeout, CommandTimeout: defaultSSHCommandTimeout}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("unexpected defaulted config: %+v", got)
			}
			return &mockSSHClient{session: session}, nil
		},
	}
	if err := commandRunner.SetAllowedKernelModules([]string{"algif_aead"}); err != nil {
		t.Fatal(err)
	}
	output, err := commandRunner.Run(context.Background(), "find", "/lib/modules/6.1.0-test", "-name", "algif_aead.ko*", "-type", "f")
	var commandErr *CommandError
	if !errors.As(err, &commandErr) || errors.As(err, &connectionErr) || !errors.Is(err, commandCause) {
		t.Fatalf("expected CommandError only, got %T: %v", err, err)
	}
	if output != "remote stderr" || session.command != "'find' '/lib/modules/6.1.0-test' '-name' 'algif_aead.ko*' '-type' 'f'" {
		t.Fatalf("unexpected output/command: output=%q command=%q", output, session.command)
	}
}

func TestSSHRunnerRejectsBeforeDial(t *testing.T) {
	dialed := false
	runner := &SSHRunner{dial: func(context.Context, SSHConfig) (sshClient, error) {
		dialed = true
		return nil, errors.New("must not dial")
	}}
	_, err := runner.Run(context.Background(), "sh", "-c", "id")
	var rejected *CommandNotAllowedError
	if !errors.As(err, &rejected) || dialed {
		t.Fatalf("allowlist rejection failed: err=%v dialed=%v", err, dialed)
	}
}

func TestSSHRunnerReusesConnectionAndCloseIsIdempotent(t *testing.T) {
	dialCount := 0
	clients := []*mockSSHClient{
		{session: &mockSSHSession{output: []byte("first")}},
		{session: &mockSSHSession{output: []byte("after close")}},
	}
	runner := &SSHRunner{
		Config: SSHConfig{Host: "example", User: "tester", Password: "example-password"},
		dial: func(context.Context, SSHConfig) (sshClient, error) {
			client := clients[dialCount]
			dialCount++
			return client, nil
		},
	}

	if _, err := runner.Run(context.Background(), "uname", "-r"); err != nil {
		t.Fatal(err)
	}
	if _, err := runner.Run(context.Background(), "hostname"); err != nil {
		t.Fatal(err)
	}
	if dialCount != 1 || clients[0].newSessionCount != 2 {
		t.Fatalf("connection was not reused: dials=%d sessions=%d", dialCount, clients[0].newSessionCount)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Close(); err != nil {
		t.Fatal(err)
	}
	if clients[0].closeCount != 1 {
		t.Fatalf("Close was not idempotent: close count=%d", clients[0].closeCount)
	}

	if _, err := runner.Run(context.Background(), "id"); err != nil {
		t.Fatal(err)
	}
	if dialCount != 2 || clients[1].newSessionCount != 1 {
		t.Fatalf("Run after Close did not reconnect: dials=%d sessions=%d", dialCount, clients[1].newSessionCount)
	}
	_ = runner.Close()
}
