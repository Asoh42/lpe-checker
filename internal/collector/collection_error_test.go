package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"lpe-checker/internal/rules"
)

func TestSafeCollectionErrorsDoNotLeakButReturnedErrorsStayRaw(t *testing.T) {
	localExitErr := testLocalExitError(t)
	tests := []struct {
		name   string
		reason string
		err    func(string) error
	}{
		{
			name: "command not found", reason: CollectionErrorReasonNotFound,
			err: func(marker string) error { return fmt.Errorf("%s: %w", marker, exec.ErrNotFound) },
		},
		{
			name: "permission", reason: CollectionErrorReasonPermission,
			err: func(marker string) error { return fmt.Errorf("%s: %w", marker, os.ErrPermission) },
		},
		{
			name: "deadline", reason: CollectionErrorReasonTimeout,
			err: func(marker string) error { return fmt.Errorf("%s: %w", marker, context.DeadlineExceeded) },
		},
		{
			name: "canceled", reason: CollectionErrorReasonCanceled,
			err: func(marker string) error { return fmt.Errorf("%s: %w", marker, context.Canceled) },
		},
		{
			name: "local exit", reason: CollectionErrorReasonLocalExit,
			err: func(marker string) error { return fmt.Errorf("%s: %w", marker, localExitErr) },
		},
		{
			name: "connection wrapper", reason: CollectionErrorReasonConnection,
			err: func(marker string) error {
				return &ConnectionError{Err: errors.New(marker + " dial tcp 192.0.2.10:22: private detail")}
			},
		},
		{
			name: "connection wrapper with deadline", reason: CollectionErrorReasonTimeout,
			err: func(marker string) error {
				return &ConnectionError{Err: fmt.Errorf("%s: %w", marker, context.DeadlineExceeded)}
			},
		},
		{
			name: "command wrapper with SSH exit", reason: CollectionErrorReasonRemoteExit,
			err: func(marker string) error {
				return &CommandError{Name: "uname", Err: fmt.Errorf("%s: %w", marker, &ssh.ExitError{})}
			},
		},
		{
			name: "allowlist rejection", reason: CollectionErrorReasonNotAllowed,
			err: func(marker string) error { return &CommandNotAllowedError{Name: marker} },
		},
		{
			name: "other", reason: CollectionErrorReasonOther,
			err: func(marker string) error { return errors.New(marker + " private library detail") },
		},
	}

	for index, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			marker := fmt.Sprintf("SENTINEL-LEAK-abc123-%d", index)
			rawErr := tt.err(marker)
			info, collectErr := (Collector{Runner: fakeRunner{
				outputs: safeCollectionTestOutputs(),
				errors:  map[string]error{"uname -r": rawErr},
			}}).Collect(context.Background())

			safe := info.CollectionErrors["kernel"]
			if safe != safeCollectionErrorPrefix+tt.reason+":uname -r" {
				t.Fatalf("safe collection error = %q; want reason %q", safe, tt.reason)
			}
			if strings.Contains(safe, marker) {
				t.Fatalf("safe collection error leaked raw marker: %q", safe)
			}
			if collectErr == nil || !strings.Contains(collectErr.Error(), marker) {
				t.Fatalf("returned diagnostic error lost raw marker: %v", collectErr)
			}
		})
	}
}

func TestCollectionFailureReachesCheckAsSafeValue(t *testing.T) {
	marker := "SENTINEL-LEAK-end-to-end"
	info, collectErr := (Collector{Runner: fakeRunner{
		outputs: safeCollectionTestOutputs(),
		errors: map[string]error{
			"uname -r": fmt.Errorf("%s: %w", marker, exec.ErrNotFound),
		},
	}}).Collect(context.Background())
	if collectErr == nil || !strings.Contains(collectErr.Error(), marker) {
		t.Fatalf("returned diagnostic error lost raw marker: %v", collectErr)
	}

	findings, checks := rules.EvaluateWithChecks(info, []rules.Rule{{
		ID: "KERNEL-COLLECTION-CHECK", Name: "kernel collection check",
		Match: rules.MatchCriteria{Type: "kernel_contains", Contains: "test"},
	}})
	if len(findings) != 0 || len(checks) != 1 || checks[0].Status != "failed" || checks[0].Result != "unknown" {
		t.Fatalf("unexpected evaluation result: findings=%+v checks=%+v", findings, checks)
	}
	if checks[0].Error != safeCollectionErrorPrefix+CollectionErrorReasonNotFound+":uname -r" {
		t.Fatalf("check error was not the safe collector value: %+v", checks[0])
	}
	if strings.Contains(checks[0].Error, marker) {
		t.Fatalf("check error leaked raw marker: %q", checks[0].Error)
	}
}

func safeCollectionTestOutputs() map[string]string {
	return map[string]string{
		"uname -m":            "x86_64",
		"cat /etc/os-release": "ID=test",
		"id":                  "uid=1000(test)",
		"sudo -n -l":          "",
	}
}

func testLocalExitError(t *testing.T) *exec.ExitError {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=TestSafeCollectionErrorExecExitHelper")
	cmd.Env = append(os.Environ(), "LPE_CHECKER_EXEC_EXIT_HELPER=1")
	err := cmd.Run()
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("helper error = %T %v; want *exec.ExitError", err, err)
	}
	return exitErr
}

func TestSafeCollectionErrorExecExitHelper(t *testing.T) {
	if os.Getenv("LPE_CHECKER_EXEC_EXIT_HELPER") != "1" {
		return
	}
	os.Exit(23)
}
