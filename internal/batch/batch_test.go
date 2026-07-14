package batch

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"lpe-checker/internal/collector"
)

type fakeRunner struct {
	host   string
	fail   bool
	gate   *concurrencyGate
	closed bool
}

func (r *fakeRunner) Run(_ context.Context, name string, _ ...string) (string, error) {
	if r.fail {
		return "", &collector.ConnectionError{Err: errors.New("unreachable")}
	}
	if r.gate != nil {
		r.gate.enter()
		defer r.gate.leave()
		time.Sleep(2 * time.Millisecond)
	}
	switch name {
	case "uname":
		return "6.1.0-" + r.host, nil
	case "hostname":
		return r.host, nil
	case "id":
		return "uid=1000(test)", nil
	default:
		return "", nil
	}
}
func (r *fakeRunner) Close() error { r.closed = true; return nil }

type concurrencyGate struct {
	mu      sync.Mutex
	current int
	max     int
}

func (g *concurrencyGate) enter() {
	g.mu.Lock()
	g.current++
	if g.current > g.max {
		g.max = g.current
	}
	g.mu.Unlock()
}
func (g *concurrencyGate) leave() { g.mu.Lock(); g.current--; g.mu.Unlock() }

func TestScanAllKeepsResultsIndependentAndLimitsConcurrency(t *testing.T) {
	hosts := []Host{{Host: "one", Port: 22}, {Host: "two", Port: 22}, {Host: "three", Port: 22}, {Host: "four", Port: 22}}
	gate := &concurrencyGate{}
	results, err := ScanAll(context.Background(), hosts, []string{"LPE-SUDO-NOPASSWD"}, 2, func(host Host) Runner {
		return &fakeRunner{host: host.Host, gate: gate}
	}, nil)
	if err != nil || len(results) != len(hosts) {
		t.Fatalf("unexpected batch result: len=%d err=%v", len(results), err)
	}
	for index, result := range results {
		if result.Target != hosts[index].ID() || result.Report.Target.Host != hosts[index].Host || result.Report.ScanTarget != hosts[index].ID() || result.Report.Target.Hostname != hosts[index].Host {
			t.Fatalf("result %d was mixed up: %+v", index, result)
		}
	}
	if gate.max > 2 || gate.max < 2 {
		t.Fatalf("unexpected maximum concurrency: %d", gate.max)
	}
}

func TestScanAllConnectionFailureDoesNotStopOthers(t *testing.T) {
	hosts := []Host{{Host: "good", Port: 22}, {Host: "bad", Port: 22}, {Host: "also-good", Port: 22}}
	results, err := ScanAll(context.Background(), hosts, []string{"LPE-SUDO-NOPASSWD"}, DefaultConcurrency, func(host Host) Runner {
		return &fakeRunner{host: host.Host, fail: host.Host == "bad"}
	}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if results[1].Status != StatusConnectionError || results[0].Status != StatusSuccess || results[2].Status != StatusSuccess {
		t.Fatalf("unexpected isolated statuses: %+v", results)
	}
}

func TestScanAllRejectsEmptyInputs(t *testing.T) {
	if _, err := ScanAll(context.Background(), nil, []string{"rule"}, 3, nil, nil); !errors.Is(err, ErrNoHosts) {
		t.Fatalf("expected ErrNoHosts, got %v", err)
	}
	if _, err := ScanAll(context.Background(), []Host{{Host: "one", Port: 22}}, nil, 3, nil, nil); !errors.Is(err, ErrNoRules) {
		t.Fatalf("expected ErrNoRules, got %v", err)
	}
}
