package batch

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"

	"lpe-checker/internal/collector"
	"lpe-checker/internal/model"
	"lpe-checker/internal/scanner"
)

const DefaultConcurrency = 3

const (
	StatusWaiting         = "waiting"
	StatusScanning        = "scanning"
	StatusSuccess         = "success"
	StatusConnectionError = "connection_error"
	StatusCommandError    = "command_error"
	StatusRejected        = "rejected"
	StatusCanceled        = "canceled"
	StatusPanic           = "panic"
)

var (
	ErrNoHosts = errors.New("no hosts supplied")
	ErrNoRules = errors.New("no rules selected")
)

type Host struct {
	Host     string
	Port     int
	User     string
	Password string
}

func (h Host) ID() string { return net.JoinHostPort(h.Host, strconv.Itoa(h.Port)) }

type Result struct {
	Index  int
	Target string
	Status string
	Report model.Report
	Err    error
}

type Runner interface {
	collector.CommandRunner
	Close() error
}

type RunnerFactory func(Host) Runner
type UpdateFunc func(Result)

func DefaultRunnerFactory(host Host) Runner {
	return &collector.SSHRunner{Config: collector.SSHConfig{
		Host: host.Host, Port: host.Port, User: host.User, Password: host.Password,
	}}
}

func ScanOne(ctx context.Context, index int, host Host, selectedRuleIDs []string, factory RunnerFactory) Result {
	result := Result{Index: index, Target: host.ID(), Status: StatusSuccess}
	if factory == nil {
		factory = DefaultRunnerFactory
	}
	runner := factory(host)
	defer runner.Close()
	s, err := scanner.NewWithRunner("", runner, host.Host)
	if err == nil {
		s, err = s.WithRuleIDs(selectedRuleIDs)
	}
	if err == nil {
		result.Report, err = s.Scan(ctx)
		// The scanner's target host preserves the existing host-only field;
		// ScanTarget records the actual SSH endpoint including its port.
		result.Report.ScanTarget = host.ID()
	}
	result.Err = err
	if err == nil {
		return result
	}
	var connectionErr *collector.ConnectionError
	var commandErr *collector.CommandError
	var rejectedErr *collector.CommandNotAllowedError
	switch {
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		result.Status = StatusCanceled
	case errors.As(err, &connectionErr):
		result.Status = StatusConnectionError
	case errors.As(err, &rejectedErr):
		result.Status = StatusRejected
	case errors.As(err, &commandErr):
		result.Status = StatusCommandError
	default:
		result.Status = StatusCommandError
	}
	return result
}

func ScanAll(ctx context.Context, hosts []Host, selectedRuleIDs []string, concurrency int, factory RunnerFactory, update UpdateFunc) ([]Result, error) {
	if len(hosts) == 0 {
		return nil, ErrNoHosts
	}
	if len(selectedRuleIDs) == 0 {
		return nil, ErrNoRules
	}
	if concurrency <= 0 {
		concurrency = DefaultConcurrency
	}
	if concurrency > len(hosts) {
		concurrency = len(hosts)
	}
	results := make([]Result, len(hosts))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for worker := 0; worker < concurrency; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if update != nil {
					update(Result{Index: index, Target: hosts[index].ID(), Status: StatusScanning})
				}
				result := safeScanOne(ctx, index, hosts[index], selectedRuleIDs, factory)
				results[index] = result
				if update != nil {
					update(result)
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for index := range hosts {
			select {
			case jobs <- index:
			case <-ctx.Done():
				return
			}
		}
	}()
	wg.Wait()
	for index := range results {
		if results[index].Status == "" {
			results[index] = Result{Index: index, Target: hosts[index].ID(), Status: StatusCanceled, Err: ctx.Err()}
			if update != nil {
				update(results[index])
			}
		}
	}
	return results, nil
}

func safeScanOne(ctx context.Context, index int, host Host, selectedRuleIDs []string, factory RunnerFactory) (result Result) {
	defer func() {
		if recovered := recover(); recovered != nil {
			result = Result{Index: index, Target: host.ID(), Status: StatusPanic, Err: fmt.Errorf("scan panic: %v", recovered)}
		}
	}()
	return ScanOne(ctx, index, host, selectedRuleIDs, factory)
}
