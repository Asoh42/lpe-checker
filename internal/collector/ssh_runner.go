package collector

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	defaultSSHPort           = 22
	defaultSSHConnectTimeout = 5 * time.Second
	defaultSSHCommandTimeout = 5 * time.Second
)

var allowedSSHCommands = map[string]struct{}{
	"uname": {}, "id": {}, "sudo": {}, "/sbin/lsmod": {}, "cat": {},
	"hostname": {}, "find": {}, "ls": {}, "test": {},
}

var (
	sshKernelModuleNamePattern = regexp.MustCompile(`^[a-z0-9_-]+$`)
	sshModuleDirPattern        = regexp.MustCompile(`^/lib/modules/[A-Za-z0-9._+-]+$`)
)

// SSHConfig contains the password-authentication settings for one target host.
type SSHConfig struct {
	Host           string
	Port           int
	User           string
	Password       string
	ConnectTimeout time.Duration
	CommandTimeout time.Duration
}

// ConnectionError identifies a host-level SSH connection or authentication failure.
type ConnectionError struct{ Err error }

func (e *ConnectionError) Error() string { return "SSH connection failed: " + e.Err.Error() }
func (e *ConnectionError) Unwrap() error { return e.Err }

// CommandError identifies a failure after an SSH connection was established.
type CommandError struct {
	Name string
	Err  error
}

func (e *CommandError) Error() string {
	return fmt.Sprintf("SSH command %q failed: %v", e.Name, e.Err)
}
func (e *CommandError) Unwrap() error { return e.Err }

// CommandNotAllowedError identifies rejection by the SSH command-name allowlist.
type CommandNotAllowedError struct{ Name string }

func (e *CommandNotAllowedError) Error() string {
	return fmt.Sprintf("SSH command %q rejected by read-only command allowlist", e.Name)
}

type sshSession interface {
	CombinedOutput(command string) ([]byte, error)
	Close() error
}

type sshClient interface {
	NewSession() (sshSession, error)
	Close() error
}

type sshDialFunc func(context.Context, SSHConfig) (sshClient, error)

// SSHRunner executes allowlisted read-only commands on one SSH target.
// One instance is designed for serial use by one scan and one host. Batch use
// must create an independent instance per host; connections are never global.
type SSHRunner struct {
	Config               SSHConfig
	dial                 sshDialFunc
	mu                   sync.Mutex
	client               sshClient
	allowedKernelModules map[string]struct{}
}

// SetAllowedKernelModules replaces this runner's per-scan closed set of module
// names. Names must originate from the loaded kernel_cve_module rules.
func (r *SSHRunner) SetAllowedKernelModules(moduleNames []string) error {
	validated := make(map[string]struct{}, len(moduleNames))
	for _, name := range moduleNames {
		if !sshKernelModuleNamePattern.MatchString(name) {
			return &CommandNotAllowedError{Name: "find module " + name}
		}
		validated[name] = struct{}{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.allowedKernelModules = validated
	return nil
}

// Run implements CommandRunner.
func (r *SSHRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	remoteName := name
	// Resolve the logical collector name before validation so the allowlist
	// checks the exact executable path that will be sent to the remote shell.
	if name == "lsmod" {
		remoteName = "/sbin/lsmod"
	}
	command, err := buildSSHCommand(r.allowedKernelModules, remoteName, args...)
	if err != nil {
		return "", err
	}

	config := r.Config
	applySSHDefaults(&config)
	if r.client == nil {
		dial := r.dial
		if dial == nil {
			dial = dialSSH
		}
		connectCtx, cancelConnect := context.WithTimeout(ctx, config.ConnectTimeout)
		client, dialErr := dial(connectCtx, config)
		cancelConnect()
		if dialErr != nil {
			return "", &ConnectionError{Err: dialErr}
		}
		r.client = client
	}

	session, err := r.client.NewSession()
	if err != nil {
		r.closeLocked()
		return "", &CommandError{Name: name, Err: err}
	}
	defer session.Close()

	type result struct {
		output []byte
		err    error
	}
	resultCh := make(chan result, 1)
	go func() {
		output, runErr := session.CombinedOutput(command)
		resultCh <- result{output: output, err: runErr}
	}()

	commandCtx, cancelCommand := context.WithTimeout(ctx, config.CommandTimeout)
	defer cancelCommand()
	select {
	case result := <-resultCh:
		output := strings.TrimSpace(string(result.output))
		if result.err != nil {
			return output, &CommandError{Name: name, Err: result.err}
		}
		return output, nil
	case <-commandCtx.Done():
		_ = session.Close()
		r.closeLocked()
		return "", &CommandError{Name: name, Err: commandCtx.Err()}
	}
}

// Close releases the cached connection. It is idempotent. A later Run starts
// a fresh connection, which permits explicit scan boundaries and safe retries.
func (r *SSHRunner) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.closeLocked()
}

func (r *SSHRunner) closeLocked() error {
	if r.client == nil {
		return nil
	}
	client := r.client
	r.client = nil
	return client.Close()
}

func applySSHDefaults(config *SSHConfig) {
	if config.Port <= 0 {
		config.Port = defaultSSHPort
	}
	if config.ConnectTimeout <= 0 {
		config.ConnectTimeout = defaultSSHConnectTimeout
	}
	if config.CommandTimeout <= 0 {
		config.CommandTimeout = defaultSSHCommandTimeout
	}
}

func buildSSHCommand(allowedKernelModules map[string]struct{}, name string, args ...string) (string, error) {
	if _, allowed := allowedSSHCommands[name]; !allowed {
		return "", &CommandNotAllowedError{Name: name}
	}
	if !allowedSSHCommandArgs(allowedKernelModules, name, args) {
		return "", &CommandNotAllowedError{Name: name}
	}
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, shellQuote(name))
	for _, arg := range args {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " "), nil
}

func allowedSSHCommandArgs(allowedKernelModules map[string]struct{}, name string, args []string) bool {
	switch name {
	case "uname":
		return len(args) == 1 && (args[0] == "-r" || args[0] == "-m")
	case "id", "/sbin/lsmod", "hostname":
		return len(args) == 0
	case "sudo":
		return len(args) == 2 && args[0] == "-n" && args[1] == "-l"
	case "cat":
		return len(args) == 1 && args[0] == "/etc/os-release"
	case "find":
		return allowedSUIDFindArgs(args) || allowedModuleFindArgs(allowedKernelModules, args)
	case "ls", "test":
		return true
	default:
		return false
	}
}

func allowedSUIDFindArgs(args []string) bool {
	candidates := commonSUIDCandidates()
	if len(args) != len(candidates)+4 {
		return false
	}
	for index, candidate := range candidates {
		if args[index] != candidate {
			return false
		}
	}
	tail := args[len(candidates):]
	return tail[0] == "-perm" && tail[1] == "-4000" && tail[2] == "-type" && tail[3] == "f"
}

func allowedModuleFindArgs(allowedKernelModules map[string]struct{}, args []string) bool {
	if len(args) != 5 || !sshModuleDirPattern.MatchString(args[0]) ||
		args[1] != "-name" || args[3] != "-type" || args[4] != "f" {
		return false
	}
	pattern := args[2]
	if !strings.HasSuffix(pattern, ".ko*") {
		return false
	}
	moduleName := strings.TrimSuffix(pattern, ".ko*")
	if !sshKernelModuleNamePattern.MatchString(moduleName) {
		return false
	}
	_, allowed := allowedKernelModules[moduleName]
	return allowed
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

type realSSHClient struct{ client *ssh.Client }

func (c *realSSHClient) NewSession() (sshSession, error) { return c.client.NewSession() }
func (c *realSSHClient) Close() error                    { return c.client.Close() }

func dialSSH(ctx context.Context, config SSHConfig) (sshClient, error) {
	if strings.TrimSpace(config.Host) == "" {
		return nil, errors.New("SSH host is empty")
	}
	if strings.TrimSpace(config.User) == "" {
		return nil, errors.New("SSH user is empty")
	}
	address := net.JoinHostPort(config.Host, strconv.Itoa(config.Port))
	netConn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = netConn.SetDeadline(deadline)
	}
	sshConfig := &ssh.ClientConfig{
		User:    config.User,
		Auth:    []ssh.AuthMethod{ssh.Password(config.Password)},
		Timeout: config.ConnectTimeout,
		// Known security tradeoff for the first version: host keys are not verified.
		// Replace this with known_hosts verification before production deployment.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	clientConn, channels, requests, err := ssh.NewClientConn(netConn, address, sshConfig)
	if err != nil {
		_ = netConn.Close()
		return nil, err
	}
	_ = netConn.SetDeadline(time.Time{})
	return &realSSHClient{client: ssh.NewClient(clientConn, channels, requests)}, nil
}

var _ CommandRunner = (*SSHRunner)(nil)
