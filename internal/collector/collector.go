package collector

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"

	"lpe-checker/internal/model"
)

// CommandRunner abstracts command execution for tests.
type CommandRunner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

// ExecRunner runs local commands with a timeout.
type ExecRunner struct {
	Timeout time.Duration
}

func (r ExecRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	if r.Timeout <= 0 {
		r.Timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, r.Timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, name, args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return strings.TrimSpace(out.String()), err
	}
	return strings.TrimSpace(out.String()), nil
}

// Collector gathers local Linux privilege-escalation relevant facts.
type Collector struct {
	Runner            CommandRunner
	Platform          string
	KernelModuleNames []string
}

func New() Collector {
	return Collector{Runner: ExecRunner{Timeout: 5 * time.Second}}
}

func (c Collector) Collect(ctx context.Context) (model.SystemInfo, error) {
	if c.Runner == nil {
		c.Runner = ExecRunner{Timeout: 5 * time.Second}
	}
	platform := c.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	info := model.SystemInfo{
		Platform:         platform,
		CollectionErrors: map[string]string{},
		SUIDFiles:        []string{},
		CurrentUser:      model.CurrentUser{Groups: []model.UserGroup{}},
		KernelModules:    map[string]model.KernelModule{},
	}
	var errs []error

	if out, err := c.Runner.Run(ctx, "uname", "-r"); err == nil {
		info.KernelVersion = out
	} else {
		errs = append(errs, err)
		info.CollectionErrors["kernel"] = err.Error()
		info.KernelVersion = runtime.GOOS + " (uname unavailable)"
	}
	if out, err := c.Runner.Run(ctx, "uname", "-m"); err == nil {
		info.Architecture = strings.TrimSpace(out)
	} else {
		errs = append(errs, err)
		info.CollectionErrors["architecture"] = err.Error()
	}

	osRelease, err := c.Runner.Run(ctx, "cat", "/etc/os-release")
	if err != nil {
		errs = append(errs, err)
		info.CollectionErrors["os_release"] = err.Error()
	}
	osInfo := parseOSRelease(osRelease)
	info.OSID = osInfo["ID"]
	info.OSName = osInfo["NAME"]
	info.OSVersionID = osInfo["VERSION_ID"]
	info.OSPrettyName = osInfo["PRETTY_NAME"]

	if out, err := c.Runner.Run(ctx, "id"); err == nil {
		info.CurrentUser = parseIDOutput(out)
	} else {
		errs = append(errs, err)
		info.CollectionErrors["user"] = err.Error()
		info.CurrentUser.Raw = err.Error()
	}

	if out, err := c.Runner.Run(ctx, "sudo", "-n", "-l"); err == nil {
		info.SudoList = model.SudoList{Available: true, Raw: out}
	} else if isExpectedSudoDenial(out) {
		info.SudoList = model.SudoList{Available: false, Raw: out}
	} else {
		info.SudoList = model.SudoList{Available: false, Raw: "sudo -n -l unavailable or requires a password"}
		errs = append(errs, err)
		info.CollectionErrors["sudo"] = err.Error()
	}

	info.SUIDFiles, err = c.collectSUIDFiles(ctx)
	if err != nil {
		errs = append(errs, err)
		info.CollectionErrors["suid"] = err.Error()
	}
	info.KernelModules = c.collectKernelModules(ctx, info.KernelVersion, c.KernelModuleNames)
	return info, errors.Join(errs...)
}

func isExpectedSudoDenial(out string) bool {
	value := strings.ToLower(strings.TrimSpace(out))
	return strings.Contains(value, "password is required") ||
		strings.Contains(value, "a terminal is required") ||
		strings.Contains(value, "not allowed to run sudo") ||
		strings.Contains(value, "is not allowed to run sudo") ||
		strings.Contains(value, "may not run sudo") ||
		strings.Contains(value, "not in the sudoers")
}

// Hostname returns the target hostname through the configured command runner.
func (c Collector) Hostname(ctx context.Context) (string, error) {
	if c.Runner == nil {
		c.Runner = ExecRunner{Timeout: 5 * time.Second}
	}
	out, err := c.Runner.Run(ctx, "hostname")
	if err != nil || strings.TrimSpace(out) == "" {
		if err == nil {
			err = errors.New("hostname returned empty output")
		}
		return "unknown", err
	}
	return strings.TrimSpace(out), nil
}

func (c Collector) collectKernelModules(ctx context.Context, kernelVersion string, moduleNames []string) map[string]model.KernelModule {
	modules := make(map[string]model.KernelModule, len(moduleNames))
	platform := c.Platform
	if platform == "" {
		platform = runtime.GOOS
	}
	if len(moduleNames) == 0 {
		return modules
	}

	if platform != "linux" {
		for _, moduleName := range moduleNames {
			modules[moduleName] = model.KernelModule{
				Name: moduleName, LoadedStatus: "not_applicable", AvailableStatus: "not_applicable", Paths: []string{},
				Raw: "non-linux platform; skipped read-only kernel module checks",
			}
		}
		return modules
	}

	lsmodOutput, lsmodErr := c.Runner.Run(ctx, "lsmod")
	loaded := make(map[string]struct{})
	if lsmodErr == nil {
		for _, line := range strings.Split(lsmodOutput, "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				loaded[fields[0]] = struct{}{}
			}
		}
	}

	for _, moduleName := range moduleNames {
		module := model.KernelModule{Name: moduleName, LoadedStatus: "unknown", AvailableStatus: "unknown", Paths: []string{}}
		if lsmodErr == nil {
			module.Raw = lsmodOutput
			module.LoadedStatus = "not_loaded"
			if _, ok := loaded[moduleName]; ok {
				module.LoadedStatus = "loaded"
			}
		} else {
			module.Raw = "lsmod failed: " + lsmodErr.Error()
		}

		paths, err := c.collectModuleFiles(ctx, kernelVersion, moduleName)
		if err != nil {
			module.Raw += "\nmodule file check failed: " + err.Error()
			modules[moduleName] = module
			continue
		}
		module.Paths = paths
		if len(paths) > 0 {
			module.AvailableStatus = "available"
		} else {
			module.AvailableStatus = "not_found"
		}
		modules[moduleName] = module
	}
	return modules
}

func (c Collector) collectModuleFiles(ctx context.Context, kernelVersion, moduleName string) ([]string, error) {
	moduleDir := "/lib/modules/" + strings.TrimSpace(kernelVersion)
	// The -name argument contains a wildcard. In an SSH runner it must be quoted
	// or escaped so the remote shell cannot expand it before find receives it.
	out, err := c.Runner.Run(ctx, "find", moduleDir, "-name", moduleName+".ko*", "-type", "f")
	if err != nil {
		return []string{}, err
	}
	return parsePathLines(out), nil
}

func parseOSRelease(raw string) map[string]string {
	out := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		out[key] = strings.Trim(val, "\"'")
	}
	return out
}

var idPartRE = regexp.MustCompile(`([a-z]+)=([0-9]+)(?:\(([^)]*)\))?`)

func parseIDOutput(raw string) model.CurrentUser {
	user := model.CurrentUser{Raw: strings.TrimSpace(raw), Groups: []model.UserGroup{}}
	for _, match := range idPartRE.FindAllStringSubmatch(user.Raw, -1) {
		key, num, name := match[1], match[2], match[3]
		switch key {
		case "uid":
			user.UID = num
			user.Username = name
		case "gid":
			user.GID = num
			user.Group = name
		case "groups":
			user.Groups = append(user.Groups, model.UserGroup{GID: num, Group: name})
		}
	}
	if strings.Contains(user.Raw, "groups=") {
		_, groupsRaw, _ := strings.Cut(user.Raw, "groups=")
		for _, groupText := range strings.Split(groupsRaw, ",") {
			m := idPartRE.FindStringSubmatch("groups=" + strings.TrimSpace(groupText))
			if len(m) == 4 {
				user.Groups = appendIfMissingGroup(user.Groups, model.UserGroup{GID: m[2], Group: m[3]})
			}
		}
	}
	return user
}

func appendIfMissingGroup(groups []model.UserGroup, candidate model.UserGroup) []model.UserGroup {
	for _, g := range groups {
		if g.GID == candidate.GID && g.Group == candidate.Group {
			return groups
		}
	}
	return append(groups, candidate)
}

func commonSUIDCandidates() []string {
	return []string{
		// Common legitimate SUID binaries.
		"/bin/su", "/bin/mount", "/bin/umount", "/usr/bin/sudo", "/usr/bin/passwd",
		"/usr/bin/chsh", "/usr/bin/chfn", "/usr/bin/newgrp", "/usr/bin/gpasswd",
		"/usr/bin/pkexec", "/usr/lib/openssh/ssh-keysign", "/usr/lib/dbus-1.0/dbus-daemon-launch-helper",
		// Dangerous when SUID is set by mistake or compromise.
		"/bin/bash", "/usr/bin/bash", "/bin/sh", "/usr/bin/sh", "/usr/bin/find",
		"/usr/bin/vim", "/usr/bin/vi", "/usr/bin/nano", "/usr/bin/nmap",
		"/usr/bin/cp", "/usr/bin/less", "/usr/bin/more", "/usr/bin/python",
		"/usr/bin/python3", "/usr/bin/perl", "/usr/bin/ruby", "/usr/bin/node",
	}
}

func (c Collector) collectSUIDFiles(ctx context.Context) ([]string, error) {
	candidates := commonSUIDCandidates()
	args := append([]string{}, candidates...)
	args = append(args, "-perm", "-4000", "-type", "f")
	out, err := c.Runner.Run(ctx, "find", args...)
	if err != nil {
		// find returns a non-zero exit status when one or more fixed candidates do
		// not exist. ExecRunner still returns the combined output, so preserve and
		// strictly parse it. Runner/launch errors remain reportable failures.
		var exitErr *exec.ExitError
		var remoteExitErr interface{ ExitStatus() int }
		if !errors.As(err, &exitErr) && !errors.As(err, &remoteExitErr) {
			return []string{}, err
		}
	}
	return parseSUIDPaths(out, candidates), nil
}

func parseSUIDPaths(raw string, candidates []string) []string {
	allowed := make(map[string]struct{}, len(candidates))
	for _, candidate := range candidates {
		allowed[candidate] = struct{}{}
	}
	found := []string{}
	for _, path := range parsePathLines(raw) {
		if _, ok := allowed[path]; ok {
			found = append(found, path)
		}
	}
	return found
}

func parsePathLines(raw string) []string {
	paths := []string{}
	for _, line := range strings.Split(raw, "\n") {
		if path := strings.TrimSpace(line); path != "" {
			paths = append(paths, path)
		}
	}
	return paths
}
