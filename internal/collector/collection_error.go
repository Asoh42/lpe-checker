package collector

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

const safeCollectionErrorPrefix = "collection_error:"

const (
	CollectionErrorReasonNotFound   = "command_not_found"
	CollectionErrorReasonPermission = "permission_denied"
	CollectionErrorReasonTimeout    = "timeout"
	CollectionErrorReasonCanceled   = "canceled"
	CollectionErrorReasonLocalExit  = "local_nonzero_exit"
	CollectionErrorReasonRemoteExit = "remote_nonzero_exit"
	CollectionErrorReasonConnection = "connection_failed"
	CollectionErrorReasonNotAllowed = "not_allowed"
	CollectionErrorReasonOther      = "other"
)

// safeCollectionError converts an arbitrary runner error into a stable,
// report-safe value. The command label is supplied by the collector and must
// not contain target-controlled data. The original error remains in the
// separate error returned by Collector.Collect for stderr diagnostics.
func safeCollectionError(command string, err error) string {
	return fmt.Sprintf("%s%s:%s", safeCollectionErrorPrefix, collectionErrorReason(err), command)
}

// ParseSafeCollectionError exposes the stable code to the display layer
// without making collector depend on display (which already imports collector).
func ParseSafeCollectionError(value string) (command, reason string, ok bool) {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, safeCollectionErrorPrefix) {
		return "", "", false
	}
	rest := strings.TrimPrefix(value, safeCollectionErrorPrefix)
	reason, command, ok = strings.Cut(rest, ":")
	if !ok || reason == "" || command == "" {
		return "", "", false
	}
	return command, reason, true
}

func collectionErrorReason(err error) string {
	var rejected *CommandNotAllowedError
	if errors.As(err, &rejected) {
		return CollectionErrorReasonNotAllowed
	}

	var connectionErr *ConnectionError
	if errors.As(err, &connectionErr) {
		if reason, known := knownCollectionErrorReason(connectionErr.Err); known {
			return reason
		}
		return CollectionErrorReasonConnection
	}

	var commandErr *CommandError
	if errors.As(err, &commandErr) {
		if reason, known := knownCollectionErrorReason(commandErr.Err); known {
			return reason
		}
		return CollectionErrorReasonOther
	}

	if reason, known := knownCollectionErrorReason(err); known {
		return reason
	}
	return CollectionErrorReasonOther
}

func knownCollectionErrorReason(err error) (string, bool) {
	switch {
	case errors.Is(err, exec.ErrNotFound):
		return CollectionErrorReasonNotFound, true
	case errors.Is(err, os.ErrPermission):
		return CollectionErrorReasonPermission, true
	case errors.Is(err, context.DeadlineExceeded):
		return CollectionErrorReasonTimeout, true
	case errors.Is(err, context.Canceled):
		return CollectionErrorReasonCanceled, true
	}

	var localExitErr *exec.ExitError
	if errors.As(err, &localExitErr) {
		return CollectionErrorReasonLocalExit, true
	}
	var remoteExitErr interface{ ExitStatus() int }
	if errors.As(err, &remoteExitErr) {
		return CollectionErrorReasonRemoteExit, true
	}
	return "", false
}
