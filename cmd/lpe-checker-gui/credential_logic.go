package main

import "strings"

const (
	credentialSourceOwn = "__own__"

	credentialErrorOwnEmpty   = "own_password_empty"
	credentialErrorMissing    = "credential_group_missing"
	credentialErrorGroupEmpty = "credential_group_password_empty"
)

type credentialResolutionError struct {
	Kind  string
	Group string
}

func (e *credentialResolutionError) Error() string {
	if e.Group == "" {
		return e.Kind
	}
	return e.Kind + ": " + e.Group
}

func resolveHostPassword(source, ownPassword string, groups map[string]string) (string, error) {
	if source == credentialSourceOwn {
		if ownPassword == "" {
			return "", &credentialResolutionError{Kind: credentialErrorOwnEmpty}
		}
		return ownPassword, nil
	}
	groupName := strings.TrimSpace(source)
	password, ok := groups[groupName]
	if !ok || groupName == "" {
		return "", &credentialResolutionError{Kind: credentialErrorMissing, Group: groupName}
	}
	if password == "" {
		return "", &credentialResolutionError{Kind: credentialErrorGroupEmpty, Group: groupName}
	}
	return password, nil
}
