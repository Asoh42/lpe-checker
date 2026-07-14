package main

import (
	"errors"
	"testing"
)

func TestResolveHostPasswordOwn(t *testing.T) {
	got, err := resolveHostPassword(credentialSourceOwn, "example-password", map[string]string{"shared": "example-password"})
	if err != nil || got != "example-password" {
		t.Fatalf("got password=%q err=%v", got, err)
	}
}

func TestResolveHostPasswordCredentialGroup(t *testing.T) {
	got, err := resolveHostPassword("shared", "example-password-unused", map[string]string{"shared": "example-password"})
	if err != nil || got != "example-password" {
		t.Fatalf("got password=%q err=%v", got, err)
	}
}

func TestResolveHostPasswordRejectsMissingAndEmptyGroup(t *testing.T) {
	tests := []struct {
		source string
		groups map[string]string
		kind   string
	}{
		{source: "missing", groups: map[string]string{}, kind: credentialErrorMissing},
		{source: "empty", groups: map[string]string{"empty": ""}, kind: credentialErrorGroupEmpty},
	}
	for _, tt := range tests {
		_, err := resolveHostPassword(tt.source, "", tt.groups)
		var resolutionErr *credentialResolutionError
		if !errors.As(err, &resolutionErr) || resolutionErr.Kind != tt.kind {
			t.Fatalf("source=%q got err=%v", tt.source, err)
		}
	}
}

func TestResolveHostPasswordRejectsEmptyOwnPassword(t *testing.T) {
	_, err := resolveHostPassword(credentialSourceOwn, "", nil)
	var resolutionErr *credentialResolutionError
	if !errors.As(err, &resolutionErr) || resolutionErr.Kind != credentialErrorOwnEmpty {
		t.Fatalf("got err=%v", err)
	}
}
