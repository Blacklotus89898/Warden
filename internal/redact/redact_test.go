package redact

import (
	"strings"
	"testing"
)

func TestSecretsAreRedacted(t *testing.T) {
	leaks := map[string]string{
		"password=hunter2":                                          "hunter2",
		`"api_key": "abc123xyz"`:                                    "abc123xyz",
		"Authorization: Bearer s3cr3t-token-value":                  "s3cr3t-token-value",
		"postgres://admin:admin@db:5432/x":                          "admin:admin",
		"token ghp_0123456789abcdefghijABCDEFGHIJ":                  "ghp_0123456789",
		"jwt eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.SflKxwRJSMeKKF2QT4":  "SflKxwRJSMeKKF2QT4",
		"blob dGhpcyBpcyBhIHZlcnkgbG9uZyBzZWNyZXQgdmFsdWUgaW5kZWVk": "dGhpcyBpcyBhIHZlcnkg",
	}
	for in, secret := range leaks {
		if out := String(in); strings.Contains(out, secret) {
			t.Errorf("%q → %q still contains %q", in, out, secret)
		}
	}
	keep := "Back-off restarting failed container dind in pod petal-1"
	if String(keep) != keep {
		t.Errorf("ordinary text changed: %q", String(keep))
	}
}

func TestTruncateAndLines(t *testing.T) {
	if got := Truncate("héllo wörld", 3); got != "hé …" && got != "h …" {
		t.Errorf("truncate = %q", got)
	}
	ls := Lines("a\nb\nc\nd\n", 2)
	if len(ls) != 2 || ls[0] != "c" || ls[1] != "d" {
		t.Errorf("lines = %v", ls)
	}
}
