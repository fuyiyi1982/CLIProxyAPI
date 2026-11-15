package management

import (
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestIsPersistentAuthFailureAllowsAntigravityOnDemandRefresh(t *testing.T) {
	coreauth.RegisterRefreshLeadProvider("antigravity", func() *time.Duration { return nil })
	now := time.Now()

	lazy := &coreauth.Auth{
		ID:       "agy-lazy-mgmt",
		Provider: "antigravity",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{
			"access_token":  "expired-tok",
			"refresh_token": "valid-ref",
			"expired":       now.Add(-5 * time.Minute).Format(time.RFC3339),
		},
	}
	if isPersistentAuthFailure(lazy, now) {
		t.Fatal("expected expired antigravity credential with refresh_token not to be marked persistent failure")
	}

	missingRefresh := lazy.Clone()
	delete(missingRefresh.Metadata, "refresh_token")
	if !isPersistentAuthFailure(missingRefresh, now) {
		t.Fatal("expected expired antigravity credential without refresh_token to be marked persistent failure")
	}
}
