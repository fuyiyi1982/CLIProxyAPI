package auth

import (
	"context"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type antigravityLazyPrepareTestExecutor struct {
	schedulerProviderTestExecutor
	prepareCalls int
}

func (e *antigravityLazyPrepareTestExecutor) ShouldPrepareRequestAuth(auth *Auth) bool {
	if auth == nil {
		return false
	}
	exp, ok := auth.ExpirationTime()
	return ok && !exp.After(time.Now().Add(5*time.Minute))
}

func (e *antigravityLazyPrepareTestExecutor) PrepareRequestAuth(_ context.Context, auth *Auth) (*Auth, error) {
	e.prepareCalls++
	updated := auth.Clone()
	if updated.Metadata == nil {
		updated.Metadata = make(map[string]any)
	}
	updated.Metadata["access_token"] = "refreshed-access-token"
	updated.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	return updated, nil
}

func (e *antigravityLazyPrepareTestExecutor) Execute(_ context.Context, auth *Auth, _ cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{Payload: []byte(authAccessToken(auth))}, nil
}

func TestAntigravityExpiredAccessTokenRefreshesOnDemand(t *testing.T) {
	setRefreshLeadFactory(t, "antigravity", func() *time.Duration { return nil })
	now := time.Now()

	validLazy := &Auth{
		ID:       "agy-lazy-1",
		Provider: "antigravity",
		Status:   StatusActive,
		Metadata: map[string]any{
			"access_token":  "expired-access-token",
			"refresh_token": "valid-refresh-token",
			"project_id":    "aicode-consumers",
			"expired":       now.Add(-10 * time.Minute).Format(time.RFC3339),
		},
	}
	if !validLazy.CanRefreshAccessTokenOnDemand(now) {
		t.Fatal("expected expired antigravity credential with refresh_token to allow on-demand refresh")
	}
	if !IsAuthAvailableForModel(validLazy, "gemini-3.8-flash", now) {
		t.Fatal("expected selector not to block expired antigravity credential when on-demand refresh is available")
	}
	if isCredentialBlocked(validLazy, 0, now) {
		t.Fatal("expected scheduler not to block expired antigravity credential when on-demand refresh is available")
	}

	noRefresh := validLazy.Clone()
	delete(noRefresh.Metadata, "refresh_token")
	if noRefresh.CanRefreshAccessTokenOnDemand(now) || IsAuthAvailableForModel(noRefresh, "gemini-3.8-flash", now) {
		t.Fatal("expected expired antigravity credential without refresh_token to remain blocked")
	}

	rejected := validLazy.Clone()
	rejected.RequiresSignIn = true
	if rejected.CanRefreshAccessTokenOnDemand(now) || IsAuthAvailableForModel(rejected, "gemini-3.8-flash", now) {
		t.Fatal("expected antigravity credential requiring sign-in to remain blocked")
	}

	manager := NewManager(nil, &RoundRobinSelector{}, nil)
	exec := &antigravityLazyPrepareTestExecutor{
		schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "antigravity"},
	}
	manager.RegisterExecutor(exec)
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(validLazy.ID, "antigravity", []*registry.ModelInfo{{ID: "gemini-3.8-flash"}})
	t.Cleanup(func() {
		reg.UnregisterClient(validLazy.ID)
	})
	if _, err := manager.Register(context.Background(), validLazy); err != nil {
		t.Fatalf("Register error = %v", err)
	}

	resp, err := manager.Execute(context.Background(), []string{"antigravity"}, cliproxyexecutor.Request{Model: "gemini-3.8-flash"}, cliproxyexecutor.Options{})
	if err != nil {
		t.Fatalf("Execute error = %v", err)
	}
	if got := string(resp.Payload); got != "refreshed-access-token" {
		t.Fatalf("Execute payload = %q, want refreshed-access-token", got)
	}
	if exec.prepareCalls != 1 {
		t.Fatalf("prepareCalls = %d, want 1", exec.prepareCalls)
	}
	persisted, ok := manager.GetByID(validLazy.ID)
	if !ok || !persisted.HasValidAccessToken(time.Now()) {
		t.Fatalf("expected refreshed token to be persisted on manager, got %#v", persisted)
	}
}
