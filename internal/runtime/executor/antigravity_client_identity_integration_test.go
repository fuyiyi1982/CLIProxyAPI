package executor

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestAntigravityTavernIdentityRequestBuilder(t *testing.T) {
	identity := "You are an AI agent powered by DeepSeek Harness."
	for _, stream := range []bool{false, true} {
		for _, prefix := range []string{"tavern", "shared", ""} {
			exec := NewAntigravityExecutor(&config.Config{})
			auth := &cliproxyauth.Auth{ID: "identity-test", Prefix: prefix, Metadata: map[string]any{"project_id": "test-project"}}
			doc := ojson.NewDoc([]byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"Reply OK"}]}],"systemInstruction":{"parts":[]}}}`))
			_ = doc.Set("request.systemInstruction.parts", []any{map[string]any{"text": identity + "\nYou are Yuika."}})
			req, body, err := exec.buildRequestDoc(context.Background(), auth, "test-token", "gemini-4-argon", doc, stream, "", "https://example.invalid")
			if err != nil {
				t.Fatal(err)
			}
			wire, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if string(wire) != string(body) {
				t.Fatal("request body differs from finalized payload")
			}
			text := ojson.GetBytesNoCopy(body, "request.systemInstruction.parts.0.text").String()
			if (prefix == "tavern") == strings.Contains(text, "DeepSeek Harness") {
				t.Fatalf("wrong identity result for prefix %q: %q", prefix, text)
			}
			if !strings.Contains(text, "You are Yuika.") {
				t.Fatal("persona lost")
			}
		}
	}
}

func TestAntigravityTavernIdentityPreservesFinalPayloadBarrier(t *testing.T) {
	exec := NewAntigravityExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{ID: "identity-barrier", Prefix: "tavern", Metadata: map[string]any{"project_id": "test-project"}}
	doc := ojson.NewDoc([]byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"Reply OK"}]}],"systemInstruction":{"parts":[{"text":"You are an AI agent powered by DeepSeek Harness."}]}}}`))
	calls := 0
	finalizer := helps.PayloadFinalizer(func(body []byte) []byte {
		calls++
		current := ojson.NewDoc(body)
		if got := current.Get("request.systemInstruction.parts.0.text").String(); got != "You are an AI coding assistant." {
			t.Fatalf("normalization must precede payload rules: %q", got)
		}
		_ = current.Set("request.systemInstruction.parts.0.text", "operator final override")
		return current.Bytes()
	})
	ctx := helps.WithPayloadFinalizer(context.Background(), finalizer)
	_, body, err := exec.buildRequestDoc(ctx, auth, "test-token", "gemini-3.8-flash", doc, false, "", "https://example.invalid")
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("finalizer calls = %d", calls)
	}
	if got := ojson.GetBytesNoCopy(body, "request.systemInstruction.parts.0.text").String(); got != "operator final override" {
		t.Fatalf("payload rule overwritten: %q", got)
	}
}
