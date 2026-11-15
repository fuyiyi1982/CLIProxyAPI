package helps

import (
	"strings"
	"testing"

	"github.com/MoeForge/moego/ojson"
)

func TestAntigravityTavernClientIdentity(t *testing.T) {
	identity := "You are an AI agent powered by DeepSeek Harness."
	doc := ojson.NewDoc([]byte(`{"request":{"systemInstruction":{"parts":[]},"contents":[{"role":"user","parts":[]},{"role":"model","parts":[]}]}}`))
	text := identity + " Keep this same-line persona.\nYou are Yuika."
	_ = doc.Set("request.systemInstruction.parts", []any{map[string]any{"text": text}})
	_ = doc.Set("request.contents.0.parts", []any{
		map[string]any{"text": "<system-reminder>" + identity + "</system-reminder>"},
		map[string]any{"functionResponse": map[string]any{"name": "read", "response": map[string]any{"text": identity}}},
		map[string]any{"inlineData": map[string]any{"mimeType": "image/png", "data": "aGVsbG8="}},
	})
	_ = doc.Set("request.contents.1.parts", []any{
		map[string]any{"text": identity, "thought": true, "thoughtSignature": "opaque-signature"},
		map[string]any{"functionCall": map[string]any{"name": "echo", "args": map[string]any{"text": identity}}},
		map[string]any{"text": identity},
	})
	_ = doc.Set("request.tools", []any{map[string]any{"functionDeclarations": []any{map[string]any{"name": "echo", "description": identity}}}})
	preserved := map[string]string{}
	for _, p := range []string{"request.tools", "request.contents.0.parts.1", "request.contents.0.parts.2", "request.contents.1.parts.0", "request.contents.1.parts.1"} {
		preserved[p] = doc.Get(p).Raw
	}
	if !SanitizeAntigravityTavernIdentityDoc(doc, "tavern", "gemini-4-argon") {
		t.Fatal("expected identity normalization")
	}
	if got := doc.Get("request.systemInstruction.parts.0.text").String(); got != "You are an AI coding assistant. Keep this same-line persona.\nYou are Yuika." {
		t.Fatalf("persona changed: %q", got)
	}
	for _, p := range []string{"request.contents.0.parts.0.text", "request.contents.1.parts.2.text"} {
		if strings.Contains(doc.Get(p).String(), "DeepSeek Harness") {
			t.Fatalf("identity remains at %s", p)
		}
	}
	for p, want := range preserved {
		if doc.Get(p).Raw != want {
			t.Fatalf("non-text field changed: %s", p)
		}
	}
	first := doc.String()
	if SanitizeAntigravityTavernIdentityDoc(doc, "tavern", "gemini-4-argon") || doc.String() != first {
		t.Fatal("normalization is not idempotent")
	}
}

func TestAntigravityTavernClientIdentityIsolation(t *testing.T) {
	identity := "You are an AI agent powered by DeepSeek Harness."
	for _, tc := range []struct{ prefix, model string }{{"shared", "gemini-4-argon"}, {"", "gemini-4-argon"}, {"tavern", "claude-sonnet"}, {"tavern", "gpt-oss"}} {
		doc := ojson.NewDoc([]byte(`{"request":{"systemInstruction":{"parts":[]}}}`))
		_ = doc.Set("request.systemInstruction.parts", []any{map[string]any{"text": identity}})
		before := doc.String()
		if SanitizeAntigravityTavernIdentityDoc(doc, tc.prefix, tc.model) || before != doc.String() {
			t.Fatalf("unexpected mutation: %+v", tc)
		}
	}
	for _, text := range []string{"You are an AI agent powered by another service.", "DeepSeek Harness documentation", "You are Yuika.", "", "You are an AI assistant powered by Example Harness."} {
		if normalizeAntigravityClientIdentity(text) != text {
			t.Fatalf("ordinary text changed: %q", text)
		}
	}
	if got := normalizeAntigravityClientIdentity("You are an AI agent powered by Deep\u200bSeek Harness."); got != "You are an AI coding assistant." {
		t.Fatalf("invisible variant: %q", got)
	}
}
