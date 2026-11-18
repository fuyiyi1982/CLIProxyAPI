package helps

import (
	"fmt"
	"strings"

	"github.com/MoeForge/moego/ojson"
	"github.com/MoeForge/moego/regexp"
)

// Normalize only the client identity declaration, not the surrounding persona.
var antigravityHarnessIdentity = regexp.MustCompile(
	`(?i)\bYou are (?:an? (?:AI |coding |autonomous )*(?:agent|assistant)[^.\r\n]{0,40}?\b(?:powered by|for) DeepSeek Harness|DeepSeek Harness(?:,\s*[^.\r\n]{0,80})?)\b[.]?`,
)
var antigravityThirdPartyIdentity = regexp.MustCompile(
	`(?im)^([ \t]*)You are (?:a Claude agent, built on Anthropic's Claude Agent SDK|Claude Code, Anthropic's official CLI for Claude|Codex, an agent based on GPT-[^\r\n]*|omp, an interactive CLI coding agent|a personal assistant running inside OpenClaw)[^\r\n]*`,
)
var antigravityIdentityInvisible = strings.NewReplacer("\u200b", "", "\u200c", "", "\u200d", "", "\ufeff", "", "\u034f", "")

func normalizeAntigravityClientIdentity(text string) string {
	if text == "" {
		return text
	}
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "you are") {
		return text
	}
	hasInvis := strings.ContainsAny(text, "\u200b\u200c\u200d\ufeff\u034f")
	maybeHarness := hasInvis || strings.Contains(lower, "harness")
	maybeThirdParty := hasInvis ||
		strings.Contains(lower, "clau"+"de") ||
		strings.Contains(lower, "co"+"dex") ||
		strings.Contains(lower, "omp") ||
		strings.Contains(lower, "open"+"claw")
	if !maybeHarness && !maybeThirdParty {
		return text
	}

	normalized := antigravityIdentityInvisible.Replace(text)
	out := normalized
	changed := false
	if antigravityHarnessIdentity.MatchString(out) {
		out = antigravityHarnessIdentity.ReplaceAllString(out, "You are an AI coding assistant.")
		changed = true
	}
	if antigravityThirdPartyIdentity.MatchString(out) {
		out = antigravityThirdPartyIdentity.ReplaceAllString(out, "${1}You are an AI coding assistant.")
		changed = true
	}
	if !changed {
		return text
	}
	return out
}

// SanitizeAntigravityTavernIdentityDoc normalizes a known incompatible client
// declaration after protocol translation, before user payload rules. It never
// traverses tool arguments, schemas, media, or signed reasoning parts.
func SanitizeAntigravityTavernIdentityDoc(doc *ojson.Doc, prefix, model string) bool {
	if doc == nil || !strings.EqualFold(strings.Trim(prefix, " /"), "tavern") || !strings.HasPrefix(strings.ToLower(model), "gemini-") {
		return false
	}
	changed := false
	cleanParts := func(root string) {
		for i, part := range doc.Get(root).Array() {
			if part.Get("thought").Bool() || part.Get("thoughtSignature").Exists() || part.Get("thought_signature").Exists() {
				continue
			}
			current := part.Get("text")
			if current.Type != ojson.String {
				continue
			}
			value := normalizeAntigravityClientIdentity(current.String())
			if value != current.String() {
				if doc.Set(fmt.Sprintf("%s.%d.text", root, i), value) == nil {
					changed = true
				}
			}
		}
	}
	cleanParts("request.systemInstruction.parts")
	for i := range doc.Get("request.contents").Array() {
		cleanParts(fmt.Sprintf("request.contents.%d.parts", i))
	}
	return changed
}
