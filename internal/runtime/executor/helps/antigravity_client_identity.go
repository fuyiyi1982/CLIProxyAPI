package helps

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/MoeForge/moego/ojson"
)

// Normalize only the client identity declaration, not the surrounding persona.
var antigravityHarnessIdentity = regexp.MustCompile(`(?i)\bYou are (?:an? (?:AI |coding |autonomous )*(?:agent|assistant) powered by DeepSeek Harness|DeepSeek Harness)\b[.]?`)
var antigravityIdentityInvisible = strings.NewReplacer("\u200b", "", "\u200c", "", "\u200d", "", "\ufeff", "", "\u034f", "")

func normalizeAntigravityClientIdentity(text string) string {
	if !strings.Contains(strings.ToLower(text), "harness") {
		return text
	}
	normalized := antigravityIdentityInvisible.Replace(text)
	if !antigravityHarnessIdentity.MatchString(normalized) {
		return text
	}
	return antigravityHarnessIdentity.ReplaceAllString(normalized, "You are an AI coding assistant.")
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
