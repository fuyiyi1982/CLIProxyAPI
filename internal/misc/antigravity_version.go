// Package misc provides miscellaneous utility functions for the CLI Proxy API server.
package misc

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

const (
	// antigravityCLIVersion and related fields match the native @google/antigravity-cli
	// wire profile (antigravity/cli/1.3.5).
	antigravityCLIVersion    = "1.3.5"
	antigravityCLIChangelist = "998863838"
	antigravityCLIAuthMethod = "consumer"

	// antigravityFallbackVersion is retained for hub-manifest helpers when queried directly.
	antigravityFallbackVersion = "2.29.0"
	antigravityHubPlatform     = "os_type=darwin; arch=arm64"
	antigravityVersionCacheTTL = 6 * time.Hour
	antigravityFetchTimeout    = 10 * time.Second
	AntigravityNodeAPIClientUA = "google-api-nodejs-client/10.3.0"
	AntigravityGoogAPIClientUA = "gl-node/22.21.1"
)

var (
	antigravityHubLatestManifestURL = "https://antigravity-hub-auto-updater-974169037036.us-central1.run.app/manifest/latest-arm64-mac.yml"
)

// Changelists belong to specific Hub releases, not to the latest manifest in
// general. Update the fallback release and its entry together. The 2.24.0 value
// was verified in the official darwin-arm archive's webm_encoder build metadata.
// Unknown releases keep their online version without claiming another build's CL.
var antigravityHubChangelists = map[string]string{
	"2.23.0": "998057262",
	"2.24.0": "1000335682",
	"2.29.0": "1013060670",
}

type antigravityHubUpdaterManifest struct {
	Version string `yaml:"version"`
}

var (
	cachedAntigravityVersion = antigravityFallbackVersion
	antigravityVersionMu     sync.RWMutex
	antigravityVersionExpiry time.Time
	antigravityUpdaterOnce   sync.Once
)

// StartAntigravityVersionUpdater is a no-op for the Antigravity CLI wire profile;
// background hub manifest polling is disabled to eliminate non-interactive probes.
func StartAntigravityVersionUpdater(_ context.Context) {}

func runAntigravityVersionUpdater(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}

	ticker := time.NewTicker(antigravityVersionCacheTTL / 2)
	defer ticker.Stop()

	log.Infof("periodic antigravity version refresh started (interval=%s)", antigravityVersionCacheTTL/2)

	refreshAntigravityVersion(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshAntigravityVersion(ctx)
		}
	}
}

func refreshAntigravityVersion(ctx context.Context) {
	version, errFetch := fetchAntigravityLatestVersion(ctx)

	antigravityVersionMu.Lock()
	defer antigravityVersionMu.Unlock()

	now := time.Now()

	if errFetch == nil {
		cachedAntigravityVersion = version
		antigravityVersionExpiry = now.Add(antigravityVersionCacheTTL)
		log.WithField("version", version).Info("fetched latest antigravity version")
		return
	}

	if cachedAntigravityVersion == "" || now.After(antigravityVersionExpiry) {
		cachedAntigravityVersion = antigravityFallbackVersion
		antigravityVersionExpiry = now.Add(antigravityVersionCacheTTL)
		log.WithError(errFetch).Warn("failed to refresh antigravity version, using fallback version")
		return
	}

	log.WithError(errFetch).Debug("failed to refresh antigravity version, keeping cached value")
}

// AntigravityLatestVersion returns the cached antigravity version refreshed by StartAntigravityVersionUpdater.
// It falls back to antigravityFallbackVersion if the cache is empty or stale.
func AntigravityLatestVersion() string {
	antigravityVersionMu.RLock()
	if cachedAntigravityVersion != "" && time.Now().Before(antigravityVersionExpiry) {
		v := cachedAntigravityVersion
		antigravityVersionMu.RUnlock()
		return v
	}
	antigravityVersionMu.RUnlock()

	return antigravityFallbackVersion
}

// AntigravityUserAgent returns the User-Agent string matching the native Antigravity CLI wire profile.
func AntigravityUserAgent() string {
	return fmt.Sprintf(
		"antigravity/cli/%s (aidev_client; os_type=%s; arch=%s; cl=%s; auth_method=%s)",
		antigravityCLIVersion,
		runtime.GOOS,
		runtime.GOARCH,
		antigravityCLIChangelist,
		antigravityCLIAuthMethod,
	)
}

func isAntigravityFamilyUserAgent(lower string) bool {
	return strings.HasPrefix(lower, "antigravity/cli/") ||
		strings.HasPrefix(lower, "antigravity/hub/") ||
		strings.HasPrefix(lower, "antigravity/")
}

func antigravityBaseUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return AntigravityUserAgent()
	}
	lower := strings.ToLower(userAgent)
	if isAntigravityFamilyUserAgent(lower) {
		if idx := strings.Index(lower, " google-api-nodejs-client/"); idx >= 0 {
			trimmed := strings.TrimSpace(userAgent[:idx])
			if trimmed != "" {
				return trimmed
			}
		}
	}
	return userAgent
}

// AntigravityRequestUserAgent returns the Antigravity runtime UA used by
// generate/stream/model-list requests.
func AntigravityRequestUserAgent(userAgent string) string {
	return antigravityBaseUserAgent(userAgent)
}

// AntigravityLoadCodeAssistUserAgent returns the Antigravity runtime UA used by
// loadCodeAssist requests.
func AntigravityLoadCodeAssistUserAgent(userAgent string) string {
	return AntigravityRequestUserAgent(userAgent)
}

// AntigravityOnboardUserUserAgent returns the long Antigravity control-plane UA
// used by onboardUser requests.
func AntigravityOnboardUserUserAgent(userAgent string) string {
	userAgent = strings.TrimSpace(userAgent)
	if userAgent == "" {
		return AntigravityUserAgent() + " " + AntigravityNodeAPIClientUA
	}
	lower := strings.ToLower(userAgent)
	if !isAntigravityFamilyUserAgent(lower) {
		return userAgent
	}
	if strings.Contains(lower, "google-api-nodejs-client/") {
		return userAgent
	}
	return antigravityBaseUserAgent(userAgent) + " " + AntigravityNodeAPIClientUA
}

// AntigravityVersionFromUserAgent extracts the Antigravity version prefix from
// either the short or long Antigravity UA forms.
func AntigravityVersionFromUserAgent(userAgent string) string {
	base := antigravityBaseUserAgent(userAgent)
	lower := strings.ToLower(base)
	for _, prefix := range []string{"antigravity/cli/", "antigravity/hub/", "antigravity/"} {
		if strings.HasPrefix(lower, prefix) {
			rest := base[len(prefix):]
			if idx := strings.IndexAny(rest, " \t"); idx >= 0 {
				rest = rest[:idx]
			}
			rest = strings.TrimSpace(rest)
			if rest == "" {
				return antigravityCLIVersion
			}
			return rest
		}
	}
	return antigravityCLIVersion
}

func fetchAntigravityLatestVersion(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	client := &http.Client{Timeout: antigravityFetchTimeout}
	return fetchAntigravityHubLatestManifestVersion(ctx, client)
}

func fetchAntigravityHubLatestManifestVersion(ctx context.Context, client *http.Client) (string, error) {
	httpReq, errReq := http.NewRequestWithContext(ctx, http.MethodGet, antigravityHubLatestManifestURL, nil)
	if errReq != nil {
		return "", fmt.Errorf("build antigravity Hub updater manifest request: %w", errReq)
	}
	httpReq.Header.Set("User-Agent", "electron-builder")
	httpReq.Header.Set("Cache-Control", "no-cache")

	resp, errDo := client.Do(httpReq)
	if errDo != nil {
		return "", fmt.Errorf("fetch antigravity Hub updater manifest: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.WithError(errClose).Warn("antigravity Hub updater manifest response body close error")
		}
	}()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("antigravity Hub updater manifest returned status %d", resp.StatusCode)
	}

	raw, errRead := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if errRead != nil {
		return "", fmt.Errorf("read antigravity Hub updater manifest: %w", errRead)
	}

	var manifest antigravityHubUpdaterManifest
	if errDecode := yaml.Unmarshal(raw, &manifest); errDecode != nil {
		return "", fmt.Errorf("decode antigravity Hub updater manifest: %w", errDecode)
	}

	version := strings.TrimSpace(manifest.Version)
	if version == "" {
		return "", errors.New("antigravity Hub updater manifest returned empty version")
	}
	if !isValidAntigravitySemVersion(version) {
		return "", fmt.Errorf("antigravity Hub updater manifest returned invalid version %q", version)
	}
	return version, nil
}

func isValidAntigravitySemVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}

	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, ch := range part {
			if ch < '0' || ch > '9' {
				return false
			}
		}
	}

	return true
}
