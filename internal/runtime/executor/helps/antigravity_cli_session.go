package helps

import (
	"fmt"
	"hash/fnv"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/google/uuid"
)

const (
	agyDefaultSessionTTL     = 24 * time.Hour
	agyDefaultMaxSessions    = 512
	agyDefaultFallbackBucket = "_default"
)

// AgyModelInfo describes the telemetry metadata and native token cap for a Cloud Code model.
type AgyModelInfo struct {
	EnumString             string
	IsClaude               bool
	IsClaudeConservative   bool
	IsNonGemini            bool
	DefaultMaxOutputTokens int
}

// ResolveAgyModelInfo maps an Antigravity upstream model name to Cloud Code telemetry metadata.
func ResolveAgyModelInfo(modelName string) AgyModelInfo {
	normalized := strings.ToLower(strings.TrimSpace(modelName))
	normalized = strings.TrimPrefix(normalized, "models/")

	switch normalized {
	case "gemini-3.1-pro-high":
		return AgyModelInfo{EnumString: "M438", DefaultMaxOutputTokens: 65535}
	case "gemini-3.1-pro-low":
		return AgyModelInfo{EnumString: "M437", DefaultMaxOutputTokens: 65535}
	case "gemini-3.1-pro":
		return AgyModelInfo{EnumString: "M438", DefaultMaxOutputTokens: 65535}
	case "gemini-3.1-flash-image":
		return AgyModelInfo{EnumString: "M427", DefaultMaxOutputTokens: 32768}
	case "gemini-3-flash-agent":
		return AgyModelInfo{EnumString: "M419", DefaultMaxOutputTokens: 65535}
	case "gemini-3-flash", "gemini-3-flash-high", "gemini-3-flash-low", "gemini-3.1-flash-lite":
		return AgyModelInfo{EnumString: "M418", DefaultMaxOutputTokens: 65535}
	case "gemini-3-pro-image":
		return AgyModelInfo{EnumString: "M417", DefaultMaxOutputTokens: 32768}
	case "gemini-3-pro-high":
		return AgyModelInfo{EnumString: "M320", DefaultMaxOutputTokens: 65535}
	case "gemini-3-pro-low":
		return AgyModelInfo{EnumString: "M319", DefaultMaxOutputTokens: 65535}
	case "gemini-3-pro":
		return AgyModelInfo{EnumString: "M318", DefaultMaxOutputTokens: 65535}
	case "gemini-2.5-flash", "gemini-2.5-pro", "gemini-2.5-flash-lite":
		return AgyModelInfo{EnumString: "M21", DefaultMaxOutputTokens: 65535}
	case "claude-opus-4-6-thinking", "claude-opus-4-6":
		return AgyModelInfo{
			EnumString:             "M405",
			IsClaude:               true,
			IsNonGemini:            true,
			DefaultMaxOutputTokens: 64000,
		}
	case "claude-sonnet-4-6", "claude-sonnet-4-6-thinking":
		return AgyModelInfo{
			EnumString:             "M404",
			IsClaude:               true,
			IsNonGemini:            true,
			DefaultMaxOutputTokens: 64000,
		}
	case "claude-opus-4-5-thinking", "claude-opus-4-5":
		return AgyModelInfo{
			EnumString:             "M403",
			IsClaude:               true,
			IsNonGemini:            true,
			DefaultMaxOutputTokens: 64000,
		}
	case "claude-haiku-4-5", "claude-haiku-4-5-thinking":
		return AgyModelInfo{
			EnumString:             "M402",
			IsClaude:               true,
			IsNonGemini:            true,
			DefaultMaxOutputTokens: 64000,
		}
	case "claude-sonnet-4-5-thinking", "claude-sonnet-4-5":
		return AgyModelInfo{
			EnumString:             "M401",
			IsClaude:               true,
			IsNonGemini:            true,
			DefaultMaxOutputTokens: 64000,
		}
	}

	if strings.Contains(normalized, "claude") {
		enum := "M400"
		if strings.Contains(normalized, "opus-4-6") || strings.Contains(normalized, "opus-4.6") {
			enum = "M405"
		} else if strings.Contains(normalized, "sonnet-4-6") || strings.Contains(normalized, "sonnet-4.6") {
			enum = "M404"
		} else if strings.Contains(normalized, "opus") {
			enum = "M403"
		} else if strings.Contains(normalized, "sonnet") {
			enum = "M401"
		}
		return AgyModelInfo{
			EnumString:             enum,
			IsClaude:               true,
			IsNonGemini:            true,
			DefaultMaxOutputTokens: 64000,
		}
	}

	if strings.Contains(normalized, "image") {
		return AgyModelInfo{EnumString: "M427", DefaultMaxOutputTokens: 32768}
	}

	if strings.HasPrefix(normalized, "gemini-3") || strings.HasPrefix(normalized, "gemini-2.5") {
		return AgyModelInfo{EnumString: "MODEL_UNSPECIFIED", DefaultMaxOutputTokens: 65535}
	}

	return AgyModelInfo{EnumString: "MODEL_UNSPECIFIED"}
}

// AgyPreparedMetadata contains per-request Cloud Code CLI requestId, sessionId, and telemetry labels.
type AgyPreparedMetadata struct {
	ConversationID   string
	TrajectoryID     string
	NumericSessionID string
	RequestID        string
	ExecutionID      string
	StepIndex        int
	Labels           map[string]string
}

// AgyExecutionLease advances stored trajectory state when Committed after a clean upstream response.
type AgyExecutionLease struct {
	store      *AgySessionStore
	authKey    string
	sessionKey string
	entry      *agySessionEntry
	execID     string
	stepIndex  int
	once       sync.Once
}

// Commit promotes this request's execution ID and step index to become the previous state for the next turn.
func (l *AgyExecutionLease) Commit() {
	if l == nil || l.store == nil || l.entry == nil {
		return
	}
	l.once.Do(func() {
		l.store.mu.Lock()
		defer l.store.mu.Unlock()
		bucket := l.store.byAuth[l.authKey]
		if bucket == nil || bucket[l.sessionKey] != l.entry {
			return
		}
		l.entry.HasCommitted = true
		l.entry.LastExecutionID = l.execID
		l.entry.LastStepIndex = l.stepIndex
		if l.stepIndex+2 > l.entry.NextStepIndex {
			l.entry.NextStepIndex = l.stepIndex + 2
		}
		l.entry.LastUsed = l.store.now()
	})
}

type agySessionEntry struct {
	ConversationID   string
	TrajectoryID     string
	NumericSessionID string
	HasCommitted     bool
	LastExecutionID  string
	LastStepIndex    int
	NextStepIndex    int
	LastUsed         time.Time
}

// AgySessionStore tracks bounded per-auth conversation/trajectory state for Cloud Code CLI telemetry.
type AgySessionStore struct {
	mu          sync.Mutex
	byAuth      map[string]map[string]*agySessionEntry
	ttl         time.Duration
	maxPerAuth  int
	now         func() time.Time
	newUUIDFunc func() string
}

// NewAgySessionStore constructs a production AgySessionStore with 24h TTL and 512 entries per auth.
func NewAgySessionStore() *AgySessionStore {
	return &AgySessionStore{
		byAuth:      make(map[string]map[string]*agySessionEntry),
		ttl:         agyDefaultSessionTTL,
		maxPerAuth:  agyDefaultMaxSessions,
		now:         time.Now,
		newUUIDFunc: uuid.NewString,
	}
}

// NewAgySessionStoreForTest constructs an AgySessionStore with injectable clock and limits.
func NewAgySessionStoreForTest(ttl time.Duration, maxPerAuth int, nowFn func() time.Time) *AgySessionStore {
	if ttl <= 0 {
		ttl = agyDefaultSessionTTL
	}
	if maxPerAuth <= 0 {
		maxPerAuth = agyDefaultMaxSessions
	}
	if nowFn == nil {
		nowFn = time.Now
	}
	return &AgySessionStore{
		byAuth:      make(map[string]map[string]*agySessionEntry),
		ttl:         ttl,
		maxPerAuth:  maxPerAuth,
		now:         nowFn,
		newUUIDFunc: uuid.NewString,
	}
}

// BeginExecution prepares stateful CLI metadata and returns a lease to Commit on HTTP 200 success.
func (s *AgySessionStore) BeginExecution(
	authID string,
	derivedSessionID string,
	explicitSessionID string,
	contents ojson.Result,
	modelInfo AgyModelInfo,
) (*AgyPreparedMetadata, *AgyExecutionLease) {
	if s == nil {
		return nil, nil
	}
	authKey := strings.TrimSpace(authID)
	if authKey == "" {
		authKey = agyDefaultFallbackBucket
	}
	explicitSessionID = strings.TrimSpace(explicitSessionID)
	derivedSessionID = strings.TrimSpace(derivedSessionID)

	sessionKey := "_auth_default"
	if explicitSessionID != "" {
		sessionKey = "explicit:" + explicitSessionID
	} else if derivedSessionID != "" {
		sessionKey = "derived:" + derivedSessionID
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := s.now()
	bucket := s.byAuth[authKey]
	if bucket == nil {
		bucket = make(map[string]*agySessionEntry)
		s.byAuth[authKey] = bucket
	}

	s.pruneBucketLocked(bucket, now)

	entry := bucket[sessionKey]
	if entry == nil {
		if len(bucket) >= s.maxPerAuth {
			s.evictOldestLocked(bucket)
		}
		convID := s.newUUID()
		trajID := s.newUUID()
		numericSession := explicitSessionID
		if numericSession == "" {
			numericSession = derivedSessionID
		}
		if numericSession == "" {
			numericSession = strconv.FormatInt(fnv1a64Signed(convID), 10)
		}
		entry = &agySessionEntry{
			ConversationID:   convID,
			TrajectoryID:     trajID,
			NumericSessionID: numericSession,
			NextStepIndex:    0,
			LastUsed:         now,
		}
		bucket[sessionKey] = entry
	}
	entry.LastUsed = now

	stepIndex := entry.NextStepIndex
	if contentsCount := countJSONArrayItems(contents); contentsCount > 0 {
		if minStep := contentsCount - 1; minStep > stepIndex {
			stepIndex = minStep
		}
	}

	execID := s.newUUID()
	lastStepIndex := 0
	if entry.HasCommitted {
		lastStepIndex = entry.LastStepIndex
	}

	labels := map[string]string{
		"last_step_index":          strconv.Itoa(lastStepIndex),
		"model_enum":               modelInfo.EnumString,
		"trajectory_id":            entry.TrajectoryID,
		"used_claude":              strconv.FormatBool(modelInfo.IsClaude),
		"used_claude_conservative": strconv.FormatBool(modelInfo.IsClaudeConservative),
		"used_non_gemini_model":    strconv.FormatBool(modelInfo.IsNonGemini),
	}
	if entry.LastExecutionID != "" {
		labels["last_execution_id"] = entry.LastExecutionID
	}

	requestID := fmt.Sprintf("agent/%s/%d/%s/%d", entry.ConversationID, now.UnixMilli(), entry.TrajectoryID, stepIndex)
	meta := &AgyPreparedMetadata{
		ConversationID:   entry.ConversationID,
		TrajectoryID:     entry.TrajectoryID,
		NumericSessionID: entry.NumericSessionID,
		RequestID:        requestID,
		ExecutionID:      execID,
		StepIndex:        stepIndex,
		Labels:           labels,
	}
	lease := &AgyExecutionLease{
		store:      s,
		authKey:    authKey,
		sessionKey: sessionKey,
		entry:      entry,
		execID:     execID,
		stepIndex:  stepIndex,
	}
	return meta, lease
}

// DeleteAuth removes all tracked sessions belonging to an auth credential.
func (s *AgySessionStore) DeleteAuth(authID string) {
	if s == nil {
		return
	}
	authKey := strings.TrimSpace(authID)
	if authKey == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.byAuth, authKey)
}

func (s *AgySessionStore) newUUID() string {
	if s.newUUIDFunc != nil {
		return s.newUUIDFunc()
	}
	return uuid.NewString()
}

func (s *AgySessionStore) pruneBucketLocked(bucket map[string]*agySessionEntry, now time.Time) {
	if s.ttl <= 0 {
		return
	}
	for k, e := range bucket {
		if now.Sub(e.LastUsed) > s.ttl {
			delete(bucket, k)
		}
	}
}

func (s *AgySessionStore) evictOldestLocked(bucket map[string]*agySessionEntry) {
	var oldestKey string
	var oldestTime time.Time
	for k, e := range bucket {
		if oldestKey == "" || e.LastUsed.Before(oldestTime) {
			oldestKey = k
			oldestTime = e.LastUsed
		}
	}
	if oldestKey != "" {
		delete(bucket, oldestKey)
	}
}

func fnv1a64Signed(s string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	return int64(h.Sum64())
}

func countJSONArrayItems(arr ojson.Result) int {
	if !arr.IsArray() {
		return 0
	}
	n := 0
	arr.ForEach(func(_, _ ojson.Result) bool {
		n++
		return true
	})
	return n
}

var (
	agyEnvelopeKeyOrder = []string{"project", "model", "request", "requestType", "userAgent", "requestId"}
	agyRequestKeyOrder  = []string{"contents", "systemInstruction", "tools", "toolConfig", "labels", "generationConfig", "sessionId"}
)

// OrderAgyEnvelopeDoc serializes key order for Cloud Code top-level and request objects without mutating values.
func OrderAgyEnvelopeDoc(doc *ojson.Doc) {
	if doc == nil {
		return
	}
	if reqRes := doc.Get("request"); reqRes.Exists() && isJSONObjectResult(reqRes) {
		if orderedReq, ok := reorderJSONObject(reqRes, agyRequestKeyOrder); ok {
			_ = doc.SetRawBytes("request", orderedReq)
		}
	}
	root := ojson.GetBytesNoCopy(doc.Bytes(), "@this")
	if root.Exists() && isJSONObjectResult(root) {
		if orderedRoot, ok := reorderJSONObject(root, agyEnvelopeKeyOrder); ok {
			*doc = *ojson.NewDoc(orderedRoot)
		}
	}
}

func isJSONObjectResult(res ojson.Result) bool {
	if res.IsObject() {
		return true
	}
	return res.Type == ojson.JSON && strings.HasPrefix(strings.TrimSpace(res.Raw), "{")
}

func reorderJSONObject(obj ojson.Result, preferred []string) ([]byte, bool) {
	rawByKey := make(map[string]string)
	originalOrder := make([]string, 0, 16)
	obj.ForEach(func(k, v ojson.Result) bool {
		key := k.Str
		if _, seen := rawByKey[key]; !seen {
			originalOrder = append(originalOrder, key)
		}
		rawByKey[key] = v.Raw
		return true
	})
	if len(rawByKey) == 0 {
		return []byte("{}"), true
	}

	out := ojson.NewDocString("{}")
	emitted := make(map[string]bool, len(rawByKey))
	for _, key := range preferred {
		if rawVal, ok := rawByKey[key]; ok {
			if errSet := out.SetRaw(escapeOJSONPathKey(key), rawVal); errSet != nil {
				return nil, false
			}
			emitted[key] = true
		}
	}
	for _, key := range originalOrder {
		if emitted[key] {
			continue
		}
		if errSet := out.SetRaw(escapeOJSONPathKey(key), rawByKey[key]); errSet != nil {
			return nil, false
		}
	}
	return out.Bytes(), true
}

func escapeOJSONPathKey(key string) string {
	var b strings.Builder
	b.Grow(len(key))
	for i := 0; i < len(key); i++ {
		switch key[i] {
		case '.', '*', '?', ':', '@', '\\':
			b.WriteByte('\\')
		}
		b.WriteByte(key[i])
	}
	return b.String()
}
