package executor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v8/sdk/translator"
)

func TestAntigravityCLIVersionAndUserAgent(t *testing.T) {
	want := fmt.Sprintf("antigravity/cli/1.3.5 (aidev_client; os_type=%s; arch=%s; cl=998863838; auth_method=consumer)", runtime.GOOS, runtime.GOARCH)
	if got := misc.AntigravityUserAgent(); got != want {
		t.Fatalf("AntigravityUserAgent() = %q, want %q", got, want)
	}

	// StartAntigravityVersionUpdater must return immediately as a no-op.
	misc.StartAntigravityVersionUpdater(context.Background())

	exec := NewAntigravityExecutor(&config.Config{})
	authWithLegacyHubUA := &cliproxyauth.Auth{
		ID: "legacy-hub-ua-auth",
		Metadata: map[string]any{
			"project_id": "proj-1",
			"user_agent": "antigravity/hub/2.29.0 (aidev_client; os_type=darwin; arch=arm64; cl=1013060670)",
		},
	}
	reqHub, errHub := exec.buildRequest(context.Background(), authWithLegacyHubUA, "tok", "gemini-3.1-pro-high", []byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}}`), false, "", "https://example.invalid")
	if errHub != nil {
		t.Fatalf("buildRequest error = %v", errHub)
	}
	if got := reqHub.Header.Get("User-Agent"); got != want {
		t.Fatalf("User-Agent for legacy hub metadata = %q, want %q", got, want)
	}

	authWithLegacy1xUA := &cliproxyauth.Auth{
		ID: "legacy-1x-ua-auth",
		Metadata: map[string]any{
			"project_id": "proj-1",
			"user_agent": "antigravity/1.23.2 windows/amd64",
		},
	}
	req1x, err1x := exec.buildRequest(context.Background(), authWithLegacy1xUA, "tok", "gemini-3.1-pro-high", []byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}}`), false, "", "https://example.invalid")
	if err1x != nil {
		t.Fatalf("buildRequest error = %v", err1x)
	}
	if got := req1x.Header.Get("User-Agent"); got != want {
		t.Fatalf("User-Agent for legacy 1.x metadata = %q, want %q", got, want)
	}

	authWithExplicitAttr := &cliproxyauth.Auth{
		ID:         "explicit-attr-ua-auth",
		Attributes: map[string]string{"user_agent": "antigravity/cli/custom-override"},
		Metadata:   map[string]any{"project_id": "proj-1"},
	}
	reqAttr, errAttr := exec.buildRequest(context.Background(), authWithExplicitAttr, "tok", "gemini-3.1-pro-high", []byte(`{"request":{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}}`), false, "", "https://example.invalid")
	if errAttr != nil {
		t.Fatalf("buildRequest error = %v", errAttr)
	}
	if got := reqAttr.Header.Get("User-Agent"); got != "antigravity/cli/custom-override" {
		t.Fatalf("User-Agent for explicit attribute = %q, want override", got)
	}
}

func TestAntigravityRefreshDefaultZeroLoadCodeAssist(t *testing.T) {
	tokenCalls, creditsCalls := 0, 0
	transport := roundTripperFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://oauth2.googleapis.com/token":
			tokenCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{"access_token":"fresh-tok","expires_in":3600}`)),
				Request:    req,
			}, nil
		case "https://daily-cloudcode-pa.googleapis.com/v1internal:loadCodeAssist":
			creditsCalls++
			return &http.Response{
				StatusCode: http.StatusOK,
				Header:     http.Header{"Content-Type": {"application/json"}},
				Body:       io.NopCloser(strings.NewReader(`{}`)),
				Request:    req,
			}, nil
		default:
			return nil, fmt.Errorf("unexpected URL: %s", req.URL.String())
		}
	})

	exec := NewAntigravityExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID:       "refresh-zero-lca",
		Provider: "antigravity",
		Metadata: map[string]any{
			"access_token":  "old-tok",
			"refresh_token": "ref-tok",
			"project_id":    "proj-1",
			"expired":       time.Now().Add(-time.Minute).Format(time.RFC3339),
		},
	}
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", transport)
	updated, err := exec.Refresh(ctx, auth)
	if err != nil {
		t.Fatalf("Refresh() error = %v", err)
	}
	if updated == nil || updated.Metadata["access_token"] != "fresh-tok" {
		t.Fatalf("unexpected updated auth: %#v", updated)
	}
	if tokenCalls != 1 {
		t.Fatalf("tokenCalls = %d, want 1", tokenCalls)
	}
	if creditsCalls != 0 {
		t.Fatalf("creditsCalls = %d, want 0 (loadCodeAssist must not be called during default Refresh)", creditsCalls)
	}
}

func TestAntigravityStatefulTrajectoryAndLabelsAcrossTurns(t *testing.T) {
	var mu sync.Mutex
	var capturedBodies [][]byte
	attempt := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		attempt++
		cur := attempt
		capturedBodies = append(capturedBodies, body)
		mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		if cur == 2 {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `{"error":{"code":500,"message":"simulated upstream error"}}`)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":3,"totalTokenCount":13}}}`)
	}))
	defer server.Close()

	exec := NewAntigravityExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID:       "trajectory-auth-1",
		Provider: "antigravity",
		Attributes: map[string]string{
			"base_url": server.URL,
		},
		Metadata: map[string]any{
			"access_token": "tok-1",
			"project_id":   "proj-traj",
			"expired":      time.Now().Add(time.Hour).Format(time.RFC3339),
		},
	}

	req1 := cliproxyexecutor.Request{
		Model:   "gemini-3.1-pro-high",
		Payload: []byte(`{"contents":[{"role":"user","parts":[{"text":"turn 1"}]}]}`),
		Metadata: map[string]any{
			"session_id": "conv-session-alpha",
		},
	}
	opts := cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatGemini,
		Metadata: map[string]any{
			"session_id": "conv-session-alpha",
		},
	}

	// Turn 1: succeeds and commits step 0.
	if _, err := exec.Execute(context.Background(), auth, req1, opts); err != nil {
		t.Fatalf("Turn 1 Execute error = %v", err)
	}
	// Turn 2: fails with 500 -> must NOT advance trajectory state.
	req2 := req1
	req2.Payload = []byte(`{"contents":[{"role":"user","parts":[{"text":"turn 1"}]},{"role":"model","parts":[{"text":"ok"}]},{"role":"user","parts":[{"text":"turn 2"}]}]}`)
	if _, err := exec.Execute(context.Background(), auth, req2, opts); err == nil {
		t.Fatal("Turn 2 expected error on 500, got nil")
	}
	// Turn 3: retry Turn 2 succeeds -> must share Turn 2's pre-commit state (last_step_index="0").
	if _, err := exec.Execute(context.Background(), auth, req2, opts); err != nil {
		t.Fatalf("Turn 3 Execute error = %v", err)
	}
	// Turn 4: after committed Turn 3 -> last_step_index="2", requestId step 4.
	req4 := req1
	req4.Payload = []byte(`{"contents":[{"role":"user","parts":[{"text":"t1"}]},{"role":"model","parts":[{"text":"r1"}]},{"role":"user","parts":[{"text":"t2"}]},{"role":"model","parts":[{"text":"r2"}]},{"role":"user","parts":[{"text":"t4"}]}]}`)
	if _, err := exec.Execute(context.Background(), auth, req4, opts); err != nil {
		t.Fatalf("Turn 4 Execute error = %v", err)
	}
	// Reset auth sessions -> Turn 5 starts a fresh trajectory_id with no last_execution_id.
	exec.CloseAuthExecutionSessions(auth.ID)
	if _, err := exec.Execute(context.Background(), auth, req1, opts); err != nil {
		t.Fatalf("Turn 5 Execute error = %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(capturedBodies) != 5 {
		t.Fatalf("capturedBodies len = %d, want 5", len(capturedBodies))
	}

	extractMeta := func(raw []byte) (reqID, trajID, lastExec, lastStep, modelEnum string, maxOut int64, parts []string) {
		reqID = ojson.GetBytesNoCopy(raw, "requestId").String()
		trajID = ojson.GetBytesNoCopy(raw, "request.labels.trajectory_id").String()
		lastExec = ojson.GetBytesNoCopy(raw, "request.labels.last_execution_id").String()
		lastStep = ojson.GetBytesNoCopy(raw, "request.labels.last_step_index").String()
		modelEnum = ojson.GetBytesNoCopy(raw, "request.labels.model_enum").String()
		maxOut = ojson.GetBytesNoCopy(raw, "request.generationConfig.maxOutputTokens").Int()
		parts = strings.Split(reqID, "/")
		return
	}

	id1, traj1, le1, ls1, enum1, max1, p1 := extractMeta(capturedBodies[0])
	if len(p1) != 5 || p1[0] != "agent" || p1[4] != "0" || p1[3] != traj1 {
		t.Fatalf("Turn 1 requestId = %q (traj=%q), want agent/<conv>/<ts>/<traj>/0", id1, traj1)
	}
	if le1 != "" {
		t.Fatalf("Turn 1 last_execution_id = %q, want omitted", le1)
	}
	if ls1 != "0" || enum1 != "M438" || max1 != 65535 {
		t.Fatalf("Turn 1 labels=(step=%q enum=%q maxOut=%d)", ls1, enum1, max1)
	}

	_, traj2, le2, ls2, _, _, p2 := extractMeta(capturedBodies[1])
	_, traj3, le3, ls3, _, _, p3 := extractMeta(capturedBodies[2])
	_, traj4, le4, ls4, _, _, p4 := extractMeta(capturedBodies[3])
	_, traj5, le5, ls5, _, _, p5 := extractMeta(capturedBodies[4])

	if traj2 != traj1 || traj3 != traj1 || traj4 != traj1 {
		t.Fatalf("trajectory_id changed across turns: %q %q %q %q", traj1, traj2, traj3, traj4)
	}
	if p2[4] != "2" || p3[4] != "2" || p4[4] != "4" {
		t.Fatalf("unexpected requestId steps across turns: t2=%q t3=%q t4=%q", p2[4], p3[4], p4[4])
	}
	if le2 == "" || le2 != le3 || ls2 != "0" || ls3 != "0" {
		t.Fatalf("failed Turn 2 mutated state for retry Turn 3: le2=%q le3=%q ls2=%q ls3=%q", le2, le3, ls2, ls3)
	}
	if le4 == "" || le4 == le3 || ls4 != "2" {
		t.Fatalf("Turn 4 did not advance committed state from Turn 3: le3=%q le4=%q ls4=%q", le3, le4, ls4)
	}
	if traj5 == traj1 || le5 != "" || ls5 != "0" || p5[4] != "0" {
		t.Fatalf("CloseAuthExecutionSessions did not reset session: traj5=%q traj1=%q le5=%q ls5=%q step5=%q", traj5, traj1, le5, ls5, p5[4])
	}
}

func TestAntigravityJSONKeyOrderingAndModelEnums(t *testing.T) {
	cases := []struct {
		model     string
		wantEnum  string
		wantMax   int64
		wantClaud string
	}{
		{"gemini-3.1-pro-high", "M438", 65535, "false"},
		{"gemini-3-flash", "M418", 65535, "false"},
		{"gemini-3-pro-image", "M417", 32768, ""},
		{"claude-sonnet-4-6", "M404", 64000, "true"},
		{"claude-opus-4-6-thinking", "M405", 64000, "true"},
	}

	exec := NewAntigravityExecutor(&config.Config{})
	auth := &cliproxyauth.Auth{
		ID:       "order-enum-auth",
		Provider: "antigravity",
		Metadata: map[string]any{"project_id": "proj-order"},
	}

	for _, tc := range cases {
		t.Run(tc.model, func(t *testing.T) {
			info := helps.ResolveAgyModelInfo(tc.model)
			if info.EnumString != tc.wantEnum || int64(info.DefaultMaxOutputTokens) != tc.wantMax {
				t.Fatalf("ResolveAgyModelInfo(%q) = %+v, want enum=%q max=%d", tc.model, info, tc.wantEnum, tc.wantMax)
			}

			rawDoc := ojson.NewDocString(`{"request":{"sessionId":"-42","generationConfig":{"temperature":0.5},"tools":[{"functionDeclarations":[{"name":"f","parameters":{"type":"object"}}]}],"systemInstruction":{"parts":[{"text":"sys"}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}]},"userAgent":"ignore"}`)
			_, finalPayload, _, err := exec.buildRequestDocWithExecution(context.Background(), auth, "tok", tc.model, rawDoc, true, "", "https://example.invalid")
			if err != nil {
				t.Fatalf("buildRequestDocWithExecution error = %v", err)
			}

			if gotMax := ojson.GetBytesNoCopy(finalPayload, "request.generationConfig.maxOutputTokens").Int(); gotMax != tc.wantMax {
				t.Fatalf("maxOutputTokens = %d, want %d; body=%s", gotMax, tc.wantMax, finalPayload)
			}
			if tc.wantClaud != "" {
				if gotEnum := ojson.GetBytesNoCopy(finalPayload, "request.labels.model_enum").String(); gotEnum != tc.wantEnum {
					t.Fatalf("model_enum = %q, want %q", gotEnum, tc.wantEnum)
				}
				if gotClaude := ojson.GetBytesNoCopy(finalPayload, "request.labels.used_claude").String(); gotClaude != tc.wantClaud {
					t.Fatalf("used_claude = %q, want %q", gotClaude, tc.wantClaud)
				}
			}

			// Verify top-level envelope key order via sequential Key iteration.
			root := ojson.GetBytesNoCopy(finalPayload, "@this")
			var topKeys []string
			root.ForEach(func(k, _ ojson.Result) bool {
				topKeys = append(topKeys, k.Str)
				return true
			})
			wantTop := []string{"project", "model", "request", "requestType", "userAgent", "requestId"}
			if strings.Join(topKeys, ",") != strings.Join(wantTop, ",") {
				t.Fatalf("top-level key order = %v, want %v", topKeys, wantTop)
			}

			var reqKeys []string
			ojson.GetBytesNoCopy(finalPayload, "request").ForEach(func(k, _ ojson.Result) bool {
				reqKeys = append(reqKeys, k.Str)
				return true
			})
			assertSubsequence(t, reqKeys, []string{"contents", "systemInstruction", "tools", "generationConfig", "sessionId"})
		})
	}
}

func TestAntigravityWireTLSHTTP11HeaderOrderChunkedAndKeepAlive(t *testing.T) {
	priv, errKey := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if errKey != nil {
		t.Fatalf("generate key: %v", errKey)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, errCert := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if errCert != nil {
		t.Fatalf("create cert: %v", errCert)
	}
	tlsCert := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}

	rawLn, errLn := net.Listen("tcp", "127.0.0.1:0")
	if errLn != nil {
		t.Fatalf("listen: %v", errLn)
	}
	defer func() { _ = rawLn.Close() }()

	type capturedWireReq struct {
		connID         int
		requestLine    string
		headerNames    []string
		headerMap      map[string]string
		decodedBody    []byte
		alpnOffered    []string
		negotiatedALPN string
	}
	var (
		mu       sync.Mutex
		captured []capturedWireReq
		wg       sync.WaitGroup
	)

	tlsLn := tls.NewListener(rawLn, &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS13,
	})
	defer func() { _ = tlsLn.Close() }()

	go func() {
		connSeq := 0
		for {
			c, errAccept := tlsLn.Accept()
			if errAccept != nil {
				return
			}
			connSeq++
			cid := connSeq
			wg.Add(1)
			go func(conn net.Conn, id int) {
				defer wg.Done()
				defer func() { _ = conn.Close() }()

				br := bufio.NewReader(conn)
				for {
					reqLine, errLine := br.ReadString('\n')
					if errLine != nil {
						return
					}
					reqLine = strings.TrimRight(reqLine, "\r\n")
					var names []string
					hMap := make(map[string]string)
					for {
						hl, errHL := br.ReadString('\n')
						if errHL != nil {
							return
						}
						hl = strings.TrimRight(hl, "\r\n")
						if hl == "" {
							break
						}
						colon := strings.IndexByte(hl, ':')
						if colon <= 0 {
							return
						}
						name := hl[:colon]
						val := strings.TrimSpace(hl[colon+1:])
						names = append(names, name)
						hMap[strings.ToLower(name)] = val
					}

					var body []byte
					if strings.Contains(strings.ToLower(hMap["transfer-encoding"]), "chunked") {
						body, _ = io.ReadAll(httputil.NewChunkedReader(br))
						for {
							tl, errTL := br.ReadString('\n')
							if errTL != nil || strings.TrimRight(tl, "\r\n") == "" {
								break
							}
						}
					} else if cl, errCL := strconv.Atoi(hMap["content-length"]); errCL == nil && cl > 0 {
						body = make([]byte, cl)
						_, _ = io.ReadFull(br, body)
					}

					var state tls.ConnectionState
					if tc, ok := conn.(*tls.Conn); ok {
						state = tc.ConnectionState()
					}

					mu.Lock()
					captured = append(captured, capturedWireReq{
						connID:         id,
						requestLine:    reqLine,
						headerNames:    names,
						headerMap:      hMap,
						decodedBody:    body,
						negotiatedALPN: state.NegotiatedProtocol,
					})
					mu.Unlock()

					if strings.Contains(reqLine, "streamGenerateContent") {
						sse := "data: {\"response\":{\"candidates\":[{\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"stream-ok\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":4,\"candidatesTokenCount\":2,\"totalTokenCount\":6}}}\n\n"
						resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: %d\r\n\r\n%s", len(sse), sse)
						_, _ = io.WriteString(conn, resp)
					} else {
						jsonResp := `{"response":{"candidates":[{"content":{"role":"model","parts":[{"text":"unary-ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":4,"candidatesTokenCount":2,"totalTokenCount":6}}}`
						resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s", len(jsonResp), jsonResp)
						_, _ = io.WriteString(conn, resp)
					}
				}
			}(c, cid)
		}
	}()

	baseTransport := http.DefaultTransport.(*http.Transport).Clone()
	baseTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	auth := &cliproxyauth.Auth{
		ID:       "wire-tls-auth",
		Provider: "antigravity",
		Attributes: map[string]string{
			"base_url": "https://" + rawLn.Addr().String(),
		},
		Metadata: map[string]any{
			"access_token": "wire-token",
			"project_id":   "proj-wire",
			"expired":      time.Now().Add(time.Hour).Format(time.RFC3339),
		},
	}
	ctx := context.WithValue(context.Background(), "cliproxy.roundtripper", baseTransport)
	defer closeAntigravityAuthIdleTransports(auth)

	exec := NewAntigravityExecutor(&config.Config{})
	reqPayload := []byte(`{"contents":[{"role":"user","parts":[{"text":"hello wire"}]}]}`)
	streamRes, errStream := exec.ExecuteStream(ctx, auth, cliproxyexecutor.Request{
		Model:   "gemini-3-flash",
		Payload: reqPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatGemini,
		Stream:       true,
	})
	if errStream != nil {
		t.Fatalf("ExecuteStream error = %v", errStream)
	}
	for ch := range streamRes.Chunks {
		if ch.Err != nil {
			t.Fatalf("ExecuteStream chunk error = %v", ch.Err)
		}
	}

	if _, errExec := exec.Execute(ctx, auth, cliproxyexecutor.Request{
		Model:   "gemini-3-flash",
		Payload: reqPayload,
	}, cliproxyexecutor.Options{
		SourceFormat: sdktranslator.FormatGemini,
	}); errExec != nil {
		t.Fatalf("Execute error = %v", errExec)
	}

	closeAntigravityAuthIdleTransports(auth)
	baseTransport.CloseIdleConnections()
	_ = tlsLn.Close()
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(captured) != 2 {
		t.Fatalf("captured %d requests, want 2", len(captured))
	}

	r1 := captured[0]
	r2 := captured[1]
	if r1.connID != r2.connID {
		t.Fatalf("expected HTTP/1.1 keep-alive reuse on single TLS connection, got connIDs %d and %d", r1.connID, r2.connID)
	}
	if r1.negotiatedALPN != "" || r2.negotiatedALPN != "" {
		t.Fatalf("expected empty ALPN negotiated protocol, got %q and %q", r1.negotiatedALPN, r2.negotiatedALPN)
	}
	if !strings.HasSuffix(r1.requestLine, "HTTP/1.1") || !strings.HasSuffix(r2.requestLine, "HTTP/1.1") {
		t.Fatalf("expected HTTP/1.1 request lines, got %q and %q", r1.requestLine, r2.requestLine)
	}

	if _, hasHarness := r1.headerMap["x-deepseek-harness-attribution"]; hasHarness {
		t.Fatal("must not emit X-DeepSeek-Harness-Attribution")
	}
	if !strings.HasPrefix(r1.headerMap["user-agent"], "antigravity/cli/1.3.5 ") {
		t.Fatalf("wire User-Agent = %q, want antigravity/cli/1.3.5", r1.headerMap["user-agent"])
	}
	if r1.headerMap["transfer-encoding"] != "chunked" {
		t.Fatalf("stream Transfer-Encoding = %q, want chunked", r1.headerMap["transfer-encoding"])
	}
	if _, hasCL := r1.headerMap["content-length"]; hasCL {
		t.Fatalf("stream request unexpectedly sent Content-Length: %v", r1.headerMap)
	}

	wantStreamOrder := []string{"Host", "User-Agent", "Transfer-Encoding", "Authorization", "Content-Type", "Accept", "Accept-Encoding"}
	if strings.Join(r1.headerNames, ",") != strings.Join(wantStreamOrder, ",") {
		t.Fatalf("stream wire header order = %v, want %v", r1.headerNames, wantStreamOrder)
	}

	wantUnaryOrder := []string{"Host", "User-Agent", "Content-Length", "Authorization", "Content-Type", "Accept", "Accept-Encoding"}
	if strings.Join(r2.headerNames, ",") != strings.Join(wantUnaryOrder, ",") {
		t.Fatalf("unary wire header order = %v, want %v", r2.headerNames, wantUnaryOrder)
	}

	if !bytes.Contains(r1.decodedBody, []byte(`"model":"gemini-3-flash"`)) || !bytes.Contains(r2.decodedBody, []byte(`"last_execution_id"`)) {
		t.Fatalf("decoded wire bodies did not chain stateful execution: r1=%s r2=%s", r1.decodedBody, r2.decodedBody)
	}
}

func assertSubsequence(t *testing.T, haystack, want []string) {
	t.Helper()
	pos := 0
	for _, item := range haystack {
		if pos < len(want) && item == want[pos] {
			pos++
		}
	}
	if pos != len(want) {
		t.Fatalf("expected subsequence %v inside %v", want, haystack)
	}
}
