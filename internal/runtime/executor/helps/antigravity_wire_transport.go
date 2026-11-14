package helps

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ChunkedBytesReader wraps an io.Reader without exposing Len(), io.Seeker, or *bytes.Reader,
// forcing net/http to emit Transfer-Encoding: chunked when ContentLength is -1.
type ChunkedBytesReader struct {
	R io.Reader
}

func (c ChunkedBytesReader) Read(p []byte) (int, error) {
	return c.R.Read(p)
}

// ApplyChunkedStreamBody configures an outbound streaming HTTP/1.1 request to send
// its JSON payload using Transfer-Encoding: chunked without a Content-Length header.
func ApplyChunkedStreamBody(httpReq *http.Request, payload []byte) {
	if httpReq == nil {
		return
	}
	snapshot := append([]byte(nil), payload...)
	httpReq.ContentLength = -1
	httpReq.Body = io.NopCloser(ChunkedBytesReader{R: bytes.NewReader(snapshot)})
	httpReq.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(ChunkedBytesReader{R: bytes.NewReader(snapshot)}), nil
	}
}

// WrapTransportWithAgyWireOrder installs a net.Conn wrapper on tr in place so outgoing HTTP/1.1
// requests emit headers in Cloud Code Antigravity CLI order across keep-alive connections.
func WrapTransportWithAgyWireOrder(tr *http.Transport) {
	if tr == nil {
		return
	}
	origDialContext := tr.DialContext
	if origDialContext == nil {
		dialer := &net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
		}
		origDialContext = dialer.DialContext
	}
	origDialTLSContext := tr.DialTLSContext
	tlsCfgTemplate := tr.TLSClientConfig
	tlsTimeout := tr.TLSHandshakeTimeout

	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		conn, err := origDialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		return newAgyWireOrderConn(conn), nil
	}

	if origDialTLSContext != nil {
		tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := origDialTLSContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return newAgyWireOrderConn(conn), nil
		}
		return
	}

	tr.DialTLSContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		rawConn, err := origDialContext(ctx, network, addr)
		if err != nil {
			return nil, err
		}
		var tlsCfg *tls.Config
		if tlsCfgTemplate != nil {
			tlsCfg = tlsCfgTemplate.Clone()
		} else {
			tlsCfg = &tls.Config{}
		}
		if tlsCfg.ServerName == "" {
			host, _, splitErr := net.SplitHostPort(addr)
			if splitErr != nil {
				host = addr
			}
			tlsCfg.ServerName = host
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		handshakeCtx := ctx
		if tlsTimeout > 0 {
			var cancel context.CancelFunc
			handshakeCtx, cancel = context.WithTimeout(ctx, tlsTimeout)
			defer cancel()
		}
		if errHandshake := tlsConn.HandshakeContext(handshakeCtx); errHandshake != nil {
			_ = rawConn.Close()
			return nil, errHandshake
		}
		return newAgyWireOrderConn(tlsConn), nil
	}
}

type agyWireState uint8

const (
	wireStateHead agyWireState = iota
	wireStateFixedBody
	wireStateChunkSize
	wireStateChunkData
	wireStateChunkTrailers
	wireStatePassthrough
)

const agyMaxHeadBufferBytes = 256 * 1024

type agyWireOrderConn struct {
	net.Conn
	writeMu        sync.Mutex
	state          agyWireState
	headBuf        []byte
	lineBuf        []byte
	bodyRemaining  int64
	chunkRemaining int64
}

func newAgyWireOrderConn(conn net.Conn) *agyWireOrderConn {
	return &agyWireOrderConn{
		Conn:  conn,
		state: wireStateHead,
	}
}

// ConnectionState forwards TLS connection metadata when wrapping a *tls.Conn.
func (c *agyWireOrderConn) ConnectionState() tls.ConnectionState {
	if tlsConn, ok := c.Conn.(interface{ ConnectionState() tls.ConnectionState }); ok {
		return tlsConn.ConnectionState()
	}
	return tls.ConnectionState{}
}

func (c *agyWireOrderConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	if c.state == wireStatePassthrough {
		return c.Conn.Write(p)
	}

	remaining := p
	for len(remaining) > 0 {
		switch c.state {
		case wireStatePassthrough:
			if err := writeAll(c.Conn, remaining); err != nil {
				return len(p) - len(remaining), err
			}
			return len(p), nil

		case wireStateHead:
			c.headBuf = append(c.headBuf, remaining...)
			remaining = nil

			// Detect non-HTTP binary streams (for example, TLS ciphertext over an HTTP proxy tunnel).
			if !looksLikeHTTPRequestPrefix(c.headBuf) {
				buf := c.headBuf
				c.headBuf = nil
				c.state = wireStatePassthrough
				if err := writeAll(c.Conn, buf); err != nil {
					return 0, err
				}
				return len(p), nil
			}

			idx := bytes.Index(c.headBuf, []byte("\r\n\r\n"))
			if idx < 0 {
				if len(c.headBuf) > agyMaxHeadBufferBytes {
					buf := c.headBuf
					c.headBuf = nil
					c.state = wireStatePassthrough
					if err := writeAll(c.Conn, buf); err != nil {
						return 0, err
					}
				}
				continue
			}

			headBytes := c.headBuf[:idx]
			tail := append([]byte(nil), c.headBuf[idx+4:]...)
			c.headBuf = nil

			orderedHead, nextState, contentLen := reorderHTTP11Head(headBytes)
			if err := writeAll(c.Conn, orderedHead); err != nil {
				return 0, err
			}
			c.state = nextState
			c.bodyRemaining = contentLen
			c.lineBuf = c.lineBuf[:0]
			remaining = tail

		case wireStateFixedBody:
			n := int64(len(remaining))
			if n > c.bodyRemaining {
				n = c.bodyRemaining
			}
			if n > 0 {
				if err := writeAll(c.Conn, remaining[:n]); err != nil {
					return 0, err
				}
				c.bodyRemaining -= n
				remaining = remaining[n:]
			}
			if c.bodyRemaining <= 0 {
				c.state = wireStateHead
			}

		case wireStateChunkSize:
			c.lineBuf = append(c.lineBuf, remaining...)
			remaining = nil
			idx := bytes.Index(c.lineBuf, []byte("\r\n"))
			if idx < 0 {
				if len(c.lineBuf) > 1024 {
					buf := c.lineBuf
					c.lineBuf = nil
					c.state = wireStatePassthrough
					if err := writeAll(c.Conn, buf); err != nil {
						return 0, err
					}
				}
				continue
			}
			lineBytes := c.lineBuf[:idx+2]
			tail := append([]byte(nil), c.lineBuf[idx+2:]...)
			c.lineBuf = c.lineBuf[:0]
			if err := writeAll(c.Conn, lineBytes); err != nil {
				return 0, err
			}
			sizeToken := string(bytes.TrimSuffix(lineBytes, []byte("\r\n")))
			if semi := strings.IndexByte(sizeToken, ';'); semi >= 0 {
				sizeToken = sizeToken[:semi]
			}
			sizeToken = strings.TrimSpace(sizeToken)
			chunkLen, errParse := strconv.ParseUint(sizeToken, 16, 64)
			if errParse != nil {
				c.state = wireStatePassthrough
				remaining = tail
				continue
			}
			if chunkLen == 0 {
				c.state = wireStateChunkTrailers
			} else {
				c.chunkRemaining = int64(chunkLen) + 2
				c.state = wireStateChunkData
			}
			remaining = tail

		case wireStateChunkData:
			n := int64(len(remaining))
			if n > c.chunkRemaining {
				n = c.chunkRemaining
			}
			if n > 0 {
				if err := writeAll(c.Conn, remaining[:n]); err != nil {
					return 0, err
				}
				c.chunkRemaining -= n
				remaining = remaining[n:]
			}
			if c.chunkRemaining <= 0 {
				c.state = wireStateChunkSize
			}

		case wireStateChunkTrailers:
			c.lineBuf = append(c.lineBuf, remaining...)
			remaining = nil
			for {
				idx := bytes.Index(c.lineBuf, []byte("\r\n"))
				if idx < 0 {
					break
				}
				lineBytes := c.lineBuf[:idx+2]
				if err := writeAll(c.Conn, lineBytes); err != nil {
					return 0, err
				}
				rest := append([]byte(nil), c.lineBuf[idx+2:]...)
				c.lineBuf = c.lineBuf[:0]
				if idx == 0 {
					c.state = wireStateHead
					remaining = rest
					break
				}
				c.lineBuf = rest
			}
		}
	}

	return len(p), nil
}

func looksLikeHTTPRequestPrefix(buf []byte) bool {
	if len(buf) == 0 {
		return true
	}
	b0 := buf[0]
	if b0 < 'A' || b0 > 'Z' {
		return false
	}
	limit := len(buf)
	if limit > 32 {
		limit = 32
	}
	for i := 0; i < limit; i++ {
		ch := buf[i]
		if ch == ' ' {
			return i >= 3
		}
		if ch < 'A' || ch > 'Z' {
			return false
		}
	}
	return len(buf) < 16
}

func reorderHTTP11Head(head []byte) ([]byte, agyWireState, int64) {
	rawStr := string(head)
	lines := strings.Split(rawStr, "\r\n")
	if len(lines) == 0 {
		out := make([]byte, len(head)+4)
		copy(out, head)
		copy(out[len(head):], "\r\n\r\n")
		return out, wireStateHead, 0
	}

	requestLine := lines[0]
	if strings.HasPrefix(requestLine, "CONNECT ") {
		out := make([]byte, len(head)+4)
		copy(out, head)
		copy(out[len(head):], "\r\n\r\n")
		return out, wireStatePassthrough, 0
	}

	var (
		isChunked     bool
		contentLength int64
	)

	buckets := make(map[string][]string, len(lines))
	otherLines := make([]string, 0, len(lines))

	for _, line := range lines[1:] {
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			otherLines = append(otherLines, line)
			continue
		}
		lowerKey := strings.ToLower(strings.TrimSpace(line[:colon]))
		val := strings.TrimSpace(line[colon+1:])

		switch lowerKey {
		case "transfer-encoding":
			if strings.Contains(strings.ToLower(val), "chunked") {
				isChunked = true
			}
			buckets[lowerKey] = append(buckets[lowerKey], line)
		case "content-length":
			if parsed, errParse := strconv.ParseInt(val, 10, 64); errParse == nil && parsed > 0 {
				contentLength = parsed
			}
			buckets[lowerKey] = append(buckets[lowerKey], line)
		case "host", "user-agent", "authorization", "content-type", "accept", "accept-encoding":
			buckets[lowerKey] = append(buckets[lowerKey], line)
		default:
			otherLines = append(otherLines, line)
		}
	}

	orderedKeysPrefix := []string{
		"host",
		"user-agent",
		"transfer-encoding",
		"content-length",
		"authorization",
		"content-type",
		"accept",
	}

	var b strings.Builder
	b.Grow(len(head) + 4)
	b.WriteString(requestLine)
	b.WriteString("\r\n")

	for _, k := range orderedKeysPrefix {
		for _, line := range buckets[k] {
			b.WriteString(line)
			b.WriteString("\r\n")
		}
	}
	for _, line := range otherLines {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	for _, line := range buckets["accept-encoding"] {
		b.WriteString(line)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")

	nextState := wireStateHead
	if isChunked {
		nextState = wireStateChunkSize
		contentLength = 0
	} else if contentLength > 0 {
		nextState = wireStateFixedBody
	}
	return []byte(b.String()), nextState, contentLength
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}
