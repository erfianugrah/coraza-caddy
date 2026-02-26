// Copyright 2025 The OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

package coraza

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/stretchr/testify/require"
)

// fakeHijackConn is a minimal net.Conn returned by the fake hijacker.
type fakeHijackConn struct{ net.Conn }

// fakeHijackResponseWriter implements http.ResponseWriter and http.Hijacker
// so we can test hijack tracking without a real TCP connection.
type fakeHijackResponseWriter struct {
	http.ResponseWriter
	hijacked bool
}

func (f *fakeHijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	f.hijacked = true
	server, _ := net.Pipe()
	rw := bufio.NewReadWriter(bufio.NewReader(server), bufio.NewWriter(server))
	return server, rw, nil
}

// newTestWAF creates a minimal WAF in DetectionOnly mode for testing.
func newTestWAF(t *testing.T) coraza.WAF {
	t.Helper()
	cfg := coraza.NewWAFConfig().WithDirectives(`SecRuleEngine DetectionOnly`)
	waf, err := coraza.NewWAF(cfg)
	require.NoError(t, err)
	return waf
}

func TestHijackTrackerSetsFlag(t *testing.T) {
	i := &rwInterceptor{}
	underlying := &fakeHijackResponseWriter{ResponseWriter: httptest.NewRecorder()}
	tracker := &hijackTracker{Hijacker: underlying, interceptor: i}

	require.False(t, i.hijacked)

	conn, _, err := tracker.Hijack()
	require.NoError(t, err)
	require.True(t, i.hijacked)
	conn.Close()
}

func TestWriteHeaderNoOpAfterHijack(t *testing.T) {
	rec := httptest.NewRecorder()
	waf := newTestWAF(t)
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}
	i.hijacked = true

	// Should not panic or write anything
	i.WriteHeader(http.StatusOK)

	// The underlying recorder should not have received a WriteHeader call
	// (default status is 200, and Code is only set on explicit WriteHeader)
	require.Equal(t, 200, rec.Code)
	require.False(t, i.wroteHeader)
}

func TestWriteNoOpAfterHijack(t *testing.T) {
	rec := httptest.NewRecorder()
	waf := newTestWAF(t)
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	i := &rwInterceptor{w: rec, tx: tx, proto: "HTTP/1.1", statusCode: 200}
	i.hijacked = true

	n, err := i.Write([]byte("hello"))
	require.NoError(t, err)
	require.Equal(t, 5, n)
	require.Empty(t, rec.Body.String())
}

func TestFlushWriteHeaderNoOpAfterHijack(t *testing.T) {
	rec := httptest.NewRecorder()

	i := &rwInterceptor{w: rec, statusCode: 500}
	i.hijacked = true

	i.flushWriteHeader()
	// isWriteHeaderFlush should remain false — nothing was flushed
	require.False(t, i.isWriteHeaderFlush)
}

func TestResponseProcessorSkipsAfterHijack(t *testing.T) {
	underlying := &fakeHijackResponseWriter{ResponseWriter: httptest.NewRecorder()}
	waf := newTestWAF(t)
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	req := httptest.NewRequest("GET", "/ws", nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")

	ww, processResponse := wrap(underlying, req, tx)

	// The wrapped writer should implement http.Hijacker
	hijacker, ok := ww.(http.Hijacker)
	require.True(t, ok, "wrapped writer should implement http.Hijacker")

	// Simulate the WebSocket upgrade: hijack the connection
	conn, _, err := hijacker.Hijack()
	require.NoError(t, err)
	defer conn.Close()

	// processResponse should return nil without panicking
	err = processResponse(tx, req)
	require.NoError(t, err)
}

func TestWrapPreservesHijackerInterface(t *testing.T) {
	underlying := &fakeHijackResponseWriter{ResponseWriter: httptest.NewRecorder()}
	waf := newTestWAF(t)
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	req := httptest.NewRequest("GET", "/", nil)
	ww, _ := wrap(underlying, req, tx)

	_, ok := ww.(http.Hijacker)
	require.True(t, ok, "wrap() must preserve http.Hijacker on the returned writer")
}

func TestWrapWithoutHijacker(t *testing.T) {
	// Plain httptest.Recorder does not implement http.Hijacker
	rec := httptest.NewRecorder()
	waf := newTestWAF(t)
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	req := httptest.NewRequest("GET", "/", nil)
	ww, processResponse := wrap(rec, req, tx)

	_, ok := ww.(http.Hijacker)
	require.False(t, ok, "wrap() should not add http.Hijacker when underlying writer lacks it")

	// Normal response processing should still work
	ww.WriteHeader(http.StatusOK)
	err := processResponse(tx, req)
	require.NoError(t, err)
}

func TestNormalRequestUnaffected(t *testing.T) {
	// Ensure a normal (non-WebSocket) request through a hijack-capable writer
	// still works correctly — the hijacked flag stays false.
	underlying := &fakeHijackResponseWriter{ResponseWriter: httptest.NewRecorder()}
	waf := newTestWAF(t)
	tx := waf.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	req := httptest.NewRequest("GET", "/normal", nil)
	ww, processResponse := wrap(underlying, req, tx)

	// Simulate a normal response (no hijack)
	ww.WriteHeader(http.StatusOK)
	_, err := ww.Write([]byte("hello"))
	require.NoError(t, err)

	err = processResponse(tx, req)
	require.NoError(t, err)

	// The underlying hijacker should NOT have been called
	require.False(t, underlying.hijacked)
}
