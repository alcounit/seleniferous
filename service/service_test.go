package service

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alcounit/seleniferous/v2/pkg/session"
	"github.com/alcounit/seleniferous/v2/pkg/store"
	"github.com/alcounit/selenosis/v2/pkg/proxy"
	"github.com/alcounit/selenosis/v2/pkg/proxy/rule"
	"github.com/alcounit/selenosis/v2/pkg/selenium"
	"github.com/go-chi/chi/v5"
)

func TestCreateSessionStoreNotEmpty(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("x", "y")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", nil, nil, "")
	rw := httptestRecorder()

	svc.CreateSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestCreateSessionNilBody(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", nil, map[string]string{}, "")
	req.Body = nil
	rw := httptestRecorder()

	svc.CreateSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestCreateSessionWaitFails(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 20 * time.Millisecond}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return nil, errors.New("down")
		}
		return response(http.StatusOK, ""), nil
	})

	withDefaultClientTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)

		if rw.status != http.StatusServiceUnavailable {
			t.Fatalf("expected status 503, got %d", rw.status)
		}
	})
}

func TestCreateSessionSuccess(t *testing.T) {
	st := store.NewDefaultStore()
	rec := &fakeBroadcaster{}
	cfg := ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 100 * time.Millisecond,
	}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), rec)

	payload := selenium.Payload{
		"value": map[string]any{
			"sessionId": "orig",
			"capabilities": map[string]any{
				"webSocketUrl": "ws://oldhost/session/orig",
				"se:cdp":       "ws://oldhost/devtools/orig",
			},
		},
	}
	body, _ := json.Marshal(payload)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusOK, string(body)), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		req.Header.Set("X-Selenosis-External-URL", "http://external.test")
		rw := httptestRecorder()

		svc.CreateSession(rw, req)

		if rw.status != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rw.status)
		}

		var got selenium.Payload
		if err := json.Unmarshal(rw.body.Bytes(), &got); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}

		if sessionId, _ := got.GetSessionId(); sessionId != "fake" {
			t.Fatalf("expected sessionId fake, got %s", sessionId)
		}

		caps := got["value"].(map[string]any)["capabilities"].(map[string]any)
		if !strings.Contains(caps["webSocketUrl"].(string), "external.test") {
			t.Fatalf("expected webSocketUrl to use external host, got %s", caps["webSocketUrl"])
		}
		if !strings.Contains(caps["se:cdp"].(string), "external.test") {
			t.Fatalf("expected se:cdp to use external host, got %s", caps["se:cdp"])
		}

		if val, ok := st.Get("fake"); !ok || val != "orig" {
			t.Fatalf("expected store mapping fake->orig, got %v (ok=%v)", val, ok)
		}
	})
}

func TestCreateSessionUsesRetryConfig(t *testing.T) {
	st := store.NewDefaultStore()
	cfg := ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 100 * time.Millisecond,
		SessionRetryCount:    2,
		SessionRetryDelay:    0,
	}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	payload := selenium.Payload{
		"value": map[string]any{
			"sessionId": "orig",
		},
	}
	body, _ := json.Marshal(payload)

	var postCalls int
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		postCalls++
		if postCalls < 3 {
			return nil, errors.New("fail")
		}
		return response(http.StatusOK, string(body)), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()

		svc.CreateSession(rw, req)

		if rw.status != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rw.status)
		}
		if postCalls != 3 {
			t.Fatalf("expected 3 POST attempts, got %d", postCalls)
		}
	})
}

func TestCreateSessionZeroRetries(t *testing.T) {
	st := store.NewDefaultStore()
	cfg := ServiceConfig{
		BrowserPort:          "4444",
		SessionCreateTimeout: 100 * time.Millisecond,
		SessionRetryCount:    0,
		SessionRetryDelay:    0,
	}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var postCalls int
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		postCalls++
		if postCalls == 1 {
			return nil, errors.New("fail")
		}
		return response(http.StatusOK, `{}`), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()

		svc.CreateSession(rw, req)

		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if postCalls != 1 {
			t.Fatalf("expected 1 POST attempt, got %d", postCalls)
		}
	})
}

func TestCreateSessionResponseBodyNil(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return &http.Response{StatusCode: http.StatusOK, Body: nil, Header: make(http.Header)}, nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
	})
}

func TestCreateSessionReadError(t *testing.T) {
	st := store.NewDefaultStore()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), rec)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(errorReader{}),
			Header:     make(http.Header),
		}, nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)

		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionInvalidJSON(t *testing.T) {
	st := store.NewDefaultStore()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), rec)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusOK, "{"), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)

		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionMissingSessionId(t *testing.T) {
	st := store.NewDefaultStore()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), rec)

	body, _ := json.Marshal(map[string]any{"value": map[string]any{"foo": "bar"}})
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusOK, string(body)), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionUpdateSessionIdFails(t *testing.T) {
	st := store.NewDefaultStore()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), rec)

	body, _ := json.Marshal(map[string]any{"sessionId": "orig"})
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusOK, string(body)), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionNonOKStatus(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusBadRequest, "{}"), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.CreateSession(rw, req)
		if rw.status != http.StatusBadRequest {
			t.Fatalf("expected status 400, got %d", rw.status)
		}
	})
}

func TestProxySessionUnknownSession(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()

	svc.ProxySession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestRouteHTTPMissingSessionId(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/", nil, map[string]string{}, "/foo")
	rw := httptestRecorder()

	svc.RouteHTTP(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteHTTPUnknownSession(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake/foo", nil, map[string]string{"sessionId": "fake"}, "/foo")
	rw := httptestRecorder()

	svc.RouteHTTP(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteHTTPMissingRestPath(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake", nil, map[string]string{"sessionId": "fake"}, "/")
	rw := httptestRecorder()

	svc.RouteHTTP(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteHTTPNoMatchingRule(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake/foo", nil, map[string]string{"sessionId": "fake"}, "/foo")
	rw := httptestRecorder()

	svc.RouteHTTP(rw, req)

	if rw.status != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", rw.status)
	}
}

func TestRouteHTTPRuleApplied(t *testing.T) {
	rulesJSON := `[{"pathRegex":"/session/(?P<sessionId>[^/]+)/foo/(?P<rest>.*)","target":"example.com","rewritePath":"/proxy/{rest}"}]`
	t.Setenv("RULES", rulesJSON)
	rules, err := rule.LoadRulesFromEnv("RULES")
	if err != nil {
		t.Fatalf("failed to load rules: %v", err)
	}

	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	cfg := ServiceConfig{Rules: rules}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotReq *http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotReq = req
		return response(http.StatusOK, "ok"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodGet, "/session/fake/foo/bar/baz", nil, map[string]string{"sessionId": "fake"}, "/foo/bar/baz")
		rw := httptestRecorder()

		svc.RouteHTTP(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.URL.Host != "example.com" {
			t.Fatalf("expected target host, got %s", gotReq.URL.Host)
		}
		if gotReq.URL.Path != "/proxy/bar/baz" {
			t.Fatalf("unexpected rewritten path: %s", gotReq.URL.Path)
		}
	})
}

func TestRouteVNCMissingSessionId(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/vnc", nil, map[string]string{}, "")
	rw := httptestRecorder()

	svc.RouteVNC(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteVNCUnknownSession(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/vnc/fake", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()

	svc.RouteVNC(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteVNCUpgradeFails(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/vnc/fake", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()

	svc.RouteVNC(rw, req)
}

func TestRouteVNCDialError(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })

	req := newRequestWithParams(http.MethodGet, "/vnc/fake", nil, map[string]string{"sessionId": "fake"}, "")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	rw := &hijackResponseWriter{conn: serverConn, header: make(http.Header)}

	withDialTCP(t, func(network, addr string) (net.Conn, error) {
		return nil, errors.New("dial failed")
	}, func() {
		go func() {
			_, _ = io.Copy(io.Discard, clientConn)
		}()
		svc.RouteVNC(rw, req)
	})
}

func TestRouteVNCProxy(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })

	upgraderReq := newRequestWithParams(http.MethodGet, "/vnc/fake", nil, map[string]string{"sessionId": "fake"}, "")
	upgraderReq.Header.Set("Connection", "Upgrade")
	upgraderReq.Header.Set("Upgrade", "websocket")
	upgraderReq.Header.Set("Sec-WebSocket-Version", "13")
	upgraderReq.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	rw := &hijackResponseWriter{conn: serverConn, header: make(http.Header)}

	dialClient, dialServer := net.Pipe()
	t.Cleanup(func() { _ = dialClient.Close() })
	t.Cleanup(func() { _ = dialServer.Close() })

	withDialTCP(t, func(network, addr string) (net.Conn, error) {
		return dialServer, nil
	}, func() {
		go func() {
			_, _ = io.Copy(io.Discard, clientConn)
		}()

		done := make(chan struct{})
		go func() {
			svc.RouteVNC(rw, upgraderReq)
			close(done)
		}()

		payload := []byte("ping")
		if err := writeMaskedFrame(clientConn, 0x2, payload); err != nil {
			t.Fatalf("failed to write frame: %v", err)
		}

		buf := make([]byte, len(payload))
		if _, err := io.ReadFull(dialClient, buf); err != nil {
			t.Fatalf("read from dial conn: %v", err)
		}
		if string(buf) != "ping" {
			t.Fatalf("unexpected tcp payload: %s", string(buf))
		}

		if _, err := dialClient.Write([]byte("pong")); err != nil {
			t.Fatalf("write to dial conn: %v", err)
		}

		time.Sleep(20 * time.Millisecond)
		_ = clientConn.Close()
		_ = dialClient.Close()

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for RouteVNC to exit")
		}
	})
}

func TestStoreSessionIdAndGetSessionId(t *testing.T) {
	st := store.NewDefaultStore()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	svc.storeSessionId("orig")

	if got, ok := svc.getSessionId("fake"); !ok || got != "orig" {
		t.Fatalf("expected orig session, got %q (ok=%v)", got, ok)
	}

	st.Set("bad", 123)
	if _, ok := svc.getSessionId("bad"); ok {
		t.Fatal("expected false for non-string value")
	}
}

func TestWriteErrorResponse(t *testing.T) {
	rw := httptestRecorder()
	writeErrorResponse(rw, http.StatusBadRequest, errors.New("bad"))

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
	if got := rw.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", got)
	}
	if rw.body.Len() == 0 {
		t.Fatal("expected non-empty response body")
	}
}

func TestNotifyErrorAndDelete(t *testing.T) {
	rec := &fakeBroadcaster{}
	notifyError(rec, "src", errors.New("boom"))
	notifyDelete(rec, "src")

	if len(rec.events) != 2 {
		t.Fatalf("expected 2 events, got %d", len(rec.events))
	}
	if rec.events[0].Type != EventTypeError {
		t.Fatalf("expected error event, got %s", rec.events[0].Type)
	}
	if rec.events[1].Type != EventTypeDeleted {
		t.Fatalf("expected deleted event, got %s", rec.events[1].Type)
	}
}

func TestWSHandlersTouch(t *testing.T) {
	mgr := session.NewManager(time.Second, nil)
	svc := NewService(ServiceConfig{}, store.NewDefaultStore(), mgr, &fakeBroadcaster{})

	svc.wsOnConnect("s1")()
	svc.wsOnMessage("s1")()
	svc.wsOnClose("s1")()
}

func TestProxySessionHTTP(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotReq *http.Request
	var gotBody []byte

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotReq = req
		gotBody, _ = io.ReadAll(req.Body)
		respPayload := map[string]any{"value": map[string]any{"sessionId": "orig"}}
		respBody, _ := json.Marshal(respPayload)
		return response(http.StatusOK, string(respBody)), nil
	})

	withProxyTransport(t, rt, func() {
		reqBody := `{"value":{"sessionId":"fake"}}`
		req := newRequestWithParams(http.MethodPost, "/session/fake/url", bytes.NewBufferString(reqBody), map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()

		svc.ProxySession(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.URL.Host != "localhost:4444" {
			t.Fatalf("unexpected host: %s", gotReq.URL.Host)
		}
		if !strings.Contains(gotReq.URL.Path, "orig") {
			t.Fatalf("expected path to contain orig, got %s", gotReq.URL.Path)
		}
		if !bytes.Contains(gotBody, []byte(`"orig"`)) {
			t.Fatalf("expected request body to include orig, got %s", string(gotBody))
		}

		var resp selenium.Payload
		if err := json.Unmarshal(rw.body.Bytes(), &resp); err != nil {
			t.Fatalf("failed to parse response: %v", err)
		}
		if sid, _ := resp.GetSessionId(); sid != "fake" {
			t.Fatalf("expected response sessionId fake, got %s", sid)
		}
	})
}

func TestProxySessionBodyUnmarshalFails(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotBody []byte
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotBody, _ = io.ReadAll(req.Body)
		return response(http.StatusOK, `{}`), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session/fake/url", bytes.NewBufferString("{"), map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.ProxySession(rw, req)
		if string(gotBody) != "{" {
			t.Fatalf("expected original body to pass through, got %s", string(gotBody))
		}
	})
}

func TestProxySessionNoBody(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{}`), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodGet, "/session/fake/url", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.ProxySession(rw, req)
	})
}

func TestProxySessionResponseBodyNil(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: nil, Header: make(http.Header)}, nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodGet, "/session/fake/url", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.ProxySession(rw, req)
	})
}

func TestProxySessionRequestUpdateFails(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotBody []byte
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotBody, _ = io.ReadAll(req.Body)
		return response(http.StatusOK, `{"value":{"sessionId":"orig"}}`), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session/fake/url", bytes.NewBufferString(`{"sessionId":"fake"}`), map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.ProxySession(rw, req)
		if !bytes.Contains(gotBody, []byte(`"fake"`)) {
			t.Fatalf("expected original sessionId to remain, got %s", string(gotBody))
		}
	})
}

func TestProxySessionDeleteBranch(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{}`), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodDelete, "/session/fake", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.ProxySession(rw, req)
	})
}

func TestProxySessionResponseInvalidJSON(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, "{"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session/fake/url", bytes.NewBufferString(`{}`), map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.ProxySession(rw, req)
		if rw.status != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rw.status)
		}
	})
}

func TestProxySessionWebSocketPath(t *testing.T) {
	st := store.NewDefaultStore()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotURL *url.URL
	withWSProxy(t, func(resolver proxy.TargetResolver, opts ...proxy.WSProxyOption) wsProxy {
		return wsProxyFunc(func(rw http.ResponseWriter, req *http.Request) {
			u, err := resolver(req)
			if err == nil {
				gotURL = u
			}
		})
	}, func() {
		req := newRequestWithParams(http.MethodGet, "/session/fake/ws", nil, map[string]string{"sessionId": "fake"}, "")
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		rw := httptestRecorder()

		svc.ProxySession(rw, req)

		if gotURL == nil {
			t.Fatal("expected resolver to be called")
		}
		if gotURL.Scheme != "ws" || !strings.Contains(gotURL.Path, "orig") {
			t.Fatalf("unexpected resolved url: %s", gotURL.String())
		}
	})
}

func TestExternalBaseURLFromHeaders(t *testing.T) {
	h := http.Header{}
	if _, ok := externalBaseURLFromHeaders(h); ok {
		t.Fatal("expected false for missing header")
	}

	h.Set("X-Selenosis-External-URL", "http://example.com")
	u, ok := externalBaseURLFromHeaders(h)
	if !ok || u.Host != "example.com" {
		t.Fatalf("unexpected url: %v (ok=%v)", u, ok)
	}

	h.Set("X-Selenosis-External-URL", "://bad")
	if _, ok := externalBaseURLFromHeaders(h); ok {
		t.Fatal("expected false for invalid url")
	}
}

func TestRetryTransportSuccessAfterRetry(t *testing.T) {
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}), func() {
		var calls int
		base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls < 2 {
				return nil, errors.New("boom")
			}
			body, _ := io.ReadAll(req.Body)
			if string(body) != "payload" {
				t.Fatalf("unexpected body: %s", string(body))
			}
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader("ok")),
				Header:     make(http.Header),
			}, nil
		})

		rt := &retryTransport{Base: base, MaxRetries: 2, Delay: 0}
		req := newRequestWithParams(http.MethodPost, "http://example.com", bytes.NewBufferString("payload"), nil, "")

		resp, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("unexpected status: %d", resp.StatusCode)
		}
	})
}

func TestRetryTransportAllFail(t *testing.T) {
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}), func() {
		rt := &retryTransport{Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			return nil, errors.New("fail")
		}), MaxRetries: 1, Delay: 0}

		req := newRequestWithParams(http.MethodGet, "http://example.com", nil, nil, "")
		_, err := rt.RoundTrip(req)
		if err == nil || !strings.Contains(err.Error(), "all retries failed") {
			t.Fatalf("expected retries error, got %v", err)
		}
	})
}

func TestRetryTransportBodyReadError(t *testing.T) {
	rt := &retryTransport{Base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, "{}"), nil
	}), MaxRetries: 0, Delay: 0}

	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, ""), nil
	}), func() {
		req := newRequestWithParams(http.MethodPost, "http://example.com", io.NopCloser(errorReader{}), nil, "")
		_, err := rt.RoundTrip(req)
		if err == nil {
			t.Fatal("expected body read error")
		}
	})
}

func TestWaitSuccessAndTimeout(t *testing.T) {
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}), func() {
		if err := wait("http://example.com", 60*time.Millisecond); err != nil {
			t.Fatalf("unexpected wait error: %v", err)
		}
	})

	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("down")
	}), func() {
		if err := wait("http://example.com", 60*time.Millisecond); err == nil {
			t.Fatal("expected wait error")
		}
	})
}

type fakeBroadcaster struct {
	events []Event
}

func (f *fakeBroadcaster) Subscribe() chan Event {
	return nil
}

func (f *fakeBroadcaster) Unsubscribe(ch chan Event) {}

func (f *fakeBroadcaster) Broadcast(event Event) {
	f.events = append(f.events, event)
}

var defaultClientMu sync.Mutex

func withDefaultClientTransport(t *testing.T, rt http.RoundTripper, fn func()) {
	t.Helper()
	defaultClientMu.Lock()
	prev := http.DefaultClient.Transport
	http.DefaultClient.Transport = rt
	defer func() {
		http.DefaultClient.Transport = prev
		defaultClientMu.Unlock()
	}()
	fn()
}

func withDefaultTransports(t *testing.T, rt http.RoundTripper, fn func()) {
	t.Helper()
	defaultClientMu.Lock()
	prevClient := http.DefaultClient.Transport
	prevDefault := http.DefaultTransport
	http.DefaultClient.Transport = rt
	http.DefaultTransport = rt
	defer func() {
		http.DefaultClient.Transport = prevClient
		http.DefaultTransport = prevDefault
		defaultClientMu.Unlock()
	}()
	fn()
}

func withProxyTransport(t *testing.T, rt http.RoundTripper, fn func()) {
	t.Helper()
	defaultClientMu.Lock()
	prev := proxyTransport
	proxyTransport = rt
	defer func() {
		proxyTransport = prev
		defaultClientMu.Unlock()
	}()
	fn()
}

func withWSProxy(t *testing.T, fn func(resolver proxy.TargetResolver, opts ...proxy.WSProxyOption) wsProxy, run func()) {
	t.Helper()
	defaultClientMu.Lock()
	prev := newWSProxy
	newWSProxy = fn
	defer func() {
		newWSProxy = prev
		defaultClientMu.Unlock()
	}()
	run()
}

func withDialTCP(t *testing.T, fn func(network, addr string) (net.Conn, error), run func()) {
	t.Helper()
	defaultClientMu.Lock()
	prev := dialTCP
	dialTCP = fn
	defer func() {
		dialTCP = prev
		defaultClientMu.Unlock()
	}()
	run()
}

func withDefaultTransport(t *testing.T, rt http.RoundTripper, fn func()) {
	t.Helper()
	defaultClientMu.Lock()
	prev := http.DefaultTransport
	http.DefaultTransport = rt
	defer func() {
		http.DefaultTransport = prev
		defaultClientMu.Unlock()
	}()
	fn()
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type wsProxyFunc func(http.ResponseWriter, *http.Request)

func (f wsProxyFunc) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	f(rw, req)
}

type recorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func httptestRecorder() *recorder {
	return &recorder{header: make(http.Header)}
}

func (r *recorder) Header() http.Header {
	return r.header
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	return r.body.Write(p)
}

func (r *recorder) WriteHeader(statusCode int) {
	r.status = statusCode
}

func newRequestWithParams(method, path string, body io.Reader, params map[string]string, routePath string) *http.Request {
	req := httptest.NewRequest(method, path, body)
	rctx := chi.NewRouteContext()
	for key, val := range params {
		rctx.URLParams.Add(key, val)
	}
	rctx.RoutePath = routePath
	ctx := context.WithValue(req.Context(), chi.RouteCtxKey, rctx)
	return req.WithContext(ctx)
}

type errorReader struct{}

func (errorReader) Read(p []byte) (int, error) {
	return 0, errors.New("read failed")
}

func (errorReader) Close() error {
	return nil
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Body:       io.NopCloser(strings.NewReader(body)),
		Header:     make(http.Header),
	}
}

func writeMaskedFrame(w io.Writer, opcode byte, payload []byte) error {
	if len(payload) > 125 {
		return errors.New("payload too large")
	}

	header := []byte{0x80 | opcode, 0x80 | byte(len(payload))}
	mask := []byte{0x11, 0x22, 0x33, 0x44}
	masked := make([]byte, len(payload))
	for i := range payload {
		masked[i] = payload[i] ^ mask[i%4]
	}

	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(mask); err != nil {
		return err
	}
	_, err := w.Write(masked)
	return err
}

type hijackResponseWriter struct {
	conn   net.Conn
	header http.Header
}

func (h *hijackResponseWriter) Header() http.Header {
	return h.header
}

func (h *hijackResponseWriter) Write(p []byte) (int, error) {
	return h.conn.Write(p)
}

func (h *hijackResponseWriter) WriteHeader(statusCode int) {}

func (h *hijackResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return h.conn, bufio.NewReadWriter(bufio.NewReader(h.conn), bufio.NewWriter(h.conn)), nil
}

func TestExternalBaseURLFromHeadersBadHost(t *testing.T) {
	h := http.Header{}
	h.Set("X-Selenosis-External-URL", "http://")
	if _, ok := externalBaseURLFromHeaders(h); ok {
		t.Fatal("expected false for empty host")
	}
}

func TestRetryTransportUsesDefaultBase(t *testing.T) {
	withDefaultTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader("ok")),
			Header:     make(http.Header),
		}, nil
	}), func() {
		rt := &retryTransport{MaxRetries: 0, Delay: 0}
		req := newRequestWithParams(http.MethodGet, "http://example.com", nil, nil, "")
		_, err := rt.RoundTrip(req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestExternalBaseURLFromHeadersURLParse(t *testing.T) {
	h := http.Header{}
	h.Set("X-Selenosis-External-URL", "http://example.com/path")
	u, ok := externalBaseURLFromHeaders(h)
	if !ok || u.Host != "example.com" || u.Path != "/path" {
		t.Fatalf("unexpected url: %#v (ok=%v)", u, ok)
	}
}

func TestExternalBaseURLFromHeadersURL(t *testing.T) {
	h := http.Header{}
	h.Set("X-Selenosis-External-URL", "https://example.com")
	u, ok := externalBaseURLFromHeaders(h)
	if !ok || u.Scheme != "https" {
		t.Fatalf("unexpected url: %#v (ok=%v)", u, ok)
	}
}
