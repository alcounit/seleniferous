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
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alcounit/seleniferous/v2/pkg/session"
	"github.com/alcounit/seleniferous/v2/pkg/store"
	"github.com/alcounit/selenosis/v2/pkg/proxy"
	"github.com/alcounit/selenosis/v2/pkg/proxy/rule"
	"github.com/alcounit/selenosis/v2/pkg/selenium"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

func TestCreateSessionStoreNotEmpty(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("x", "y")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", nil, nil, "")
	rw := httptestRecorder()

	svc.WebDriverNewSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestCreateSessionNilBody(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", nil, map[string]string{}, "")
	req.Body = nil
	rw := httptestRecorder()

	svc.WebDriverNewSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestCreateSessionWaitFails(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverNewSession(rw, req)

		if rw.status != http.StatusServiceUnavailable {
			t.Fatalf("expected status 503, got %d", rw.status)
		}
	})
}

func TestCreateSessionSuccess(t *testing.T) {
	st := store.NewDefaultStore[string]()
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

		svc.WebDriverNewSession(rw, req)

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

func TestCreateSessionRemovesSelenosisOptionsFromRequest(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 100 * time.Millisecond,
	}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotBody []byte
	respPayload := selenium.Payload{
		"value": map[string]any{
			"sessionId": "orig",
		},
	}
	respBody, _ := json.Marshal(respPayload)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		gotBody, _ = io.ReadAll(req.Body)
		return response(http.StatusOK, string(respBody)), nil
	})

	withDefaultTransports(t, rt, func() {
		reqBody := `{"desiredCapabilities":{"browserName":"chrome","selenosis:options":{"labels":{"env":"test"}}}}`
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(reqBody), nil, "")
		rw := httptestRecorder()

		svc.WebDriverNewSession(rw, req)

		if rw.status != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rw.status)
		}
	})

	var forwarded map[string]any
	if err := json.Unmarshal(gotBody, &forwarded); err != nil {
		t.Fatalf("failed to decode forwarded body: %v", err)
	}
	dc, _ := forwarded["desiredCapabilities"].(map[string]any)
	if _, ok := dc["selenosis:options"]; ok {
		t.Fatalf("expected selenosis:options to be removed before forwarding, got %s", string(gotBody))
	}
}

func TestCreateSessionDoesNotRetryFailedRoundTrip(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 100 * time.Millisecond,
	}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var postCalls int
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		postCalls++
		return nil, errors.New("fail")
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()

		svc.WebDriverNewSession(rw, req)

		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if postCalls != 1 {
			t.Fatalf("expected exactly 1 POST attempt, got %d", postCalls)
		}
	})
}

func TestProxyMcpInitDoesNotRetryFailedRoundTrip(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 100 * time.Millisecond,
	}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var postCalls int
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		postCalls++
		return nil, errors.New("fail")
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if postCalls != 1 {
			t.Fatalf("expected exactly 1 POST attempt, got %d", postCalls)
		}
	})
}

func TestCreateSessionResponseBodyNil(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverNewSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
	})
}

func TestCreateSessionReadError(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverNewSession(rw, req)

		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionInvalidJSON(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverNewSession(rw, req)

		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionMissingSessionId(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverNewSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionUpdateSessionIdFails(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverNewSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestCreateSessionNonOKStatus(t *testing.T) {
	st := store.NewDefaultStore[string]()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}, st, session.NewManager(time.Second, nil), rec)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusBadRequest, "{}"), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString(`{}`), nil, "")
		rw := httptestRecorder()
		svc.WebDriverNewSession(rw, req)
		if rw.status != http.StatusInternalServerError {
			t.Fatalf("expected status 500, got %d", rw.status)
		}
		if len(rec.events) == 0 || rec.events[0].Type != EventTypeError {
			t.Fatalf("expected error event, got %+v", rec.events)
		}
	})
}

func TestProxySessionUnknownSession(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()

	svc.WebDriverProxy(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestProxyMcpMissingSessionId(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/mcp/", nil, map[string]string{}, "")
	rw := httptestRecorder()

	svc.ProxyMcp(rw, req)

	assertMcpError(t, rw, http.StatusBadRequest, -32602)
}

func TestProxyMcpUnknownSessionId(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/mcp/other", nil, map[string]string{}, "")
	req.Header.Set("Mcp-Session-Id", "other")
	rw := httptestRecorder()

	svc.ProxyMcp(rw, req)

	assertMcpError(t, rw, http.StatusNotFound, -32001)
}

func TestProxyMcpSessionNotInStore(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/mcp/fake", nil, map[string]string{}, "")
	req.Header.Set("Mcp-Session-Id", "fake")
	rw := httptestRecorder()

	svc.ProxyMcp(rw, req)

	assertMcpError(t, rw, http.StatusNotFound, -32001)
}

func TestProxyMcpPostToMcp(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotReq *http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		gotReq = req
		return response(http.StatusOK, `{"jsonrpc":"2.0","id":1,"result":{}}`), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp", bytes.NewBufferString(`{"jsonrpc":"2.0","id":1,"method":"initialize"}`), nil, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.URL.Path != "/mcp" {
			t.Fatalf("expected path /mcp, got %s", gotReq.URL.Path)
		}
		if !strings.Contains(gotReq.Host, "localhost") {
			t.Fatalf("expected Host header with localhost, got %s", gotReq.Host)
		}
	})
}

func TestProxyMcpGetToMcp(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotReq *http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotReq = req
		return response(http.StatusOK, "{}"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodGet, "/mcp/fake", nil, map[string]string{}, "")
		req.Header.Set("Mcp-Session-Id", "fake")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.URL.Path != "/mcp" {
			t.Fatalf("expected path /mcp, got %s", gotReq.URL.Path)
		}
	})
}

func TestProxyMcpPreservesQueryParams(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotReq *http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		gotReq = req
		return response(http.StatusOK, "{}"), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/fake?foo=bar&baz=qux", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.URL.RawQuery != "foo=bar&baz=qux" {
			t.Fatalf("expected query params preserved, got %q", gotReq.URL.RawQuery)
		}
	})
}

func TestProxyMcpStoresSessionWhenMissing(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		resp := response(http.StatusOK, "{}")
		resp.Header.Set("Mcp-Session-Id", "real-session")
		return resp, nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/fake", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if got, ok := st.Get("fake"); !ok || got != "real-session" {
			t.Fatalf("expected store mapping fake->real-session, got %v (ok=%v)", got, ok)
		}
		if rw.Header().Get("Mcp-Session-Id") != "fake" {
			t.Fatalf("expected response Mcp-Session-Id rewritten to fake, got %q", rw.Header().Get("Mcp-Session-Id"))
		}
	})
}

func TestProxyMcpKeepsExistingSession(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, "{}"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/fake", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if got, ok := st.Get("fake"); !ok || got != "orig" {
			t.Fatalf("expected existing mapping fake->orig, got %v (ok=%v)", got, ok)
		}
	})
}

func TestProxyMcpRewritesRequestSessionId(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	var gotReq *http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotReq = req
		return response(http.StatusOK, "{}"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/fake", nil, map[string]string{}, "")
		req.Header.Set("Mcp-Session-Id", "fake")
		req.Header.Set("Content-Type", "application/json")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.Header.Get("Mcp-Session-Id") != "orig" {
			t.Fatalf("expected Mcp-Session-Id rewritten to orig, got %q", gotReq.Header.Get("Mcp-Session-Id"))
		}
		if gotReq.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("expected Content-Type preserved, got %q", gotReq.Header.Get("Content-Type"))
		}
	})
}

func TestProxyMcpRewritesResponseSessionId(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		resp := response(http.StatusOK, "{}")
		resp.Header.Set("Mcp-Session-Id", "orig")
		return resp, nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/fake", nil, map[string]string{}, "")
		req.Header.Set("Mcp-Session-Id", "fake")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if rw.Header().Get("Mcp-Session-Id") != "fake" {
			t.Fatalf("expected response Mcp-Session-Id rewritten to fake, got %q", rw.Header().Get("Mcp-Session-Id"))
		}
	})
}

func TestProxyMcpDeleteNotifiesDelete(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	rec := &fakeBroadcaster{}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), rec)

	var gotReq *http.Request
	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		gotReq = req
		return response(http.StatusOK, "{}"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodDelete, "/mcp/fake", nil, map[string]string{}, "")
		req.Header.Set("Mcp-Session-Id", "fake")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if gotReq.Method != http.MethodDelete {
			t.Fatalf("expected DELETE method, got %s", gotReq.Method)
		}
		if gotReq.URL.Path != "/mcp" {
			t.Fatalf("expected path /mcp, got %s", gotReq.URL.Path)
		}

		rec.mu.Lock()
		defer rec.mu.Unlock()
		found := false
		for _, e := range rec.events {
			if e.Type == EventTypeDeleted {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("expected EventTypeDeleted to be broadcast after DELETE")
		}
	})
}

func TestProxyMcpDeleteDoesNotNotifyOnOtherMethods(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}
	rec := &fakeBroadcaster{}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), rec)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, "{}"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/fake", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		rec.mu.Lock()
		defer rec.mu.Unlock()
		for _, e := range rec.events {
			if e.Type == EventTypeDeleted {
				t.Fatal("unexpected EventTypeDeleted for POST request")
			}
		}
	})
}

func TestProxyMcpInitUnexpectedStatus(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444", SessionCreateTimeout: 100 * time.Millisecond}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead {
			return response(http.StatusOK, ""), nil
		}
		return response(http.StatusInternalServerError, "boom"), nil
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/", bytes.NewBufferString(`{}`), map[string]string{}, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		assertMcpError(t, rw, http.StatusInternalServerError, -32603)
		if _, ok := st.Get("fake"); ok {
			t.Fatal("expected no session stored on failed init")
		}
	})
}

func TestProxyMcpInitWaitTimeout(t *testing.T) {
	st := store.NewDefaultStore[string]()
	cfg := ServiceConfig{IPUUID: "fake", BrowserPort: "4444", SessionCreateTimeout: 20 * time.Millisecond}
	svc := NewService(cfg, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("connection refused")
	})

	withDefaultTransports(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/mcp/", bytes.NewBufferString(`{}`), map[string]string{}, "")
		rw := httptestRecorder()

		svc.ProxyMcp(rw, req)

		assertMcpError(t, rw, http.StatusServiceUnavailable, -32603)
		if _, ok := st.Get("fake"); ok {
			t.Fatal("expected no session stored on wait timeout")
		}
	})
}

func TestProxyMcpAlreadyStarted(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/mcp", bytes.NewBufferString(`{}`), nil, "")
	rw := httptestRecorder()

	svc.ProxyMcp(rw, req)

	assertMcpError(t, rw, http.StatusBadRequest, -32600)
}

func TestMcpErrorHandler(t *testing.T) {
	rw := httptestRecorder()
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	mcpErrorHandler(rw, req, errors.New("boom"))

	assertMcpError(t, rw, http.StatusInternalServerError, -32603)
}

func assertMcpError(t *testing.T, rw *recorder, wantStatus, wantCode int) {
	t.Helper()
	if rw.status != wantStatus {
		t.Fatalf("expected status %d, got %d", wantStatus, rw.status)
	}
	if ct := rw.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", ct)
	}
	var body struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Error   struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(rw.body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode JSON-RPC error body %q: %v", rw.body.String(), err)
	}
	if body.JSONRPC != "2.0" {
		t.Fatalf("expected jsonrpc 2.0, got %q", body.JSONRPC)
	}
	if body.ID != nil {
		t.Fatalf("expected id null, got %v", body.ID)
	}
	if body.Error.Code != wantCode {
		t.Fatalf("expected error code %d, got %d", wantCode, body.Error.Code)
	}
	if body.Error.Message == "" {
		t.Fatal("expected non-empty error message")
	}
}

func TestRouteHTTPMissingSessionId(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/", nil, map[string]string{}, "/foo")
	rw := httptestRecorder()

	svc.RouteHTTP(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteHTTPUnknownSession(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake/foo", nil, map[string]string{"sessionId": "fake"}, "/foo")
	rw := httptestRecorder()

	svc.RouteHTTP(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteHTTPMissingRestPath(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
	st := store.NewDefaultStore[string]()
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

	st := store.NewDefaultStore[string]()
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
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/vnc", nil, map[string]string{}, "")
	rw := httptestRecorder()

	svc.RouteVNC(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteVNCUnknownSession(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/vnc/fake", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()

	svc.RouteVNC(rw, req)

	if rw.status != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rw.status)
	}
}

func TestRouteVNCUpgradeFails(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/vnc/fake", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()

	svc.RouteVNC(rw, req)
}

func TestRouteVNCDialError(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
	st := store.NewDefaultStore[string]()
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
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	svc.storeSessionId("orig")

	if got, ok := svc.getSessionId("fake"); !ok || got != "orig" {
		t.Fatalf("expected orig session, got %q (ok=%v)", got, ok)
	}

}

func TestWriteErrorResponse(t *testing.T) {
	rw := httptestRecorder()
	writeErrorResponse(rw, http.StatusBadRequest, selenium.ErrSessionNotCreated(errors.New("bad")))

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
	if got := rw.header.Get("Content-Type"); got != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %q", got)
	}

	var body selenium.SeleniumError
	if err := json.Unmarshal(rw.body.Bytes(), &body); err != nil {
		t.Fatalf("failed to decode body %q: %v", rw.body.String(), err)
	}
	if body.Value.Name != "session not created" {
		t.Fatalf("expected error name 'session not created', got %q", body.Value.Name)
	}
	if !strings.Contains(body.Value.Message, "bad") {
		t.Fatalf("expected message to contain root cause, got %q", body.Value.Message)
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

func TestProxySessionHTTP(t *testing.T) {
	st := store.NewDefaultStore[string]()
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

		svc.WebDriverProxy(rw, req)

		if gotReq == nil {
			t.Fatal("expected request to reach transport")
		}
		if !strings.Contains(gotReq.URL.Host, "127.0.0.1") {
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
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverProxy(rw, req)
		if string(gotBody) != "{" {
			t.Fatalf("expected original body to pass through, got %s", string(gotBody))
		}
	})
}

func TestProxySessionNoBody(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{}`), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodGet, "/session/fake/url", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.WebDriverProxy(rw, req)
	})
}

func TestProxySessionResponseBodyNil(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: nil, Header: make(http.Header)}, nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodGet, "/session/fake/url", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.WebDriverProxy(rw, req)
	})
}

func TestProxySessionRequestUpdateFails(t *testing.T) {
	st := store.NewDefaultStore[string]()
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
		svc.WebDriverProxy(rw, req)
		if !bytes.Contains(gotBody, []byte(`"fake"`)) {
			t.Fatalf("expected original sessionId to remain, got %s", string(gotBody))
		}
	})
}

func TestProxySessionDeleteBranch(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), rec)

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, `{}`), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodDelete, "/session/fake", nil, map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.WebDriverProxy(rw, req)
	})

	if !waitForEventType(rec, EventTypeDeleted, 4*time.Second) {
		t.Fatal("expected delete event after delete request")
	}
}

const legacyDeleteTimerDelay = 3 * time.Second

// The delete notification raises SIGTERM, and the graceful shutdown that follows
// cannot drain the connection still serving this request. It must therefore not
// be broadcast until the DELETE response has been written. It used to be armed on
// a legacyDeleteTimerDelay timer when the request arrived, so a browser that took
// longer than that to tear down had its client's response killed by the shutdown.
// Hold the upstream open past that timer and assert nothing is broadcast while the
// request is still unanswered.
func TestProxySessionDeleteNotifiesOnlyAfterResponse(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), rec)

	var once sync.Once
	inFlight := make(chan struct{})
	release := make(chan struct{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		once.Do(func() { close(inFlight) })
		<-release
		return response(http.StatusOK, `{}`), nil
	})

	done := make(chan struct{})
	withProxyTransport(t, rt, func() {
		go func() {
			defer close(done)
			req := newRequestWithParams(http.MethodDelete, "/session/fake", nil, map[string]string{"sessionId": "fake"}, "")
			svc.WebDriverProxy(httptestRecorder(), req)
		}()

		<-inFlight

		time.Sleep(legacyDeleteTimerDelay + 500*time.Millisecond)
		if rec.hasEventType(EventTypeDeleted) {
			t.Error("delete event broadcast while the DELETE response was still in flight")
		}

		close(release)
		<-done
	})

	if !waitForEventType(rec, EventTypeDeleted, 4*time.Second) {
		t.Fatal("expected delete event once the response was written")
	}
}

func TestProxySessionResponseInvalidJSON(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rt := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, "{"), nil
	})

	withProxyTransport(t, rt, func() {
		req := newRequestWithParams(http.MethodPost, "/session/fake/url", bytes.NewBufferString(`{}`), map[string]string{"sessionId": "fake"}, "")
		rw := httptestRecorder()
		svc.WebDriverProxy(rw, req)
		if rw.status != http.StatusOK {
			t.Fatalf("expected status 200, got %d", rw.status)
		}
	})
}

func TestProxySessionWebSocketPath(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/session/fake/ws", nil, map[string]string{"sessionId": "fake"}, "")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	rw := httptestRecorder()

	svc.WebDriverProxy(rw, req)

	if rw.status != http.StatusBadGateway && rw.status != http.StatusInternalServerError {
		t.Fatalf("expected proxy error status, got %d", rw.status)
	}
}

func TestProxySessionWebSocketCallbacks(t *testing.T) {
	port, received, shutdown := startWebSocketEchoServer(t)
	defer shutdown()

	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: port}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })

	req := newRequestWithParams(http.MethodGet, "/session/fake/ws", nil, map[string]string{"sessionId": "fake"}, "")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rw := &hijackResponseWriter{conn: serverConn, header: make(http.Header)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.WebDriverProxy(rw, req)
	}()

	if err := readHTTPResponse(clientConn); err != nil {
		t.Fatalf("failed to read upgrade response: %v", err)
	}
	if err := writeMaskedFrame(clientConn, 0x2, []byte("ping")); err != nil {
		t.Fatalf("failed to write websocket frame: %v", err)
	}

	select {
	case payload := <-received:
		if string(payload) != "ping" {
			t.Fatalf("unexpected upstream payload: %q", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream websocket payload")
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for websocket proxy to exit")
	}
}

func TestProxyPlaywrightMissingIPUUID(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/playwright", nil, nil, "")
	rw := httptestRecorder()

	svc.PlaywrightConnect(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestProxyPlaywrightUnknownIPUUID(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/playwright/other", nil, map[string]string{"ipuuid": "other"}, "")
	rw := httptestRecorder()

	svc.PlaywrightConnect(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestProxyPlaywrightStoresSessionWhenMissing(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 50 * time.Millisecond,
	}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/playwright/fake", nil, map[string]string{"ipuuid": "fake"}, "")
	rw := httptestRecorder()

	svc.PlaywrightConnect(rw, req)

	if rw.status != http.StatusBadGateway && rw.status != http.StatusInternalServerError {
		t.Fatalf("expected proxy error status, got %d", rw.status)
	}
	if got, ok := st.Get("fake"); !ok || got != "fake" {
		t.Fatalf("expected store mapping fake->fake, got %v (ok=%v)", got, ok)
	}
}

func TestProxyPlaywrightKeepsExistingSession(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 50 * time.Millisecond,
	}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/playwright/fake", nil, map[string]string{"ipuuid": "fake"}, "")
	rw := httptestRecorder()

	svc.PlaywrightConnect(rw, req)

	if rw.status != http.StatusBadGateway && rw.status != http.StatusInternalServerError {
		t.Fatalf("expected proxy error status, got %d", rw.status)
	}
	if got, ok := st.Get("fake"); !ok || got != "orig" {
		t.Fatalf("expected existing mapping fake->orig, got %v (ok=%v)", got, ok)
	}
}

func TestProxyPlaywrightWebSocketCallbacks(t *testing.T) {
	port, received, shutdown := startWebSocketEchoServer(t)
	defer shutdown()

	st := store.NewDefaultStore[string]()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          port,
		SessionCreateTimeout: time.Second,
	}, st, session.NewManager(time.Second, nil), rec)

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })

	req := newRequestWithParams(http.MethodGet, "/playwright/fake", nil, map[string]string{"ipuuid": "fake"}, "")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rw := &hijackResponseWriter{conn: serverConn, header: make(http.Header)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.PlaywrightConnect(rw, req)
	}()

	if err := readHTTPResponse(clientConn); err != nil {
		t.Fatalf("failed to read upgrade response: %v", err)
	}
	if err := writeMaskedFrame(clientConn, 0x2, []byte("ping")); err != nil {
		t.Fatalf("failed to write websocket frame: %v", err)
	}

	select {
	case payload := <-received:
		if string(payload) != "ping" {
			t.Fatalf("unexpected upstream payload: %q", string(payload))
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for upstream websocket payload")
	}

	if rec.hasEventType(EventTypeDeleted) {
		t.Fatal("delete event broadcast while the websocket was still open")
	}

	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for playwright websocket proxy to exit")
	}

	if !waitForEventType(rec, EventTypeDeleted, 4*time.Second) {
		t.Fatal("expected delete event after websocket close")
	}
}

func TestProxyPlaywrightDoesNotNotifyOnDialFailure(t *testing.T) {
	st := store.NewDefaultStore[string]()
	rec := &fakeBroadcaster{}
	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          "4444",
		SessionCreateTimeout: 50 * time.Millisecond,
	}, st, session.NewManager(time.Second, nil), rec)

	req := newRequestWithParams(http.MethodGet, "/playwright/fake", nil, map[string]string{"ipuuid": "fake"}, "")
	rw := httptestRecorder()

	svc.PlaywrightConnect(rw, req)

	if rw.status != http.StatusBadGateway && rw.status != http.StatusInternalServerError {
		t.Fatalf("expected proxy error status, got %d", rw.status)
	}
	if rec.hasEventType(EventTypeDeleted) {
		t.Fatal("unexpected delete event after a failed upstream dial")
	}
}

func TestProxyPlaywrightDoesNotNotifyOnInvalidIPUUID(t *testing.T) {
	for _, ipUUID := range []string{"", "other"} {
		target := "/playwright/" + ipUUID
		st := store.NewDefaultStore[string]()
		rec := &fakeBroadcaster{}
		svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), rec)

		rw := httptestRecorder()
		svc.PlaywrightConnect(rw, newRequestWithParams(http.MethodGet, target, nil, map[string]string{"ipuuid": ipUUID}, ""))

		if rw.status != http.StatusBadRequest {
			t.Fatalf("expected status 400 for %s, got %d", target, rw.status)
		}
		if rec.hasEventType(EventTypeDeleted) {
			t.Fatalf("unexpected delete event for %s", target)
		}
	}
}

const devtoolsVersionBody = `{"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/0f3c-guid"}`

func newDevtoolsService(t *testing.T, port string, rec *fakeBroadcaster) (*Service, store.Store[string]) {
	t.Helper()

	st := store.NewDefaultStore[string]()
	if rec == nil {
		rec = &fakeBroadcaster{}
	}

	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          port,
		SessionCreateTimeout: time.Second,
	}, st, session.NewManager(time.Second, nil), rec)

	return svc, st
}

func debugModeBrowser(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/json/version" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write([]byte(devtoolsVersionBody))
}

func devtoolsRequest(method, target, rest string) *http.Request {
	params := map[string]string{"ipuuid": "fake"}
	if rest != "" {
		params["*"] = rest
	}

	req := newRequestWithParams(method, target, nil, params, "")
	req.Header.Set("X-Selenosis-External-URL", "http://selenosis.example.com")

	return req
}

func devtoolsWSRequest(target, rest string) *http.Request {
	req := devtoolsRequest(http.MethodGet, target, rest)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	return req
}

func lastCaptured(t *testing.T, captured <-chan *http.Request) *http.Request {
	t.Helper()

	var last *http.Request
	for {
		select {
		case upstream := <-captured:
			last = upstream
		case <-time.After(300 * time.Millisecond):
			if last == nil {
				t.Fatal("browser was never called")
			}
			return last
		}
	}
}

func debugModeBrowserWith(extraPath, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/json/version":
			debugModeBrowser(w, r)
		case extraPath:
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(http.StatusBadRequest)
		}
	}
}

func devtoolsUpstream(t *testing.T, rest string, respond http.HandlerFunc) *http.Request {
	t.Helper()

	if respond == nil {
		respond = debugModeBrowser
	}

	port, captured, shutdown := startBrowserRecorder(t, respond)
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/"+rest, rest))

	return lastCaptured(t, captured)
}

func TestDevToolsMissingIPUUID(t *testing.T) {
	svc, _ := newDevtoolsService(t, "4444", nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, newRequestWithParams(http.MethodGet, "/devtools/session//json/version", nil, nil, ""))

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestDevToolsForeignIPUUID(t *testing.T) {
	svc, _ := newDevtoolsService(t, "4444", nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, newRequestWithParams(http.MethodGet, "/devtools/session/other/json/version", nil, map[string]string{"ipuuid": "other"}, ""))

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestDevToolsRegistersSession(t *testing.T) {
	port, _, shutdown := startBrowserRecorder(t, debugModeBrowser)
	defer shutdown()

	svc, st := newDevtoolsService(t, port, nil)

	for range 2 {
		rw := httptestRecorder()
		svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/version", "json/version"))
	}

	if got, ok := st.Get("fake"); !ok || got != "fake" {
		t.Fatalf("expected the session to be registered under the ipuuid, got %q (present=%v)", got, ok)
	}
	if st.Len() != 1 {
		t.Fatalf("expected exactly one session in the store, got %d", st.Len())
	}
}

func TestDevToolsHTTPPathMapping(t *testing.T) {
	tests := []struct {
		name string
		rest string
		want string
	}{
		{name: "session root goes to the browser root", rest: "", want: "/"},
		{name: "json version", rest: "json/version", want: "/json/version"},
		{name: "json list", rest: "json/list", want: "/json/list"},
		{name: "short json", rest: "json", want: "/json"},
		{name: "json new", rest: "json/new", want: "/json/new"},
		{name: "json protocol", rest: "json/protocol", want: "/json/protocol"},
		{name: "json activate", rest: "json/activate/AB12", want: "/json/activate/AB12"},
		{name: "json close", rest: "json/close/AB12", want: "/json/close/AB12"},
		{name: "frontend static", rest: "devtools/inspector.html", want: "/devtools/inspector.html"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := devtoolsUpstream(t, tt.rest, nil)

			if upstream.URL.Path != tt.want {
				t.Fatalf("browser path = %q, want %q", upstream.URL.Path, tt.want)
			}
		})
	}
}

func TestDevToolsHTTPSetsHostToBrowser(t *testing.T) {
	port, captured, shutdown := startBrowserRecorder(t, debugModeBrowser)
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	req := devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/version", "json/version")
	req.Host = "selenosis.example.com"
	svc.DevToolsProxy(rw, req)

	upstream := lastCaptured(t, captured)

	want := net.JoinHostPort(loopbackAddr, port)
	if upstream.Host != want {
		t.Fatalf("Host header = %q, want %q", upstream.Host, want)
	}
}

func TestDevToolsHTTPPreservesQuery(t *testing.T) {
	port, captured, shutdown := startBrowserRecorder(t, debugModeBrowser)
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodPut, "/devtools/session/fake/json/new?url=https%3A%2F%2Fexample.com", "json/new"))

	upstream := lastCaptured(t, captured)

	if got := upstream.URL.Query().Get("url"); got != "https://example.com" {
		t.Fatalf("query did not reach the browser: %q", got)
	}
	if upstream.Method != http.MethodPut {
		t.Fatalf("method = %q, want PUT", upstream.Method)
	}
}

func TestDevToolsHTTPPreservesKeylessRawQuery(t *testing.T) {
	port, captured, shutdown := startBrowserRecorder(t, debugModeBrowser)
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodPut, "/devtools/session/fake/json/new?https://example.com", "json/new"))

	upstream := lastCaptured(t, captured)

	if upstream.URL.RawQuery != "https://example.com" {
		t.Fatalf("raw query = %q, want it untouched", upstream.URL.RawQuery)
	}
}

func TestDevToolsRewritesVersionBody(t *testing.T) {
	tests := []struct {
		name     string
		external string
		want     string
	}{
		{name: "plain", external: "http://selenosis.example.com", want: "ws://selenosis.example.com/devtools/session/fake/devtools/browser/0f3c-guid"},
		{name: "tls", external: "https://selenosis.example.com", want: "wss://selenosis.example.com/devtools/session/fake/devtools/browser/0f3c-guid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, _, shutdown := startBrowserRecorder(t, debugModeBrowser)
			defer shutdown()

			svc, _ := newDevtoolsService(t, port, nil)

			req := devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/version", "json/version")
			req.Header.Set("X-Selenosis-External-URL", tt.external)
			rw := httptestRecorder()
			svc.DevToolsProxy(rw, req)

			if !strings.Contains(rw.body.String(), tt.want) {
				t.Fatalf("expected %q in the rewritten body, got %s", tt.want, rw.body.String())
			}
		})
	}
}

func TestDevToolsRewritesListBody(t *testing.T) {
	const body = `[{"id":"AB12","webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/page/AB12"}]`

	port, _, shutdown := startBrowserRecorder(t, debugModeBrowserWith("/json/list", body))
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/list", "json/list"))

	want := "ws://selenosis.example.com/devtools/session/fake/devtools/page/AB12"
	if !strings.Contains(rw.body.String(), want) {
		t.Fatalf("expected %q in the rewritten body, got %s", want, rw.body.String())
	}
}

func TestDevToolsEmptyVersionBodyPassesThrough(t *testing.T) {
	port, _, shutdown := startBrowserRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/version", "json/version"))

	if rw.status != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rw.status)
	}
	if rw.body.Len() != 0 {
		t.Fatalf("expected an empty body to pass through, got %s", rw.body.String())
	}
}

func TestDevToolsWithoutExternalURLPassesBodyThrough(t *testing.T) {
	port, _, shutdown := startBrowserRecorder(t, debugModeBrowser)
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	req := newRequestWithParams(http.MethodGet, "/devtools/session/fake/json/version", nil, map[string]string{"ipuuid": "fake", "*": "json/version"}, "")
	rw := httptestRecorder()
	svc.DevToolsProxy(rw, req)

	if rw.body.String() != devtoolsVersionBody {
		t.Fatalf("expected the body to pass through untouched, got %s", rw.body.String())
	}
}

func TestDevToolsDoesNotRewriteNonJSONEndpoints(t *testing.T) {
	const body = `{"webSocketDebuggerUrl":"ws://127.0.0.1:9222/devtools/browser/guid"}`

	port, _, shutdown := startBrowserRecorder(t, debugModeBrowserWith("/json/protocol", body))
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/protocol", "json/protocol"))

	if !strings.Contains(rw.body.String(), "127.0.0.1:9222") {
		t.Fatalf("expected /json/protocol to pass through untouched, got %s", rw.body.String())
	}
}

func TestDevToolsMalformedBodyPassesThrough(t *testing.T) {
	port, _, shutdown := startBrowserRecorder(t, debugModeBrowserWith("/json/list", "{not json"))
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/list", "json/list"))

	if rw.body.String() != "{not json" {
		t.Fatalf("expected the malformed body to pass through, got %s", rw.body.String())
	}
}

func TestDevToolsTruncatedBodyIsAnError(t *testing.T) {
	port, _, shutdown := startBrowserRecorder(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()

		_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 4096\r\n\r\n{\"a\":1}"))
	})
	defer shutdown()

	svc, _ := newDevtoolsService(t, port, nil)

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/list", "json/list"))

	if rw.status != http.StatusBadGateway {
		t.Fatalf("expected status 502 on a truncated body, got %d", rw.status)
	}
}

func TestDevToolsHTTPTouchesIdleTimer(t *testing.T) {
	port, _, shutdown := startBrowserRecorder(t, debugModeBrowser)
	defer shutdown()

	var timedOut atomic.Bool
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          port,
		SessionCreateTimeout: time.Second,
	}, st, session.NewManager(300*time.Millisecond, func(string) { timedOut.Store(true) }), &fakeBroadcaster{})

	for range 4 {
		rw := httptestRecorder()
		svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/list", "json/list"))
		time.Sleep(100 * time.Millisecond)
	}

	if timedOut.Load() {
		t.Fatal("idle timer fired while devtools http requests were still arriving")
	}
}

func TestDevToolsHTTPWaitsForBrowserPort(t *testing.T) {
	port := deadPort(t)

	svc, _ := newDevtoolsService(t, port, nil)

	started := make(chan func(), 1)
	go func() {
		time.Sleep(200 * time.Millisecond)
		_, _, shutdown := startBrowserRecorderOn(t, port, debugModeBrowser)
		started <- shutdown
	}()

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/version", "json/version"))

	shutdown := <-started
	defer shutdown()

	if rw.status != http.StatusOK {
		t.Fatalf("expected the request to wait for the browser port, got status %d", rw.status)
	}
}

func TestDevToolsHTTPUnreachableBrowser(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{
		IPUUID:               "fake",
		BrowserPort:          deadPort(t),
		SessionCreateTimeout: 200 * time.Millisecond,
	}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rw := httptestRecorder()
	svc.DevToolsProxy(rw, devtoolsRequest(http.MethodGet, "/devtools/session/fake/json/version", "json/version"))

	if rw.status != http.StatusBadGateway {
		t.Fatalf("expected status 502, got %d", rw.status)
	}
}

func deadPort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local port: %v", err)
	}

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	if err := listener.Close(); err != nil {
		t.Fatalf("failed to close listener: %v", err)
	}

	return port
}

func echoWebSocket(w http.ResponseWriter, r *http.Request) {
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	defer conn.Close()

	for {
		msgType, payload, err := conn.ReadMessage()
		if err != nil {
			return
		}
		if err := conn.WriteMessage(msgType, payload); err != nil {
			return
		}
	}
}

func runDevtoolsSocket(t *testing.T, svc *Service, req *http.Request) {
	t.Helper()

	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() { _ = clientConn.Close() })
	t.Cleanup(func() { _ = serverConn.Close() })

	rw := &hijackResponseWriter{conn: serverConn, header: make(http.Header)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.DevToolsProxy(rw, req)
	}()

	if err := readHTTPResponse(clientConn); err != nil {
		t.Fatalf("failed to read upgrade response: %v", err)
	}
	if err := writeMaskedFrame(clientConn, 0x2, []byte("ping")); err != nil {
		t.Fatalf("failed to write websocket frame: %v", err)
	}

	time.Sleep(100 * time.Millisecond)
	_ = clientConn.Close()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for the devtools socket proxy to exit")
	}
}

func TestDevToolsWebSocketIsForwardedAsIs(t *testing.T) {
	tests := []struct {
		name string
		rest string
		want string
	}{
		{name: "root socket", rest: "", want: "/"},
		{name: "browser socket", rest: "devtools/browser/guid", want: "/devtools/browser/guid"},
		{name: "page socket", rest: "devtools/page/AB12", want: "/devtools/page/AB12"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, captured, shutdown := startBrowserRecorder(t, echoWebSocket)
			defer shutdown()

			svc, _ := newDevtoolsService(t, port, nil)

			req := devtoolsWSRequest("/devtools/session/fake/"+tt.rest, tt.rest)
			req.Host = "selenosis.example.com"
			runDevtoolsSocket(t, svc, req)

			var upstreams []*http.Request
		drain:
			for {
				select {
				case upstream := <-captured:
					upstreams = append(upstreams, upstream)
				case <-time.After(300 * time.Millisecond):
					break drain
				}
			}

			if len(upstreams) != 1 {
				t.Fatalf("expected exactly one request to reach the browser, got %d", len(upstreams))
			}

			upstream := upstreams[0]
			if !strings.EqualFold(upstream.Header.Get("Upgrade"), "websocket") {
				t.Fatalf("expected the only browser request to be a websocket upgrade, got %q", upstream.Header.Get("Upgrade"))
			}
			if upstream.URL.Path != tt.want {
				t.Fatalf("browser path = %q, want %q", upstream.URL.Path, tt.want)
			}
			if want := net.JoinHostPort(loopbackAddr, port); upstream.Host != want {
				t.Fatalf("Host header = %q, want %q", upstream.Host, want)
			}
		})
	}
}

func TestDevToolsSocketOwnership(t *testing.T) {
	tests := []struct {
		name       string
		rest       string
		wantDelete bool
	}{
		{name: "page socket does not own the session", rest: "devtools/page/AB12", wantDelete: false},
		{name: "root socket owns the session", rest: "", wantDelete: true},
		{name: "browser socket owns the session", rest: "devtools/browser/guid", wantDelete: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			port, _, shutdown := startWebSocketEchoServer(t)
			defer shutdown()

			rec := &fakeBroadcaster{}
			svc, _ := newDevtoolsService(t, port, rec)

			runDevtoolsSocket(t, svc, devtoolsWSRequest("/devtools/session/fake/"+tt.rest, tt.rest))

			timeout := 500 * time.Millisecond
			if tt.wantDelete {
				timeout = 4 * time.Second
			}

			if got := waitForEventType(rec, EventTypeDeleted, timeout); got != tt.wantDelete {
				t.Fatalf("delete event = %v, want %v", got, tt.wantDelete)
			}
		})
	}
}

func startBrowserRecorder(t *testing.T, respond http.HandlerFunc) (string, <-chan *http.Request, func()) {
	t.Helper()

	return startBrowserRecorderOn(t, "0", respond)
}

func startBrowserRecorderOn(t *testing.T, port string, respond http.HandlerFunc) (string, <-chan *http.Request, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", net.JoinHostPort(loopbackAddr, port))
	if err != nil {
		t.Fatalf("failed to listen on local port %s: %v", port, err)
	}

	captured := make(chan *http.Request, 8)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case captured <- r.Clone(context.Background()):
		default:
		}

		if respond != nil {
			respond(w, r)
			return
		}

		w.WriteHeader(http.StatusBadRequest)
	})}

	done := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(done)
	}()

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
		<-done
	}

	boundPort := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	return boundPort, captured, shutdown
}

func browserUpstreamURL(t *testing.T, target string) *url.URL {
	t.Helper()

	port, captured, shutdown := startBrowserRecorder(t, nil)
	defer shutdown()

	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{
		IPUUID:      "fake",
		BrowserPort: port,
	}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	rw := httptestRecorder()
	svc.PlaywrightConnect(rw, newRequestWithParams(http.MethodGet, target, nil, map[string]string{"ipuuid": "fake"}, ""))

	select {
	case upstream := <-captured:
		return upstream.URL
	case <-time.After(2 * time.Second):
		t.Fatal("browser was never called")
		return nil
	}
}

func TestProxyPlaywrightForwardsQueryToBrowser(t *testing.T) {
	upstream := browserUpstreamURL(t, "/playwright/fake?headless=false&timeout=30000")

	if upstream.Path != "/" {
		t.Fatalf("unexpected browser path: %q", upstream.Path)
	}

	q := upstream.Query()
	if q.Get("headless") != "false" {
		t.Fatalf("expected headless=false to reach the browser, got %q", q.Get("headless"))
	}
	if q.Get("timeout") != "30000" {
		t.Fatalf("expected timeout=30000 to reach the browser, got %q", q.Get("timeout"))
	}
}

func TestProxyPlaywrightPreservesRawQuery(t *testing.T) {
	upstream := browserUpstreamURL(t, "/playwright/fake?b=2&a=1&https://example.com")

	if upstream.RawQuery != "b=2&a=1&https://example.com" {
		t.Fatalf("expected the raw query to reach the browser untouched, got %q", upstream.RawQuery)
	}
}

func TestProxyPlaywrightSendsEmptyQueryWhenClientQueryEmpty(t *testing.T) {
	upstream := browserUpstreamURL(t, "/playwright/fake")

	if upstream.RawQuery != "" {
		t.Fatalf("expected empty raw query, got %q", upstream.RawQuery)
	}
}

func TestProxyPlaywrightPreservesRepeatedAndEncodedValues(t *testing.T) {
	upstream := browserUpstreamURL(t, "/playwright/fake?args=--no-sandbox&args=--disable-gpu&note=a+b%26c")

	q := upstream.Query()
	args := q["args"]
	if len(args) != 2 || args[0] != "--no-sandbox" || args[1] != "--disable-gpu" {
		t.Fatalf("expected both args values in order, got %#v", args)
	}
	if q.Get("note") != "a b&c" {
		t.Fatalf("expected encoded value to survive, got %q", q.Get("note"))
	}
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

func TestWaitSucceedsOnFirstProbe(t *testing.T) {
	var calls int32
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return response(http.StatusOK, "ok"), nil
	}), func() {
		if err := wait(context.Background(), "http://example.com", time.Second); err != nil {
			t.Fatalf("unexpected wait error: %v", err)
		}
	})

	if got := atomic.LoadInt32(&calls); got != 1 {
		t.Fatalf("expected exactly 1 probe, got %d", got)
	}
}

func TestWaitSucceedsAfterRetries(t *testing.T) {
	var calls int32
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if atomic.AddInt32(&calls, 1) < 3 {
			return nil, errors.New("down")
		}
		return response(http.StatusOK, "ok"), nil
	}), func() {
		if err := wait(context.Background(), "http://example.com", time.Second); err != nil {
			t.Fatalf("unexpected wait error: %v", err)
		}
	})

	if got := atomic.LoadInt32(&calls); got != 3 {
		t.Fatalf("expected 3 probes, got %d", got)
	}
}

func TestWaitTimesOutWhenBrowserNeverResponds(t *testing.T) {
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return nil, errors.New("down")
	}), func() {
		start := time.Now()
		err := wait(context.Background(), "http://example.com", 100*time.Millisecond)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected wait error")
		}
		if !strings.Contains(err.Error(), "does not respond in") {
			t.Fatalf("unexpected error: %v", err)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("wait overshot its budget: took %v", elapsed)
		}
	})
}

func TestWaitTimesOutOnHungProbe(t *testing.T) {
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		<-req.Context().Done()
		return nil, req.Context().Err()
	}), func() {
		start := time.Now()
		err := wait(context.Background(), "http://example.com", 100*time.Millisecond)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected wait error on a hung probe")
		}
		if elapsed > 2*time.Second {
			t.Fatalf("hung probe was not bounded by the budget: took %v", elapsed)
		}
	})
}

func TestWaitStopsOnCancelledContext(t *testing.T) {
	var calls int32
	withDefaultClientTransport(t, roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&calls, 1)
		return nil, errors.New("down")
	}), func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		start := time.Now()
		err := wait(ctx, "http://example.com", time.Minute)
		elapsed := time.Since(start)

		if err == nil {
			t.Fatal("expected wait error on a cancelled context")
		}
		if elapsed > 2*time.Second {
			t.Fatalf("cancelled context did not stop wait: took %v", elapsed)
		}
		if got := atomic.LoadInt32(&calls); got > 1 {
			t.Fatalf("expected at most 1 probe on a cancelled context, got %d", got)
		}
	})
}

func TestProbeReturnsWhenBudgetAlreadyExhausted(t *testing.T) {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
	defer cancel()

	if err := probe(ctx, "http://example.com"); err == nil {
		t.Fatal("expected error when the budget is already exhausted")
	}
}

func TestProbeRejectsInvalidURL(t *testing.T) {
	if err := probe(context.Background(), "http://a b.com"); err == nil {
		t.Fatal("expected error for an invalid url")
	}
}

type fakeBroadcaster struct {
	mu     sync.Mutex
	events []Event
}

func (f *fakeBroadcaster) Subscribe(_ ...func(Event) bool) chan Event {
	return nil
}

func (f *fakeBroadcaster) Unsubscribe(ch chan Event) {}

func (f *fakeBroadcaster) Broadcast(event Event) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, event)
}

func (f *fakeBroadcaster) hasEventType(typ EventType) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, event := range f.events {
		if event.Type == typ {
			return true
		}
	}
	return false
}

func waitForEventType(rec *fakeBroadcaster, typ EventType, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if rec.hasEventType(typ) {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return rec.hasEventType(typ)
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
	prevProxy := proxy.DefaultTransport
	http.DefaultClient.Transport = rt
	http.DefaultTransport = rt
	proxy.DefaultTransport = rt
	defer func() {
		http.DefaultClient.Transport = prevClient
		http.DefaultTransport = prevDefault
		proxy.DefaultTransport = prevProxy
		defaultClientMu.Unlock()
	}()
	fn()
}

func serveRoundTrip(conn net.Conn, rt http.RoundTripper) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}
	if req.URL.Scheme == "" {
		req.URL.Scheme = "http"
	}
	if req.URL.Host == "" {
		req.URL.Host = req.Host
	}
	resp, err := rt.RoundTrip(req)
	if err != nil {
		resp = &http.Response{
			StatusCode: http.StatusBadGateway,
			Body:       io.NopCloser(strings.NewReader(err.Error())),
			Header:     make(http.Header),
		}
	}
	_ = resp.Write(conn)
	if resp.Body != nil {
		resp.Body.Close()
	}
}

func startWebSocketEchoServer(t *testing.T) (string, <-chan []byte, func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen on local port: %v", err)
	}

	received := make(chan []byte, 8)
	upgrader := websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close()

		for {
			msgType, payload, err := conn.ReadMessage()
			if err != nil {
				return
			}
			select {
			case received <- append([]byte(nil), payload...):
			default:
			}
			if err := conn.WriteMessage(msgType, payload); err != nil {
				return
			}
		}
	})

	server := &http.Server{Handler: mux}
	done := make(chan struct{})
	go func() {
		_ = server.Serve(listener)
		close(done)
	}()

	shutdown := func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = server.Shutdown(ctx)
		_ = listener.Close()
		<-done
	}

	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	return port, received, shutdown
}

func withProxyTransport(t *testing.T, rt http.RoundTripper, fn func()) {
	t.Helper()
	defaultClientMu.Lock()
	prev := proxy.DefaultTransport
	proxy.DefaultTransport = &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			clientConn, serverConn := net.Pipe()
			go serveRoundTrip(serverConn, rt)
			return clientConn, nil
		},
		DisableKeepAlives: true,
	}
	defer func() {
		proxy.DefaultTransport = prev
		defaultClientMu.Unlock()
	}()
	fn()
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

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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

func readHTTPResponse(r io.Reader) error {
	reader := bufio.NewReader(r)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return err
		}
		if line == "\r\n" {
			return nil
		}
	}
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

func TestCreateSessionBodyReadError(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", io.NopCloser(errorReader{}), nil, "")
	rw := httptestRecorder()

	svc.WebDriverNewSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestCreateSessionInvalidRequestBody(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString("{invalid"), nil, "")
	rw := httptestRecorder()

	svc.WebDriverNewSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestProxySessionResponseBodyNilInModifier(t *testing.T) {
	st := store.NewDefaultStore[string]()
	st.Set("fake", "orig")
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	defaultClientMu.Lock()
	prev := proxy.DefaultTransport
	proxy.DefaultTransport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: nil, Header: make(http.Header)}, nil
	})
	defer func() {
		proxy.DefaultTransport = prev
		defaultClientMu.Unlock()
	}()

	req := newRequestWithParams(http.MethodGet, "/session/fake/url", nil, map[string]string{"sessionId": "fake"}, "")
	rw := httptestRecorder()
	svc.WebDriverProxy(rw, req)
}

func TestRouteVNCNormalClose(t *testing.T) {
	st := store.NewDefaultStore[string]()
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

	dialClient, dialServer := net.Pipe()
	t.Cleanup(func() { _ = dialClient.Close() })
	t.Cleanup(func() { _ = dialServer.Close() })

	withDialTCP(t, func(network, addr string) (net.Conn, error) {
		return dialServer, nil
	}, func() {
		done := make(chan struct{})
		go func() {
			svc.RouteVNC(rw, req)
			close(done)
		}()

		if err := readHTTPResponse(clientConn); err != nil {
			t.Fatalf("failed to read upgrade response: %v", err)
		}

		go func() { _, _ = io.Copy(io.Discard, clientConn) }()

		if err := writeMaskedFrame(clientConn, 0x8, []byte{0x03, 0xE8}); err != nil {
			t.Fatalf("failed to write close frame: %v", err)
		}

		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for RouteVNC to exit after normal close")
		}
	})
}

func TestWaitDistinguishesCallerCancelFromTimeout(t *testing.T) {
	// Nothing ever listens here, so wait can only exit via ctx.
	const dead = "http://127.0.0.1:1/session"

	t.Run("caller cancels", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		time.AfterFunc(100*time.Millisecond, cancel)

		err := wait(ctx, dead, time.Hour)
		if err == nil {
			t.Fatal("expected an error")
		}
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("want wrapped context.Canceled, got %v", err)
		}
		if strings.Contains(err.Error(), "does not respond in 1h0m0s") {
			t.Fatalf("error claims the full budget elapsed: %v", err)
		}
	})

	t.Run("own deadline expires", func(t *testing.T) {
		err := wait(context.Background(), dead, 150*time.Millisecond)
		if err == nil {
			t.Fatal("expected an error")
		}
		if errors.Is(err, context.Canceled) {
			t.Fatalf("want a timeout, not a cancellation: %v", err)
		}
		if !strings.Contains(err.Error(), "does not respond in") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestDevToolsRoutesMatchCreateAndAttach(t *testing.T) {
	var gotIPUUID, gotTail string
	var hits int
	record := func(w http.ResponseWriter, r *http.Request) {
		hits++
		gotIPUUID = chi.URLParam(r, "ipuuid")
		gotTail = chi.URLParam(r, "*")
	}

	router := chi.NewRouter()
	router.HandleFunc("/devtools/{ipuuid}", record)
	router.HandleFunc("/devtools/{ipuuid}/*", record)
	router.HandleFunc("/devtools/session/{ipuuid}", record)
	router.HandleFunc("/devtools/session/{ipuuid}/*", record)

	tests := []struct {
		path   string
		ipuuid string
		tail   string
	}{
		{path: "/devtools/abc", ipuuid: "abc"},
		{path: "/devtools/abc/json/version", ipuuid: "abc", tail: "json/version"},
		{path: "/devtools/session/abc", ipuuid: "abc"},
		{path: "/devtools/session/abc/devtools/browser/guid", ipuuid: "abc", tail: "devtools/browser/guid"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			hits, gotIPUUID, gotTail = 0, "", ""
			rw := httptestRecorder()
			router.ServeHTTP(rw, newRequestWithParams(http.MethodGet, tt.path, nil, nil, ""))

			if hits != 1 {
				t.Fatalf("expected the route to match, status %d", rw.status)
			}
			if gotIPUUID != tt.ipuuid || gotTail != tt.tail {
				t.Fatalf("params = ipuuid %q tail %q, want %q %q", gotIPUUID, gotTail, tt.ipuuid, tt.tail)
			}
		})
	}
}
