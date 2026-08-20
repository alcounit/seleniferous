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

	svc.CreateSession(rw, req)

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

	svc.CreateSession(rw, req)

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
		svc.CreateSession(rw, req)

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

		svc.CreateSession(rw, req)

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

		svc.CreateSession(rw, req)

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
		svc.CreateSession(rw, req)
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
		svc.CreateSession(rw, req)
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

	svc.ProxySession(rw, req)

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

		svc.ProxySession(rw, req)

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
		svc.ProxySession(rw, req)
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
		svc.ProxySession(rw, req)
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
		svc.ProxySession(rw, req)
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
		svc.ProxySession(rw, req)
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
		svc.ProxySession(rw, req)
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
			svc.ProxySession(httptestRecorder(), req)
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
		svc.ProxySession(rw, req)
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

	svc.ProxySession(rw, req)

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
		svc.ProxySession(rw, req)
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

	svc.ProxyPlaywright(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestProxyPlaywrightUnknownIPUUID(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodGet, "/playwright?ipuuid=other", nil, nil, "")
	rw := httptestRecorder()

	svc.ProxyPlaywright(rw, req)

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

	req := newRequestWithParams(http.MethodGet, "/playwright?ipuuid=fake", nil, nil, "")
	rw := httptestRecorder()

	svc.ProxyPlaywright(rw, req)

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

	req := newRequestWithParams(http.MethodGet, "/playwright?ipuuid=fake", nil, nil, "")
	rw := httptestRecorder()

	svc.ProxyPlaywright(rw, req)

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

	req := newRequestWithParams(http.MethodGet, "/playwright?ipuuid=fake", nil, nil, "")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	rw := &hijackResponseWriter{conn: serverConn, header: make(http.Header)}

	done := make(chan struct{})
	go func() {
		defer close(done)
		svc.ProxyPlaywright(rw, req)
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

	req := newRequestWithParams(http.MethodGet, "/playwright?ipuuid=fake", nil, nil, "")
	rw := httptestRecorder()

	svc.ProxyPlaywright(rw, req)

	if rw.status != http.StatusBadGateway && rw.status != http.StatusInternalServerError {
		t.Fatalf("expected proxy error status, got %d", rw.status)
	}
	if rec.hasEventType(EventTypeDeleted) {
		t.Fatal("unexpected delete event after a failed upstream dial")
	}
}

func TestProxyPlaywrightDoesNotNotifyOnInvalidIPUUID(t *testing.T) {
	for _, target := range []string{"/playwright", "/playwright?ipuuid=other"} {
		st := store.NewDefaultStore[string]()
		rec := &fakeBroadcaster{}
		svc := NewService(ServiceConfig{IPUUID: "fake", BrowserPort: "4444"}, st, session.NewManager(time.Second, nil), rec)

		rw := httptestRecorder()
		svc.ProxyPlaywright(rw, newRequestWithParams(http.MethodGet, target, nil, nil, ""))

		if rw.status != http.StatusBadRequest {
			t.Fatalf("expected status 400 for %s, got %d", target, rw.status)
		}
		if rec.hasEventType(EventTypeDeleted) {
			t.Fatalf("unexpected delete event for %s", target)
		}
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

	svc.CreateSession(rw, req)

	if rw.status != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", rw.status)
	}
}

func TestCreateSessionInvalidRequestBody(t *testing.T) {
	st := store.NewDefaultStore[string]()
	svc := NewService(ServiceConfig{}, st, session.NewManager(time.Second, nil), &fakeBroadcaster{})

	req := newRequestWithParams(http.MethodPost, "/session", bytes.NewBufferString("{invalid"), nil, "")
	rw := httptestRecorder()

	svc.CreateSession(rw, req)

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
	svc.ProxySession(rw, req)
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
