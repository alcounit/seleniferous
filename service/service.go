package service

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"sync"
	"time"

	logctx "github.com/alcounit/browser-controller/pkg/log"

	"github.com/alcounit/browser-service/pkg/broadcast"
	"github.com/alcounit/seleniferous/v2/pkg/pathutils"
	"github.com/alcounit/seleniferous/v2/pkg/session"
	"github.com/alcounit/seleniferous/v2/pkg/store"
	"github.com/alcounit/selenosis/v2/pkg/jsonrpc"
	"github.com/alcounit/selenosis/v2/pkg/proxy"
	"github.com/alcounit/selenosis/v2/pkg/proxy/rule"
	"github.com/alcounit/selenosis/v2/pkg/selenium"
	"github.com/go-chi/chi/v5"
	"github.com/gorilla/websocket"
)

var (
	errSessionCreate   = errors.New("failed to create a new browser session")
	errSessionNotFound = errors.New("sessionId not found")

	dialTCP = net.Dial

	defaultErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log := logctx.FromContext(req.Context())
		log.Err(err).Msg("proxy error")

		rw.WriteHeader(http.StatusInternalServerError)
	}

	mcpErrorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log := logctx.FromContext(req.Context())
		log.Err(err).Msg("mcp proxy error")
		jsonrpc.WriteError(rw, http.StatusInternalServerError, jsonrpc.InternalError, "Internal error")
	}

	loopbackAddr = "127.0.0.1"
	localhost    = "localhost"

	waitPollInterval  = 50 * time.Millisecond
	waitAttemptCutoff = 5 * time.Second
)

type ServiceConfig struct {
	IPUUID               string
	BrowserPort          string
	Rules                []rule.Rule
	SessionCreateTimeout time.Duration
}

type Service struct {
	store       store.Store[string]
	manager     *session.Manager
	broadcaster broadcast.Broadcaster[Event]
	config      ServiceConfig
}

func NewService(config ServiceConfig, store store.Store[string], mgr *session.Manager, broadcaster broadcast.Broadcaster[Event]) *Service {
	return &Service{
		store:       store,
		manager:     mgr,
		broadcaster: broadcaster,
		config:      config,
	}
}

func (s *Service) CreateSession(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	if s.store.Len() > 0 {
		log.Err(errSessionCreate).Msg("session already started")
		writeErrorResponse(rw, http.StatusBadRequest, selenium.ErrSessionNotCreated(errSessionCreate))
		return
	}

	s.manager.Touch(s.config.IPUUID)

	if req.Body == nil {
		log.Err(errSessionCreate).Msg("request body is nil")
		writeErrorResponse(rw, http.StatusBadRequest, selenium.ErrInvalidArgument(errSessionCreate))
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Err(errSessionCreate).Msg("failed to read request body")
		writeErrorResponse(rw, http.StatusBadRequest, selenium.ErrInvalidArgument(errSessionCreate))
		return
	}

	var caps selenium.Capabilities
	if err := json.Unmarshal(body, &caps); err != nil {
		log.Err(err).Msg("failed to decode request body")
		writeErrorResponse(rw, http.StatusBadRequest, selenium.ErrInvalidArgument(errSessionCreate))
		return
	}

	caps.RemoveSelenosisOptions()
	body, err = json.Marshal(caps)
	if err != nil {
		log.Err(err).Msg("failed to encode request body")
		writeErrorResponse(rw, http.StatusInternalServerError, selenium.ErrSessionNotCreated(errSessionCreate))
		return
	}

	url := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(loopbackAddr, s.config.BrowserPort),
		Path:   req.URL.Path,
	}

	if err := wait(req.Context(), url.String(), s.config.SessionCreateTimeout); err != nil {
		if errors.Is(err, context.Canceled) {
			log.Warn().Err(err).Msg("session create abandoned by caller")
		} else {
			log.Err(err).Msg("browser service unavailable")
		}
		writeErrorResponse(rw, http.StatusServiceUnavailable, selenium.Error("browser service unavailable", err))
		return
	}

	log.Info().Msg("proxying session create request")

	requestModifier := func(r *http.Request) {
		r.Host = url.Host
		r.URL = url

		r.Header.Set("Content-Type", "application/json")
		r.ContentLength = int64(len(body))
		r.Header.Del("Content-Length")
		r.Body = io.NopCloser(bytes.NewReader(body))

		log.Info().Str("browserAddr", r.URL.String()).Msg("session create request modified")
	}

	externalURL, externalURLPresent := externalBaseURLFromHeaders(req.Header)
	responseModifier := func(r *http.Response) error {

		if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
			log.Err(errSessionCreate).Int("statusCode", r.StatusCode).Msg("unexpected status code, session not created")
			notifyError(s.broadcaster, "unexpected status code", errSessionCreate)
			return errSessionCreate
		}

		if r.Body == nil {
			log.Err(errSessionCreate).Int("statusCode", r.StatusCode).Msg("response body is empty, session not created")
			r.Body = io.NopCloser(bytes.NewReader(nil))
			notifyError(s.broadcaster, "response body is empty", errSessionCreate)
			return errSessionCreate
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Err(err).Int("statusCode", r.StatusCode).Msg("failed to read response body")
			notifyError(s.broadcaster, "failed to read response body", err)
			return err
		}
		r.Body.Close()

		var response selenium.Payload
		if err := json.Unmarshal(body, &response); err != nil {
			log.Err(err).Int("statusCode", r.StatusCode).Msg("failed to decode response body")
			notifyError(s.broadcaster, "failed to decode response body", err)
			return err
		}

		originalSessionId, ok := response.GetSessionId()
		if !ok {
			log.Err(errSessionNotFound).Int("statusCode", r.StatusCode).Msg("response sessionId not found")
			notifyError(s.broadcaster, "response sessionId not found", errSessionNotFound)
			return errSessionCreate
		}

		if ok := response.UpdateSessionId(s.config.IPUUID); !ok {
			log.Err(errSessionCreate).Int("statusCode", r.StatusCode).Msg("failed to update sessionId in response")
			notifyError(s.broadcaster, "failed to update sessionId in response", errSessionCreate)
			return errSessionCreate
		}

		if externalURLPresent {
			selenium.UpdateBiDiURL("ws", externalURL.Host, originalSessionId, s.config.IPUUID, response)
			selenium.UpdateChromeCDPURL("ws", externalURL.Host, originalSessionId, s.config.IPUUID, response)
		}

		body, err = json.Marshal(response)
		if err != nil {
			log.Err(err).Int("statusCode", r.StatusCode).Msg("failed to encode response body")
			notifyError(s.broadcaster, "failed to encode response body", err)
			return err
		}

		s.storeSessionId(originalSessionId)
		s.manager.Touch(s.config.IPUUID)

		log.Info().Int("statusCode", r.StatusCode).Str("originalSessionId", originalSessionId).Str("fakeSessionId", s.config.IPUUID).Msg("session id rewritten")

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Del("Content-Length")

		log.Info().Int("statusCode", r.StatusCode).Str("sessionId", originalSessionId).Msg("session create response modified")

		return nil
	}

	rp := proxy.NewHTTPReverseProxy(
		proxy.WithRequestModifier(requestModifier),
		proxy.WithResponseModifier(responseModifier),
		proxy.WithErrorHandler(defaultErrorHandler),
	)

	rp.ServeHTTP(rw, req)
}

func (s *Service) ProxySession(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	requestSessionId := chi.URLParam(req, "sessionId")
	originalSessionId, ok := s.getSessionId(requestSessionId)
	if !ok {
		log.Err(errSessionNotFound).Msg("unknown sessionId")
		writeErrorResponse(rw, http.StatusBadRequest, selenium.ErrInvalidSessionId(errSessionNotFound))
		return
	}

	s.manager.Touch(requestSessionId)

	log.Info().Str("sessionId", requestSessionId).Msg("proxying session request")

	if proxy.IsWebSocketRequest(req) {
		resolver := func(r *http.Request) (*url.URL, error) {
			url := &url.URL{
				Scheme: "ws",
				Host:   net.JoinHostPort(loopbackAddr, s.config.BrowserPort),
				Path: pathutils.Replace(req.URL.Path, map[string]string{
					s.config.IPUUID: originalSessionId,
				}),
			}
			return url, nil
		}

		onConnect := proxy.WithOnConnect(func() {
			s.manager.Touch(requestSessionId)
			log.Info().Str("sessionId", requestSessionId).Msg("ws connection established")
		})

		onMessage := proxy.WithOnMessage(func() {
			s.manager.Touch(requestSessionId)
			log.Debug().Str("sessionId", requestSessionId).Msg("ws message received")
		})

		onClose := proxy.WithOnClose(func() {
			s.manager.Touch(requestSessionId)
			log.Info().Str("sessionId", requestSessionId).Msg("ws connection closed")
		})

		log.Info().Str("sessionId", requestSessionId).Msg("proxying websocket request")

		rp := proxy.NewWebSocketReverseProxy(resolver, onConnect, onMessage, onClose)
		rp.ServeHTTP(rw, req)
		return
	}

	// A DELETE on the session itself tears down the browser, after which this
	// sidecar has nothing left to serve and shuts itself down.
	isSessionDelete := req.Method == http.MethodDelete && len(pathutils.Parse(req.URL.Path)) == 2

	reqModifier := func(r *http.Request) {
		if !isSessionDelete {

			if r.Body != nil {
				body, err := io.ReadAll(r.Body)
				_ = r.Body.Close()
				r.Body = io.NopCloser(bytes.NewReader(body))
				if err != nil {
					return
				}

				origBody := body

				var request selenium.Payload
				if err := json.Unmarshal(body, &request); err == nil {
					if _, ok := request.GetSessionId(); ok {
						if request.UpdateSessionId(originalSessionId) {
							if body, err = json.Marshal(request); err == nil {
								r.Header.Set("Content-Type", "application/json")
								r.ContentLength = int64(len(body))
								r.Header.Del("Content-Length")
							} else {
								body = origBody
							}
						} else {
							body = origBody
						}
					}
				}

				r.Body = io.NopCloser(bytes.NewReader(body))
			}

		}

		r.URL = &url.URL{
			Scheme: "http",
			Host:   net.JoinHostPort(loopbackAddr, s.config.BrowserPort),
			Path: pathutils.Replace(req.URL.Path, map[string]string{
				s.config.IPUUID: originalSessionId,
			}),
		}
		r.Host = r.URL.Host

		log.Info().Str("sessionId", requestSessionId).Str("browserAddr", r.URL.String()).Msg("session proxy request modified")
	}

	responseModifier := func(r *http.Response) error {
		if r.Body == nil {
			r.Body = io.NopCloser(bytes.NewReader(nil))
			return nil
		}

		if body, err := io.ReadAll(r.Body); err == nil {
			r.Body.Close()

			var response selenium.Payload
			if err = json.Unmarshal(body, &response); err == nil {
				if _, ok := response.GetSessionId(); ok {
					if ok := response.UpdateSessionId(s.config.IPUUID); ok {
						if body, err = json.Marshal(response); err == nil {
							r.ContentLength = int64(len(body))
							r.Header.Set("Content-Type", "application/json")
							r.Header.Del("Content-Length")
						}
					}

				}
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
		}

		log.Info().Int("statusCode", r.StatusCode).Str("sessionId", originalSessionId).Msg("session proxy response modified")

		return nil
	}

	rp := proxy.NewHTTPReverseProxy(
		proxy.WithRequestModifier(reqModifier),
		proxy.WithResponseModifier(responseModifier),
		proxy.WithErrorHandler(defaultErrorHandler),
	)

	rp.ServeHTTP(rw, req)

	// Safe to shut down now: the client has its DELETE response.
	if isSessionDelete {
		notifyDelete(s.broadcaster, "delete browser")
		log.Info().Msg("delete browser request")
	}
}

func (s *Service) ProxyPlaywright(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	ipUUID := req.URL.Query().Get("ipuuid")
	if ipUUID == "" {
		log.Error().Msg("missing required url param: ipuuid")
		http.Error(rw, "missing ipuuid", http.StatusBadRequest)
		return
	}

	if ipUUID != s.config.IPUUID {
		log.Err(errSessionNotFound).Msg("unknown sessionId")
		http.Error(rw, "unknown ipuuid", http.StatusBadRequest)
		return
	}

	if _, ok := s.store.Get(ipUUID); !ok {
		s.storeSessionId(ipUUID)
		s.manager.Touch(ipUUID)
	}

	log.Info().Str("sessionId", ipUUID).Msg("playwright proxy request")

	resolver := func(r *http.Request) (*url.URL, error) {
		url := &url.URL{
			Scheme: "ws",
			Host:   net.JoinHostPort(loopbackAddr, s.config.BrowserPort),
			Path:   "/",
		}
		return url, nil
	}

	onConnect := proxy.WithOnConnect(func() {
		s.manager.Touch(ipUUID)
		log.Info().Str("sessionId", ipUUID).Msg("ws connection established")
	})

	onMessage := proxy.WithOnMessage(func() {
		s.manager.Touch(ipUUID)
		log.Debug().Str("sessionId", ipUUID).Msg("ws message received")
	})

	var isSessionClosed bool
	onClose := proxy.WithOnClose(func() {
		isSessionClosed = true
		log.Info().Str("sessionId", ipUUID).Msg("ws connection closed")

	})

	retryDialer := proxy.WithWSDialRetry(proxy.DialRetry{Timeout: s.config.SessionCreateTimeout})
	rp := proxy.NewWebSocketReverseProxy(resolver, onConnect, onMessage, onClose, retryDialer)
	rp.ServeHTTP(rw, req)

	if isSessionClosed {
		notifyDelete(s.broadcaster, "delete browser")
	}
}

func (s *Service) ProxyMcp(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	sessionId := req.Header.Get("Mcp-Session-Id")
	if sessionId == "" && req.Method == http.MethodPost {

		if s.store.Len() > 0 {
			log.Err(errSessionCreate).Msg("mcp session already started")
			jsonrpc.WriteError(rw, http.StatusBadRequest, jsonrpc.InvalidRequest, "Invalid Request: Server already initialized")
			return
		}

		s.manager.Touch(s.config.IPUUID)

		url := &url.URL{
			Scheme:   "http",
			Host:     net.JoinHostPort(loopbackAddr, s.config.BrowserPort),
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}

		if err := wait(req.Context(), url.String(), s.config.SessionCreateTimeout); err != nil {
			if errors.Is(err, context.Canceled) {
				log.Warn().Err(err).Msg("mcp session create abandoned by caller")
			} else {
				log.Err(err).Msg("browser service unavailable")
			}
			jsonrpc.WriteError(rw, http.StatusServiceUnavailable, jsonrpc.InternalError, "Internal error: browser mcp server unavailable")
			return
		}

		reqModifier := func(r *http.Request) {
			r.URL = url
			r.Host = net.JoinHostPort(localhost, s.config.BrowserPort)
			log.Info().Msg("mcp session create request modified")
		}

		respModifier := func(r *http.Response) error {
			if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
				log.Err(errSessionCreate).Int("statusCode", r.StatusCode).Msg("unexpected status code, mcp session not created")
				notifyError(s.broadcaster, "unexpected status code", errSessionCreate)
				return errSessionCreate
			}

			sessionId := s.config.IPUUID
			if mcpSessionId := r.Header.Get("Mcp-Session-Id"); mcpSessionId != "" {
				sessionId = mcpSessionId
			}

			s.storeSessionId(sessionId)

			r.Header.Set("Mcp-Session-Id", s.config.IPUUID)
			log.Info().Int("statusCode", r.StatusCode).Msg("mcp session create response modified")
			return nil
		}

		rp := proxy.NewHTTPReverseProxy(
			proxy.WithRequestModifier(reqModifier),
			proxy.WithResponseModifier(respModifier),
			proxy.WithErrorHandler(mcpErrorHandler),
		)

		rp.ServeHTTP(rw, req)
		return
	}

	if sessionId == "" {
		log.Err(errSessionNotFound).Msg("missing Mcp-Session-Id header")
		jsonrpc.WriteError(rw, http.StatusBadRequest, jsonrpc.InvalidParams, "Bad Request: Mcp-Session-Id header is required")
		return
	}

	if sessionId != s.config.IPUUID {
		log.Err(errSessionNotFound).Str("sessionId", sessionId).Msg("unknown mcp sessionId")
		jsonrpc.WriteError(rw, http.StatusNotFound, jsonrpc.SessionNotFound, "Session not found")
		return
	}

	originalSessionId, ok := s.getSessionId(sessionId)
	if !ok {
		log.Err(errSessionNotFound).Str("sessionId", sessionId).Msg("mcp sessionId not found")
		jsonrpc.WriteError(rw, http.StatusNotFound, jsonrpc.SessionNotFound, "Session not found")
		return
	}

	s.manager.Touch(s.config.IPUUID)

	log.Info().Str("sessionId", sessionId).Msg("proxying mcp request")

	isSessionDelete := req.Method == http.MethodDelete

	reqModifier := func(r *http.Request) {
		r.Header.Set("Mcp-Session-Id", originalSessionId)
		if sessionId == originalSessionId {
			r.Header.Del("Mcp-Session-Id")
		}

		r.URL = &url.URL{
			Scheme:   "http",
			Host:     net.JoinHostPort(loopbackAddr, s.config.BrowserPort),
			Path:     "/mcp",
			RawQuery: req.URL.RawQuery,
		}
		r.Host = net.JoinHostPort(localhost, s.config.BrowserPort)
		log.Info().Str("sessionId", sessionId).Msg("mcp request modified")
	}

	respModifier := func(r *http.Response) error {
		r.Header.Set("Mcp-Session-Id", s.config.IPUUID)
		log.Info().Int("statusCode", r.StatusCode).Str("sessionId", sessionId).Msg("mcp response modified")
		return nil
	}

	rp := proxy.NewHTTPReverseProxy(
		proxy.WithRequestModifier(reqModifier),
		proxy.WithResponseModifier(respModifier),
		proxy.WithErrorHandler(mcpErrorHandler),
	)
	rp.ServeHTTP(rw, req)

	if isSessionDelete {
		notifyDelete(s.broadcaster, "delete browser")
		log.Info().Str("sessionId", sessionId).Msg("mcp session deleted")
	}
}

func (s *Service) RouteHTTP(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	sessionId := chi.URLParam(req, "sessionId")
	if sessionId == "" {
		log.Error().Msg("missing required url param: sessionId")
		http.Error(rw, "missing required url param: sessionId", http.StatusInternalServerError)
		return
	}

	if _, ok := s.store.Get(sessionId); !ok {
		log.Error().Msg("unknown sessionId")
		http.Error(rw, "unknown sessionId", http.StatusInternalServerError)
		return
	}

	rest := chi.RouteContext(req.Context()).RoutePath
	if rest == "" || rest == "/" {
		log.Error().Msg("missing required url param: path after sessionId is required")
		http.Error(rw, "missing required url param: path after sessionId is required", http.StatusInternalServerError)
		return
	}

	var proxyrule rule.Rule
	for _, rl := range s.config.Rules {
		if rl.RuleMatch(req.URL.Path) {
			proxyrule = rl
			break
		}
	}

	if proxyrule.IsEmpty() {
		log.Error().Msg("no matching proxy rule found")
		http.Error(rw, "no matching proxy rule", http.StatusNotFound)
		return
	}

	reqModifier := func(r *http.Request) {
		r.URL.Scheme = "http"
		r.URL.Host = proxyrule.Target

		newPath := rule.SafeRewrite(proxyrule, req.URL.Path)
		r.URL.Path = path.Clean(newPath)

		log.Info().
			Str("modifiedPath", r.URL.Path).
			Str("originalPath", req.URL.Path).
			Str("target", proxyrule.Target).
			Str("sessionId", sessionId).
			Msg("http proxy request modified")
	}

	log.Info().Msg("proxying http proxy request to a browser")

	rp := proxy.NewHTTPReverseProxy(proxy.WithRequestModifier(reqModifier))
	rp.ServeHTTP(rw, req)
}

func (s *Service) RouteVNC(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	sessionId := chi.URLParam(req, "sessionId")
	if sessionId == "" {
		log.Error().Msg("missing required url param: sessionId")
		http.Error(rw, "missing required url param: sessionId", http.StatusInternalServerError)
		return
	}

	if sessionId != s.config.IPUUID {
		if _, ok := s.store.Get(sessionId); !ok {
			log.Error().Str("sessionId", sessionId).Interface("list", s.store.List()).Msg("unknown sessionId")
			http.Error(rw, "unknown sessionId", http.StatusInternalServerError)
			return
		}
	}

	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool { return true },
	}

	wsconn, err := upgrader.Upgrade(rw, req, nil)
	if err != nil {
		log.Err(err).Msg("ws upgrade failed")
		return
	}
	defer wsconn.Close()

	addr := net.JoinHostPort(loopbackAddr, "5900")
	conn, err := dialTCP("tcp", addr)
	if err != nil {
		log.Err(err).Msg("vnc tcp connection failed")
		return
	}
	defer conn.Close()

	ctx, cancel := context.WithCancel(req.Context())
	defer cancel()

	var (
		wg       sync.WaitGroup
		firstErr error
		once     sync.Once
	)

	setErr := func(err error) {
		once.Do(func() {
			firstErr = err
			cancel()
		})
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		<-ctx.Done()
		_ = conn.SetDeadline(time.Now())
		_ = wsconn.SetReadDeadline(time.Now())
	}()

	log.Info().Str("sessionId", sessionId).Msg("proxying vnc request")

	wg.Add(2)

	go func() {
		defer wg.Done()
		for {
			mt, data, err := wsconn.ReadMessage()
			if err != nil {
				setErr(err)
				return
			}
			if mt == websocket.BinaryMessage {
				if _, err := conn.Write(data); err != nil {
					setErr(err)
					return
				}
			}
		}
	}()

	go func() {
		defer wg.Done()
		buf := make([]byte, 32*1024)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				setErr(err)
				return
			}
			if err := wsconn.WriteMessage(websocket.BinaryMessage, buf[:n]); err != nil {
				setErr(err)
				return
			}
		}
	}()

	wg.Wait()
	err = firstErr
	if websocket.IsCloseError(err,
		websocket.CloseNormalClosure,
		websocket.CloseGoingAway,
	) {
		log.Info().Msg("client disconnected")
	} else {
		log.Err(err).Msg("vnc proxy error")
	}

}

func (s *Service) storeSessionId(val string) {
	s.store.Set(s.config.IPUUID, val)
}

func (s *Service) getSessionId(key string) (string, bool) {
	str, ok := s.store.Get(key)
	if !ok {
		return "", false
	}

	return str, ok
}

func writeErrorResponse(rw http.ResponseWriter, status int, err *selenium.SeleniumError) {
	selenium.WriteError(rw, status, err)
}

func notifyError(broadcaster broadcast.Broadcaster[Event], source string, err error) {
	broadcaster.Broadcast(Event{
		Type:      EventTypeError,
		Data:      fmt.Sprintf("%s: %s", source, err.Error()),
		Timestamp: time.Now(),
	})
}

func notifyDelete(broadcaster broadcast.Broadcaster[Event], source string) {
	broadcaster.Broadcast(Event{
		Type:      EventTypeDeleted,
		Data:      source,
		Timestamp: time.Now(),
	})
}

func wait(ctx context.Context, u string, timeout time.Duration) error {
	started := time.Now()
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	for {
		if probe(ctx, u) == nil {
			return nil
		}

		select {
		case <-ctx.Done():
			// A caller hanging up ends the wait too, so say which happened and how long
			// we actually waited - reporting the budget implies a browser that never came up.
			waited := time.Since(started).Round(time.Millisecond)
			if !errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return fmt.Errorf("%s abandoned after %v: %w", u, waited, ctx.Err())
			}
			return fmt.Errorf("%s does not respond in %v", u, waited)
		case <-time.After(waitPollInterval):
		}
	}
}

func probe(ctx context.Context, u string) error {
	attemptCutoff := waitAttemptCutoff
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < attemptCutoff {
			attemptCutoff = remaining
		}
	}

	if attemptCutoff <= 0 {
		return context.DeadlineExceeded
	}

	ctx, cancel := context.WithTimeout(ctx, attemptCutoff)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodHead, u, nil)
	if err != nil {
		return err
	}
	req.Close = true

	resp, err := http.DefaultClient.Do(req)
	if resp != nil {
		_ = resp.Body.Close()
	}
	return err
}

func externalBaseURLFromHeaders(h http.Header) (*url.URL, bool) {
	raw := h.Get("X-Selenosis-External-URL")
	if raw == "" {
		return nil, false
	}

	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, false
	}

	return u, true
}
