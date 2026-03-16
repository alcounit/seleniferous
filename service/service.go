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

	errorHandler = func(rw http.ResponseWriter, req *http.Request, err error) {
		log := logctx.FromContext(req.Context())
		log.Err(err).Msg("proxy error")

		rw.WriteHeader(http.StatusInternalServerError)
	}

	localHost = "localhost"

	defaultSleepTimeout       = 3 * time.Second
	defaultSessionWaitTimeout = 10 * time.Second
)

type ServiceConfig struct {
	IPUUID               string
	BrowserPort          string
	Rules                []rule.Rule
	SessionRetryCount    int
	SessionRetryDelay    time.Duration
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
		writeErrorResponse(rw, http.StatusBadRequest, errSessionCreate)
		return
	}

	if req.Body == nil {
		log.Err(errSessionCreate).Msg("request body is nil")
		writeErrorResponse(rw, http.StatusBadRequest, errSessionCreate)
		return
	}

	body, err := io.ReadAll(req.Body)
	if err != nil {
		log.Err(errSessionCreate).Msg("failed to read request body")
		writeErrorResponse(rw, http.StatusBadRequest, errSessionCreate)
		return
	}

	var caps selenium.Capabilities
	if err := json.Unmarshal(body, &caps); err != nil {
		log.Err(err).Msg("failed to decode request body")
		writeErrorResponse(rw, http.StatusBadRequest, errSessionCreate)
		return
	}

	caps.RemoveSelenosisOptions()
	body, err = json.Marshal(caps)
	if err != nil {
		log.Err(err).Msg("failed to encode request body")
		writeErrorResponse(rw, http.StatusInternalServerError, errSessionCreate)
		return
	}

	url := &url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(localHost, s.config.BrowserPort),
		Path:   req.URL.Path,
	}

	if err := wait(url.String(), s.config.SessionCreateTimeout); err != nil {
		log.Err(err).Msg("browser service unavailable")
		writeErrorResponse(rw, http.StatusServiceUnavailable, err)
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
			log.Err(errSessionCreate).Msg("response body is empty, session not created")
			r.Body = io.NopCloser(bytes.NewReader(nil))
			notifyError(s.broadcaster, "response body is empty", errSessionCreate)
			return errSessionCreate
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Err(err).Msg("failed to read response body")
			notifyError(s.broadcaster, "failed to read response body", err)
			return err
		}
		r.Body.Close()

		var response selenium.Payload
		if err := json.Unmarshal(body, &response); err != nil {
			log.Err(err).Msg("failed to decode response body")
			notifyError(s.broadcaster, "failed to decode response body", err)
			return err
		}

		originalSessionId, ok := response.GetSessionId()
		if !ok {
			log.Err(errSessionNotFound).Msg("response sessionId not found")
			notifyError(s.broadcaster, "response sessionId not found", errSessionNotFound)
			return errSessionCreate
		}

		if ok := response.UpdateSessionId(s.config.IPUUID); !ok {
			log.Err(errSessionCreate).Msg("failed to update sessionId in response")
			notifyError(s.broadcaster, "failed to update sessionId in response", errSessionCreate)
			return errSessionCreate
		}

		if externalURLPresent {
			selenium.UpdateBiDiURL("ws", externalURL.Host, originalSessionId, s.config.IPUUID, response)
			selenium.UpdateChromeCDPURL("ws", externalURL.Host, originalSessionId, s.config.IPUUID, response)
		}

		body, err = json.Marshal(response)
		if err != nil {
			log.Err(err).Msg("failed to encode response body")
			notifyError(s.broadcaster, "failed to encode response body", err)
			return err
		}

		s.storeSessionId(originalSessionId)
		s.manager.Touch(s.config.IPUUID)

		log.Info().Str("originalSessionId", originalSessionId).Str("fakeSessionId", s.config.IPUUID).Msg("session id rewritten")

		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Del("Content-Length")

		log.Info().Str("sessionId", originalSessionId).Msg("session create response modified")

		return nil
	}

	transport := &retryTransport{
		MaxRetries: s.config.SessionRetryCount,
		Delay:      s.config.SessionRetryDelay,
	}

	rp := proxy.NewHTTPReverseProxy(
		proxy.WithTransport(transport),
		proxy.WithRequestModifier(requestModifier),
		proxy.WithResponseModifier(responseModifier),
		proxy.WithErrorHandler(errorHandler),
	)

	rp.ServeHTTP(rw, req)
}

func (s *Service) ProxySession(rw http.ResponseWriter, req *http.Request) {
	log := logctx.FromContext(req.Context())

	requestSessionId := chi.URLParam(req, "sessionId")
	originalSessionId, ok := s.getSessionId(requestSessionId)
	if !ok {
		log.Err(errSessionNotFound).Msg("unknown sessionId")
		writeErrorResponse(rw, http.StatusBadRequest, errSessionCreate)
		return
	}

	s.manager.Touch(requestSessionId)

	log.Info().Str("sessionId", requestSessionId).Msg("proxying session request")

	if proxy.IsWebSocketRequest(req) {
		resolver := func(r *http.Request) (*url.URL, error) {
			url := &url.URL{
				Scheme: "ws",
				Host:   net.JoinHostPort(localHost, s.config.BrowserPort),
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
			log.Info().Str("sessionId", requestSessionId).Msg("ws message received")
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

	reqModifier := func(r *http.Request) {
		if req.Method == http.MethodDelete && len(pathutils.Parse(req.URL.Path)) == 2 {

			time.AfterFunc(defaultSleepTimeout, func() {
				notifyDelete(s.broadcaster, "delete browser")
				log.Info().Msg("delete browser request")
			})
		} else {

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
			Host:   net.JoinHostPort(localHost, s.config.BrowserPort),
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

		log.Info().Str("sessionId", originalSessionId).Msg("session proxy response modified")

		return nil
	}

	rp := proxy.NewHTTPReverseProxy(
		proxy.WithRequestModifier(reqModifier),
		proxy.WithResponseModifier(responseModifier),
		proxy.WithErrorHandler(errorHandler),
	)

	rp.ServeHTTP(rw, req)
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
			Host:   net.JoinHostPort(localHost, s.config.BrowserPort),
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
		log.Info().Str("sessionId", ipUUID).Msg("ws message received")
	})

	onClose := proxy.WithOnClose(func() {
		time.AfterFunc(defaultSleepTimeout, func() {
			notifyDelete(s.broadcaster, "delete browser")
			log.Info().Str("sessionId", ipUUID).Msg("ws connection closed")
		})

	})

	retryDialer := proxy.WithRetryTimeout(s.config.SessionCreateTimeout)
	rp := proxy.NewWebSocketReverseProxy(resolver, onConnect, onMessage, onClose, retryDialer)
	rp.ServeHTTP(rw, req)
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

	addr := net.JoinHostPort(localHost, "5900")
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

func writeErrorResponse(rw http.ResponseWriter, status int, err error) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	json.NewEncoder(rw).Encode(map[string]string{"error": err.Error()})
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

type retryTransport struct {
	Base       http.RoundTripper
	MaxRetries int
	Delay      time.Duration
}

func (t *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	log := logctx.FromContext(req.Context())

	if t.Base == nil {
		t.Base = http.DefaultTransport
	}

	if err := wait(req.URL.String(), defaultSessionWaitTimeout); err != nil {
		return nil, err
	}

	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, err
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	var lastErr error
	for i := 0; i <= t.MaxRetries; i++ {
		if i > 0 {
			time.Sleep(t.Delay)
			if bodyBytes != nil {
				req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			}
		}

		resp, err := t.Base.RoundTrip(req)
		if err == nil {
			log.Info().Msg("roundtrip successful")
			return resp, nil
		}

		lastErr = err
		log.Warn().Err(err).Int("attempt", i+1).Int("maxAttempts", t.MaxRetries+1).Msg("roundtrip failed")
	}

	return nil, fmt.Errorf("all retries failed: %w", lastErr)
}

func wait(u string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		req, _ := http.NewRequest(http.MethodHead, u, nil)
		req.Close = true

		resp, err := http.DefaultClient.Do(req)
		if resp != nil {
			_ = resp.Body.Close()
		}

		if err == nil {
			return nil
		}

		time.Sleep(50 * time.Millisecond)
	}

	return fmt.Errorf("%s does not respond in %v", u, timeout)
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
