package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/alcounit/browser-service/pkg/broadcast"
	"github.com/alcounit/seleniferous/v2/internal"
	"github.com/alcounit/seleniferous/v2/pkg/session"
	"github.com/alcounit/seleniferous/v2/pkg/store"
	"github.com/alcounit/selenosis/v2/pkg/env"
	"github.com/alcounit/selenosis/v2/pkg/ipuuid"
	"github.com/alcounit/selenosis/v2/pkg/proxy/rule"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	logctx "github.com/alcounit/browser-controller/pkg/log"
)

func main() {

	zerolog.TimeFieldFormat = time.RFC3339
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	log := zerolog.New(os.Stdout).With().Timestamp().Logger()

	cfg, listenAddr, createTimeout, idleTimeout, err := loadConfig()
	if err != nil {
		log.Fatal().Err(err).Msg("failed to load app settings")
	}
	log.Info().Msg("application configuration loaded")

	broadcaster := broadcast.NewBroadcaster[internal.Event](10)
	mgr := session.NewManager(idleTimeout, func(sessionId string) {
		broadcaster.Broadcast(sessionIdleTimeout())
		log.Info().Str("sessionId", sessionId).Msg("session timed out")
	})
	store := store.NewDefaultStore()
	service := internal.NewService(cfg, store, mgr, broadcaster)

	router := chi.NewRouter()
	router.Use(func(next http.Handler) http.Handler {
		fn := func(rw http.ResponseWriter, req *http.Request) {

			selenosisReqId := req.Header.Get("Selenosis-Request-ID")
			logger := log.With().
				Str("method", req.Method).
				Str("path", req.URL.Path).
				Str("reqId", uuid.NewString()).
				Str("selenosisReqId", selenosisReqId).
				Logger()

			ctx := req.Context()
			ctx = logctx.IntoContext(ctx, logger)

			next.ServeHTTP(rw, req.WithContext(ctx))
		}
		return http.HandlerFunc(fn)
	})

	createTimeoutMiddleWare := waitFirstRequest(createTimeout, func() {
		broadcaster.Broadcast(sessionCreateTimeout())
	})
	router.With(createTimeoutMiddleWare).Post("/session", service.CreateSession)

	idleTimeoutMiddleWare := waitFirstRequest(createTimeout+idleTimeout, func() {
		broadcaster.Broadcast(sessionIdleTimeout())
	})
	router.With(idleTimeoutMiddleWare).Route("/session/{sessionId}", func(r chi.Router) {
		r.HandleFunc("/*", service.ProxySession)
	})

	router.Route("/selenosis/v1", func(r chi.Router) {
		r.Route("/proxy/{sessionId}/proxy", func(r chi.Router) {
			r.HandleFunc("/*", service.RouteHTTP)
		})
		r.HandleFunc("/vnc/{sessionId}", service.RouteVNC)
	})

	srv := &http.Server{
		Addr:    listenAddr,
		Handler: router,
	}

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		log.Info().Msgf("HTTP server listening %s", listenAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Err(err).Msg("HTTP server error")
			select {
			case stopCh <- syscall.SIGTERM:
			default:
			}
		}
	}()

	go func() {
		sub := broadcaster.Subscribe()
		defer broadcaster.Unsubscribe(sub)

		for event := range sub {
			if event.Type == internal.EventTypeError || event.Type == internal.EventTypeDeleted {
				log.Info().Interface("event", event).Msg("session timed out")
				select {
				case stopCh <- syscall.SIGTERM:
				default:
				}
				return
			}
		}
	}()

	<-stopCh
	log.Info().Msg("Shutting down HTTP server...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Fatal().Err(err).Msg("HTTP server shutdown error")
	}

	os.Exit(1)
}

func loadConfig() (internal.ServiceConfig, string, time.Duration, time.Duration, error) {
	var cfg internal.ServiceConfig

	addr := env.GetEnvOrDefault("LISTEN_ADDR", ":4445")
	cfg.BrowserPort = env.GetEnvOrDefault("BROWSER_PORT", "4444")

	createTimeout := env.GetEnvDurationOrDefault("SESSION_CREATE_TIMEOUT", 5*time.Minute)
	idleTimeout := env.GetEnvDurationOrDefault("SESSION_IDLE_TIMEOUT", 5*time.Minute)

	rules, err := rule.LoadRulesFromEnv("ROUTING_RULES")
	if err != nil {
		return internal.ServiceConfig{}, "", 0, 0, err
	}
	cfg.Rules = rules

	podIP, err := getPodIP()
	if err != nil {
		return cfg, "", createTimeout, idleTimeout, err
	}

	ipUUID, err := ipuuid.IPToUUID(podIP)
	if err != nil {
		return cfg, "", createTimeout, idleTimeout, err
	}
	cfg.IPUUID = ipUUID.String()

	if addr == "" {
		return cfg, "", createTimeout, idleTimeout,
			errors.New("LISTEN_ADDR must be provided")
	}

	if cfg.BrowserPort == "" {
		return cfg, "", createTimeout, idleTimeout,
			errors.New("BROWSER_PORT must be provided")
	}

	return cfg, addr, createTimeout, idleTimeout, nil
}

func getPodIP() (net.IP, error) {
	if podIP := os.Getenv("POD_IP"); podIP != "" {
		if ip := net.ParseIP(podIP); ip != nil {
			return ip, nil
		}
		return nil, errors.New("invalid POD_IP in environment")
	}

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				return ipnet.IP, nil
			}
		}
	}

	return nil, errors.New("no valid pod IP found")
}

func sessionCreateTimeout() internal.Event {
	return internal.Event{
		Type:      internal.EventTypeTimedout,
		Data:      "session creation timeout exceeded",
		Timestamp: time.Now(),
	}
}

func sessionIdleTimeout() internal.Event {
	return internal.Event{
		Type:      internal.EventTypeTimedout,
		Data:      "session idle timeout exceeded",
		Timestamp: time.Now(),
	}
}

func waitFirstRequest(deadline time.Duration, onTimeout func()) func(next http.Handler) http.Handler {
	var state int32

	timer := time.AfterFunc(deadline, func() {
		if atomic.CompareAndSwapInt32(&state, 0, 2) {
			onTimeout()
		}
	})

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if atomic.CompareAndSwapInt32(&state, 0, 1) {
				timer.Stop()
			}

			next.ServeHTTP(w, r)
		})
	}
}
