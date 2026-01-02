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
	"github.com/alcounit/seleniferous/internal"
	"github.com/alcounit/seleniferous/pkg/session"
	"github.com/alcounit/seleniferous/pkg/store"
	"github.com/alcounit/selenosis/pkg/env"
	"github.com/alcounit/selenosis/pkg/ipuuid"
	"github.com/alcounit/selenosis/pkg/proxy/rule"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/rs/zerolog"

	logctx "github.com/alcounit/browser-controller/pkg/log"
)

<<<<<<< HEAD
var buildVersion = "HEAD"

func command() *cobra.Command {

	var (
		listhenPort     string
		browserPort     string
		proxyPath       string
		namespace       string
		idleTimeout     time.Duration
		shutdownTimeout time.Duration
		shuttingDown    bool
	)

	cmd := &cobra.Command{
		Use:   "seleniferous",
		Short: "seleniferous is a sidecar proxy for selenosis",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error
			logger := logrus.New()
			logger.Formatter = &logrus.JSONFormatter{}

			logger.Infof("starting seleniferous %s", buildVersion)

			hostname, err := os.Hostname()
			if err != nil {
				logger.Errorf("can't get container hostname: %v", err)
			} else {
				hostname = os.Getenv("HOSTNAME")
			}

			logger.Infof("pod hostname %s", hostname)

			client, err := buildClusterClient()
			if err != nil {
				logger.Errorf("failed to build kubernetes client: %v", err)
				return err
			}

			logger.Info("kubernetes client created")

			deleteFunc := func() {
				context := context.Background()
				err := client.CoreV1().Pods(namespace).Delete(context, hostname, metav1.DeleteOptions{
					GracePeriodSeconds: pointer.Int64Ptr(15),
				})
				defer logger.WithError(err).Infof("deleting pod %s", hostname)
			}
			defer deleteFunc()

			quit := make(chan error, 1)
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

			storage := seleniferous.NewStorage()
			app := seleniferous.New(&seleniferous.Config{
				BrowserPort:     browserPort,
				ProxyPath:       proxyPath,
				Hostname:        hostname,
				Namespace:       namespace,
				IdleTimeout:     idleTimeout,
				ShutdownTimeout: shutdownTimeout,
				Storage:         storage,
				Logger:          logger,
				Client:          client,
				Quit:            quit,
			})

			router := mux.NewRouter()
			router.HandleFunc("/wd/hub/session", app.HandleSession).Methods(http.MethodPost)
			router.PathPrefix("/wd/hub/session/{sessionId}").HandlerFunc(app.HandleProxy)
			router.PathPrefix("/devtools/{sessionId}").HandlerFunc(app.HandleDevTools)
			router.PathPrefix("/download/{sessionId}").HandlerFunc(app.HandleDownload)
			router.PathPrefix("/clipboard/{sessionId}").HandlerFunc(app.HandleClipboard)
			router.PathPrefix("/status").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if shuttingDown {
					w.WriteHeader(http.StatusBadGateway)
				}
				w.WriteHeader(http.StatusOK)
			})

			srv := &http.Server{
				Addr:    net.JoinHostPort("", listhenPort),
				Handler: router,
			}

			go func() {
				quit <- srv.ListenAndServe()
			}()

			go func() {
				timeout := time.After(idleTimeout)
				ticker := time.Tick(500 * time.Millisecond)
			loop:
				for {
					select {
					case <-timeout:
						shuttingDown = true
						logger.Warn("session wait timeout exceeded")
						quit <- errors.New("new session request timeout")
						break loop
					case <-ticker:
						if storage.IsEmpty() {
							break
						}
						break loop
					}
				}
			}()

			select {
			case err := <-quit:
				logger.Infof("stopping seleniferous: %v", err)
			case sig := <-sigs:
				logger.Warnf("stopping seleniferous: %s", sig.String())
			}

			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()

			if err = srv.Shutdown(ctx); err != nil {
				logger.Errorf("failed to stop", err)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&listhenPort, "listhen-port", "4445", "port to use for incomming requests")
	cmd.Flags().StringVar(&browserPort, "browser-port", "4444", "browser port")
	cmd.Flags().StringVar(&proxyPath, "proxy-default-path", "/session", "path used by handler")
	cmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 120*time.Second, "time in seconds for idle session")
	cmd.Flags().StringVar(&namespace, "namespace", "selenosis", "kubernetes namespace")
	cmd.Flags().DurationVar(&shutdownTimeout, "graceful-shutdown-timeout", 15*time.Second, "time in seconds  gracefull shutdown timeout")

	cmd.Flags().SortFlags = false

	return cmd
}

func buildClusterClient() (*kubernetes.Clientset, error) {
	conf, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to build cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(conf)
	if err != nil {
		return nil, fmt.Errorf("failed to build client: %v", err)
	}

	return clientset, nil
}

func main() {
	if err := command().Execute(); err != nil {
		fmt.Printf("err: %v", err)
=======
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
>>>>>>> rewrite-v2
	}
}
