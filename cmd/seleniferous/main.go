package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/alcounit/seleniferous"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/utils/pointer"
)

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
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			logger := logrus.New()
			logger.Formatter = &logrus.JSONFormatter{}

			logger.Infof("starting seleniferous %s", buildVersion)

			hostname, err := os.Hostname()
			if err != nil {
				logger.Fatalf("can't get container hostname: %v", err)
			}

			logger.Infof("pod hostname %s", hostname)

			client, err := buildClusterClient()
			if err != nil {
				logger.Fatalf("failed to build kubernetes client: %v", err)
			}

			logger.Info("kubernetes client created")

			deleteFunc := func() {
				context := context.Background()
				client.CoreV1().Pods(namespace).Delete(context, hostname, metav1.DeleteOptions{
					GracePeriodSeconds: pointer.Int64Ptr(15),
				})
				defer logger.Infof("deleting pod %s", hostname)
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

			if err := srv.Shutdown(ctx); err != nil {
				logger.Fatalf("failed to stop", err)
			}
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
		os.Exit(1)
	}
}
