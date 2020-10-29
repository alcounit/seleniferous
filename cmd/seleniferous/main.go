package main

import (
	"context"
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
)

func command() *cobra.Command {

	var (
		listhenPort  string
		browserPort  string
		proxyPath    string
		iddleTimeout time.Duration
		namespace    string
	)

	cmd := &cobra.Command{
		Use:   "seleniferous",
		Short: "seleniferous is a sidecar proxy for selenosis",
		Run: func(cmd *cobra.Command, args []string) {
			var err error
			context := context.Background()

			logger := logrus.New()
			logger.Formatter = &logrus.JSONFormatter{}

			hostname, err := os.Hostname()
			if err != nil {
				logger.Fatalf("can't get container hostname: %v", err)
			}

			logger.Infof("starting seleniferous")

			client, err := buildClusterClient()
			if err != nil {
				logger.Fatalf("failed to build kubernetes client: %v", err)
			}

			_, err = client.CoreV1().Namespaces().Get(context, namespace, metav1.GetOptions{})
			if err != nil {
				logger.Fatalf("failed to get namespace: %s: %v", namespace, err)
			}

			logger.Info("kubernetes client created")

			app := seleniferous.New(&seleniferous.Config{
				BrowserPort:  browserPort,
				ProxyPath:    proxyPath,
				Hostname:     hostname,
				Namespace:    namespace,
				IddleTimeout: iddleTimeout,
				Logger:       logger,
				Client:       client,
			})

			router := mux.NewRouter()
			router.HandleFunc("/wd/hub/session", app.HandleSession).Methods(http.MethodPost)
			router.PathPrefix("/wd/hub/session/{sessionId}").HandlerFunc(app.HandleProxy)

			srv := &http.Server{
				Addr:    net.JoinHostPort("", listhenPort),
				Handler: router,
			}

			stop := make(chan os.Signal)
			signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

			e := make(chan error)
			go func() {
				e <- srv.ListenAndServe()
			}()

			select {
			case err := <-e:
				logger.Fatalf("failed to start: %v", err)
			case <-stop:
				logger.Warn("stopping seleniferous")
			}
		},
	}

	cmd.Flags().StringVar(&listhenPort, "listhen-port", "4445", "port to use for incomming requests")
	cmd.Flags().StringVar(&browserPort, "browser-port", "4444", "browser port")
	cmd.Flags().StringVar(&proxyPath, "proxy-default-path", "/session", "path used by handler")
	cmd.Flags().DurationVar(&iddleTimeout, "iddle-timeout", 120*time.Second, "time in seconds for iddling session")
	cmd.Flags().StringVar(&namespace, "namespace", "selenosis", "kubernetes namespace")

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
