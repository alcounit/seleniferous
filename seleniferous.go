package seleniferous

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var (
	listhenPort string
	handlerPath string
	idleTimeout time.Duration
	namespace   string
	serviceName string
	hostname    string
	bucket      *storage
	logger      *logrus.Logger
	client      *kubernetes.Clientset
)

func command() *cobra.Command {

	cmd := &cobra.Command{
		Use:   "seleniferous",
		Short: "seleniferous is a sidecar proxy for selenosis",
		Run: func(cmd *cobra.Command, args []string) {

			var err error
			context := context.Background()

			logger := logrus.New()

			logger.Formatter = &logrus.JSONFormatter{}

			hostname, _ = os.Hostname()
			bucket = newStorage()

			logger.Infof("starting seleniferous sidecar proxy")

			client, err = buildClusterClient()
			if err != nil {
				logger.Fatalf("failed to build kubernetes client: %v", err)
			}

			_, err = client.CoreV1().Namespaces().Get(context, namespace, metav1.GetOptions{})
			if err != nil {
				logger.Fatalf("failed to get namespace: %s: %v", namespace, err)
			}

			_, err = client.CoreV1().Services(namespace).Get(context, serviceName, metav1.GetOptions{})
			if err != nil {
				logger.Fatalf("failed to get service: %s: %v", serviceName, err)
			}

			logger.Info("kubernetes client created")

			router := mux.NewRouter()
			router.HandleFunc("/wd/hub/session", handleSession).Methods(http.MethodPost)
			router.PathPrefix("/wd/hub/session/{sessionId}").HandlerFunc(handleProxy)

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
			}

		},
	}

	cmd.Flags().StringVar(&listhenPort, "listhen-port", "4445", "port to use for incomming requests")
	cmd.Flags().StringVar(&handlerPath, "handlers-default-path", "/session", "path used by handler")
	cmd.Flags().DurationVar(&idleTimeout, "idle-timeout", 120*time.Second, "time in seconds that a session will be iddling before termination")
	cmd.Flags().StringVar(&namespace, "namespace", "selenosis", "kubernetes namespace")
	cmd.Flags().StringVar(&serviceName, "service-name", "selenosis", "kubernetes service name for browsers")
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

//Run used to run seleniferous
func Run() error {
	return command().Execute()
}
