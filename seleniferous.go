package seleniferous

import (
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

//Config basic config
type Config struct {
	BrowserPort     string
	ProxyPath       string
	Hostname        string
	Namespace       string
	IdleTimeout     time.Duration
	ShutdownTimeout time.Duration
	Storage         *Storage
	Logger          *logrus.Logger
	Client          *kubernetes.Clientset
}

//App ...
type App struct {
	browserPort     string
	proxyPath       string
	hostname        string
	namespace       string
	idleTimeout     time.Duration
	shutdownTimeout time.Duration
	bucket          *Storage
	logger          *logrus.Logger
	client          *kubernetes.Clientset
}

//New ...
func New(conf *Config) *App {
	return &App{
		browserPort:     conf.BrowserPort,
		proxyPath:       conf.ProxyPath,
		hostname:        conf.Hostname,
		namespace:       conf.Namespace,
		idleTimeout:     conf.IdleTimeout,
		shutdownTimeout: conf.ShutdownTimeout,
		bucket:          conf.Storage,
		logger:          conf.Logger,
		client:          conf.Client,
	}
}
