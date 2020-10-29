package seleniferous

import (
	"time"

	"github.com/sirupsen/logrus"
	"k8s.io/client-go/kubernetes"
)

//Config basic config
type Config struct {
	BrowserPort  string
	ProxyPath    string
	Hostname     string
	Namespace    string
	IddleTimeout time.Duration
	Logger       *logrus.Logger
	Client       *kubernetes.Clientset
}

//App ...
type App struct {
	browserPort  string
	proxyPath    string
	hostname     string
	namespace    string
	iddleTimeout time.Duration
	bucket       *storage
	logger       *logrus.Logger
	client       *kubernetes.Clientset
}

//New ...
func New(conf *Config) *App {
	return &App{
		browserPort:  conf.BrowserPort,
		proxyPath:    conf.ProxyPath,
		hostname:     conf.Hostname,
		namespace:    conf.Namespace,
		iddleTimeout: conf.IddleTimeout,
		bucket:       newStorage(),
		logger:       conf.Logger,
		client:       conf.Client,
	}
}
