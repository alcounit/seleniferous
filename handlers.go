package seleniferous

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/pointer"
)

var (
	httpClient = &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	ports = struct {
		Devtools, Fileserver, Clipboard string
	}{
		Devtools:   "7070",
		Fileserver: "8080",
		Clipboard:  "9090",
	}
)

type sess struct {
	url string
	id  string
}

type req struct {
	*http.Request
}

func (r req) buildURL(hostPort, sessionID string) *sess {
	host, port, _ := net.SplitHostPort(hostPort)

	return &sess{
		url: fmt.Sprintf("http://%s/wd/hub/session/%s", net.JoinHostPort(host, port), sessionID),
		id:  sessionID,
	}
}

func (s sess) delete() error {
	r, err := http.NewRequest(http.MethodDelete, s.url, nil)
	if err != nil {
		return fmt.Errorf("delete request failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := httpClient.Do(r.WithContext(ctx))
	if resp != nil {
		defer resp.Body.Close()
	}

	if err == nil && resp.StatusCode == http.StatusOK {
		return nil
	}

	if err != nil {
		return fmt.Errorf("delete request failed: %v", err)
	}

	return nil
}

//HandleSession ...
func (app *App) HandleSession(w http.ResponseWriter, r *http.Request) {

	logger := app.logger.WithFields(logrus.Fields{
		"request_id": uuid.New(),
		"request":    fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		"request_by": r.Header.Get("X-Forwarded-Selenosis"),
	})

	done := make(chan func())

	go func() {
		(<-done)()
	}()

	cancel := func() {}

	defer func() {
		done <- cancel
	}()

	cancelFunc := func() {
		context := context.Background()
		app.client.CoreV1().Pods(app.namespace).Delete(context, app.hostname, metav1.DeleteOptions{
			GracePeriodSeconds: pointer.Int64Ptr(15),
		})
	}

	(&httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host, r.URL.Path = net.JoinHostPort(app.hostname, app.browserPort), app.proxyPath

			go func() {
				<-r.Context().Done()

				cancel = cancelFunc
			}()

			logger.Info("new session request")
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			w.WriteHeader(http.StatusBadGateway)
		},
		ModifyResponse: func(r *http.Response) error {
			var err error
			if body, err := ioutil.ReadAll(r.Body); err == nil {
				r.Body.Close()
				var msg map[string]interface{}

				if err := json.Unmarshal(body, &msg); err == nil {
					sessionId, ok := msg["sessionId"].(string)
					if !ok {
						value, ok := msg["value"]
						if !ok {
							cancel = cancelFunc
							logger.Errorf("unable to extract sessionId from response")
							return errors.New("selenium protocol")
						}
						valueMap, ok := value.(map[string]interface{})
						if !ok {
							cancel = cancelFunc
							logger.Errorf("unable to extract sessionId from response")
							return errors.New("selenium protocol")
						}
						sessionId, ok = valueMap["sessionId"].(string)
						if !ok {
							cancel = cancelFunc
							logger.Errorf("unable to extract sessionId from response")
							return errors.New("selenium protocol")
						}
						msg["value"].(map[string]interface{})["sessionId"] = app.hostname
					} else {
						msg["sessionId"] = app.hostname
					}

					body, _ = json.Marshal(msg)
					r.Header["Content-Length"] = []string{fmt.Sprint(len(body))}
					r.ContentLength = int64(len(body))
					r.Body = ioutil.NopCloser(bytes.NewReader(body))

					service := &session{
						URL: &url.URL{
							Scheme: "http",
							Host:   net.JoinHostPort(app.hostname, app.browserPort),
							Path:   path.Join(app.proxyPath, sessionId),
						},
						ID: sessionId,
						OnTimeout: onTimeout(app.iddleTimeout, func() {
							logger.Warnf("session timed out: %s, after %.2fs", sessionId, app.iddleTimeout.Seconds())
							cancelFunc()
						}),
						CancelFunc: cancelFunc,
					}
					app.bucket.put(app.hostname, service)
					logger.Infof("new session request completed: %s", sessionId)

					return nil
				}
				cancel = cancelFunc
				logger.Errorf("unable to parse response body: %v", err)
				return errors.New("response body parse error")
			}
			cancel = cancelFunc
			logger.Errorf("unable to read response body: %v", err)
			return errors.New("response body read error")
		},
	}).ServeHTTP(w, r)
}

//HandleProxy ...
func (app *App) HandleProxy(w http.ResponseWriter, r *http.Request) {

	done := make(chan func())
	cancel := func() {}

	go func() {
		(<-done)()
	}()

	defer func() {
		done <- cancel
	}()

	fragments := strings.Split(r.URL.Path, "/")
	vars := mux.Vars(r)
	id := vars["sessionId"]

	logger := app.logger.WithFields(logrus.Fields{
		"request_id": uuid.New(),
		"request":    fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		"request_by": r.Header.Get("X-Forwarded-Selenosis"),
	})
	_, ok := app.bucket.get(id)

	if ok {
		(&httputil.ReverseProxy{
			Director: func(r *http.Request) {
				r.URL.Scheme = "http"
				sess, ok := app.bucket.get(id)
				if ok {
					app.bucket.Lock()
					defer app.bucket.Unlock()
					select {
					case <-sess.OnTimeout:
						logger.Warnf("session %s timed out", id)
					default:
						close(sess.OnTimeout)
					}

					if r.Method == http.MethodDelete && len(fragments) == 5 {
						cancel = sess.CancelFunc
						logger.Warnf("session %s delete request", id)
					} else {
						sess.OnTimeout = onTimeout(app.iddleTimeout, func() {
							logger.Infof("session timed out: %s, after %.2fs", id, app.iddleTimeout.Seconds())
							err := req{r}.buildURL(r.Host, id).delete()
							if err != nil {
								logger.Warnf("session %s delete request failed: %v", id, err)
							}
						})

						if r.Body != nil {
							if body, err := ioutil.ReadAll(r.Body); err == nil {
								r.Body.Close()
								var msg map[string]interface{}
								if err := json.Unmarshal(body, &msg); err == nil {
									if _, ok := msg["sessionId"].(string); ok {
										msg["sessionId"] = sess.ID
										body, _ = json.Marshal(msg)
										r.Header["Content-Length"] = []string{fmt.Sprint(len(body))}
										r.ContentLength = int64(len(body))
									}
								}
								r.Body = ioutil.NopCloser(bytes.NewReader(body))
							}
						}
					}
					r.URL.Host, r.URL.Path = sess.URL.Host, path.Clean(path.Join(sess.URL.Path, strings.Join(fragments[5:], "/")))
					logger.Info("proxy session")
					return
				}
				logger.Warnf("unknown session: %s", id)
				r.URL.Path = "/error"
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				w.WriteHeader(http.StatusBadGateway)
			},
			ModifyResponse: func(r *http.Response) error {
				var err error
				if body, err := ioutil.ReadAll(r.Body); err == nil {
					r.Body.Close()
					var msg map[string]interface{}
					if err := json.Unmarshal(body, &msg); err == nil {
						if _, ok := msg["sessionId"].(string); ok {
							msg["sessionId"] = id
							body, _ = json.Marshal(msg)
							r.Header["Content-Length"] = []string{fmt.Sprint(len(body))}
							r.ContentLength = int64(len(body))
						}
						r.Body = ioutil.NopCloser(bytes.NewReader(body))
						return nil
					}
					return err
				}
				return err
			},
		}).ServeHTTP(w, r)
	} else {
		jSONError(w, fmt.Sprintf("Unknown session %s", id), http.StatusBadRequest)
		logger.Errorf("unknown session: %s", id)
	}
}

//HandleDevTools ...
func (app *App) HandleDevTools(w http.ResponseWriter, r *http.Request) {
	app.proxy(w, r, ports.Devtools)
}

//HandleDownload ...
func (app *App) HandleDownload(w http.ResponseWriter, r *http.Request) {
	app.proxy(w, r, ports.Devtools)
}

//HandleClipboard ..
func (app *App) HandleClipboard(w http.ResponseWriter, r *http.Request) {
	app.proxy(w, r, ports.Devtools)
}

func (app *App) proxy(w http.ResponseWriter, r *http.Request, port string) {

	vars := mux.Vars(r)
	id := vars["sessionId"]
	logger := app.logger.WithFields(logrus.Fields{
		"request_id": uuid.New(),
		"request":    fmt.Sprintf("%s %s", r.Method, r.URL.Path),
		"request_by": r.Header.Get("X-Forwarded-Selenosis"),
	})

	fragments := strings.Split(r.URL.Path, "/")
	remainingPath := "/" + strings.Join(fragments[3:], "/")
	_, ok := app.bucket.get(id)

	if ok {
		(&httputil.ReverseProxy{
			Director: func(r *http.Request) {
				r.URL.Scheme = "http"
				r.URL.Host = net.JoinHostPort(app.hostname, port)
				r.URL.Path = remainingPath
				logger.Infof("proxying %s", fragments[1])
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				logger.Errorf("proxying %s error: %v", fragments[1], err)
				w.WriteHeader(http.StatusBadGateway)
			},
		}).ServeHTTP(w, r)
	} else {
		jSONError(w, fmt.Sprintf("Unknown session %s", id), http.StatusBadRequest)
		logger.Errorf("unknown session: %s", id)
	}
}

func onTimeout(t time.Duration, f func()) chan struct{} {
	cancel := make(chan struct{})
	go func(cancel chan struct{}) {
		select {
		case <-time.After(t):
			f()
		case <-cancel:
		}
	}(cancel)

	return cancel
}

func jSONError(w http.ResponseWriter, message string, statusCode int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(
		map[string]interface{}{
			"value": map[string]string{
				"message": message,
			},
			"code": statusCode,
		},
	)
}
