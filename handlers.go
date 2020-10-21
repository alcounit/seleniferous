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
)

type sess struct {
	url string
	id  string
}

type req struct {
	*http.Request
}

func (r req) buildURL(hostname, port, sessionID string) *sess {
	return &sess{
		url: fmt.Sprintf("http://%s/wd/hub/session/%s", net.JoinHostPort(hostname, port), sessionID),
		id:  sessionID,
	}
}

func (s sess) delete() {
	r, err := http.NewRequest(http.MethodDelete, s.url, nil)
	if err != nil {
		logger.Warnf("delete request failed: %s", s.id)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	resp, err := httpClient.Do(r.WithContext(ctx))
	if resp != nil {
		defer resp.Body.Close()
	}
	if err == nil && resp.StatusCode == http.StatusOK {
		return
	}
	if err != nil {
		logger.Warnf("delete request failed: %s", s.id)
	} else {
		logger.Warnf("delete request failed: %s, %s", s.id, resp.Status)
	}
}

func handleSession(w http.ResponseWriter, r *http.Request) {

	logger := logger.WithFields(logrus.Fields{
		"request_id":     uuid.New(),
		"request_method": r.Method,
		"req_path":       r.URL.Path,
		"request_by":     r.Header.Get("X-Forwarded-Selenosis"),
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
		client.CoreV1().Pods(namespace).Delete(context, hostname, metav1.DeleteOptions{
			GracePeriodSeconds: pointer.Int64Ptr(15),
		})
	}

	(&httputil.ReverseProxy{
		Director: func(r *http.Request) {
			r.URL.Scheme = "http"
			r.URL.Host, r.URL.Path = hostname, handlerPath

			go func() {
				<-r.Context().Done()

				cancel = cancelFunc
			}()

			logger.Info("new session request")
			return
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
						msg["value"].(map[string]interface{})["sessionId"] = hostname
					} else {
						msg["sessionId"] = hostname
					}

					body, _ = json.Marshal(msg)
					r.Header["Content-Length"] = []string{fmt.Sprint(len(body))}
					r.ContentLength = int64(len(body))

					r.Body = ioutil.NopCloser(bytes.NewReader(body))

					service := &session{
						URL: &url.URL{
							Scheme: "http",
							Host:   hostname,
							Path:   path.Join(handlerPath, sessionId),
						},
						ID: sessionId,
						OnTimeout: onTimeout(idleTimeout, func() {
							logger.Warnf("session timed out: %s, after %.2fs", sessionId, idleTimeout.Seconds())
							cancelFunc()
						}),
						CancelFunc: cancelFunc,
					}

					bucket.put(hostname, service)
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
		//Transport: debugTransport{},
	}).ServeHTTP(w, r)

}

func handleProxy(w http.ResponseWriter, r *http.Request) {

	done := make(chan func())
	go func() {
		(<-done)()
	}()
	cancel := func() {}
	defer func() {
		done <- cancel
	}()

	fragments := strings.Split(r.URL.Path, "/")
	vars := mux.Vars(r)
	id := vars["sessionId"]

	logger := logger.WithFields(logrus.Fields{
		"request_id":     uuid.New(),
		"request_method": r.Method,
		"req_path":       r.URL.Path,
		"selenosis_id":   r.Header.Get("X-Forwarded-Selenosis"),
	})

	(&httputil.ReverseProxy{
		Director: func(r *http.Request) {

			r.URL.Scheme = "http"
			sess, ok := bucket.get(id)
			if ok {
				bucket.Lock()
				defer bucket.Unlock()
				select {
				case <-sess.OnTimeout:
				default:
					close(sess.OnTimeout)
				}

				if r.Method == http.MethodDelete && len(fragments) == 5 {
					cancel = sess.CancelFunc
				} else {
					sess.OnTimeout = onTimeout(idleTimeout, func() {
						logger.Infof("session timed out: %s, after %.2fs", id, idleTimeout.Seconds())
						req{r}.buildURL(hostname, listhenPort, id).delete()
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
				logger.Infof("request: %s: %s", r.Method, r.URL.Path)
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
		//Transport: debugTransport{},
	}).ServeHTTP(w, r)
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
