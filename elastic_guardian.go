/*
Elastic Guardian is a tiny reverse proxy that can offer authentication (using HTTP Basic Auth)
as well as authorization.

While it was originally meant as a thin layer between Elasticsearch (which has no builtin
authentication/authorization) and the World, there is nothing specific to Elasticsearch (other
than a few defaults which can be changed via command line flags).

The generic use case for Elastic Guardian is to restrict access to a HTTP API with HTTP
Basic Auth and authorization rules.

It currently offers:
	authentication (using HTTP Basic Auth);
	authorization (based on the {user, HTTP verb, HTTP path}).
*/
package main

import (
	"flag"
	"fmt"
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
)

// handlerWrapper captures the signature of a http.Handler wrapper function.
type handlerWrapper func(http.Handler) http.Handler

// BackendURL points to the target of the reverse proxy.
var BackendURL string

// FrontendURL points to the URL the proxy will accept incoming requests on.
var FrontendURL string

// Realm holds the Basic Auth realm.
var Realm string

// Logpath holds the path to the logfile.
var Logpath string

// wrapAuthentication wraps given h Handler with an authentication layer.
func wrapAuthentication(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		status, user := aa.BasicAuthPassed(r.Header.Get("Authorization"))
		if status == aa.Passed {
			r.Header.Set("X-Authenticated-User", user)
			h.ServeHTTP(w, r)
		} else if status == aa.NotAttempted {
			go logPrint(r, "401 Unauthorized")
			w.Header().Set("WWW-Authenticate", "Basic realm=\""+Realm+"\"")
			http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
		} else {
			go logPrint(r, "403 Forbidden (authentication)")
			http.Error(w, "403 Forbidden (authentication)", http.StatusForbidden)
		}
	})
}

// wrapAuthorization wraps given h Handler with an authorization layer.
func wrapAuthorization(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if az.AuthorizationPassed(r.Header.Get("X-Authenticated-User"), r.Method, r.URL.Path) {
			go logPrint(r, "200 OK")
			h.ServeHTTP(w, r)
		} else {
			go logPrint(r, "403 Forbidden (authorization)")
			http.Error(w, "403 Forbidden (authorization)", http.StatusForbidden)
		}
	})
}

// processCmdLineFlags processes the command line flags. If none given it will use the default
// values:
//
//   backend: "http://localhost:9200"
//   frontend: ":9600"
//   realm: "Elasticsearch"
func processCmdLineFlags() {
	flag.StringVar(&BackendURL, "backend", "http://localhost:9200", "Backend URL (where to proxy requests to)")
	flag.StringVar(&FrontendURL, "frontend", ":9600", "Frontend URL (where to expose the proxied backend)")
	flag.StringVar(&Realm, "realm", "Elasticsearch", "HTTP Basic Auth realm")
	flag.StringVar(&Logpath, "logpath", "./elastic_guardian.log", "Path to the logfile")
	flag.Parse()
}

// initReverseProxy initializes the reverseProxy, including applying any handlers passed.
func initReverseProxy(uri *url.URL, handlers ...handlerWrapper) (rp http.Handler) {
	rp = httputil.NewSingleHostReverseProxy(uri)
	for _, handler := range handlers {
		rp = handler(rp)
	}

	return
}

// redirectLogsToFile sets the output for logs to the given path.
func redirectLogsToFile(path string) (f *os.File, err error) {
	f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return
	}

	log.SetOutput(f)

	return
}

// logPrint is a shortcut to the log.Println, with the necessary formatting included.
func logPrint(r *http.Request, msg string) {
	tokens := strings.Split(r.RemoteAddr, ":")
	log.Println(fmt.Sprintf("%s \"%s %s %s\" %s", tokens[0], r.Method, r.URL.Path, r.Proto, msg))
}

func main() {
	processCmdLineFlags()

	if f, err := redirectLogsToFile(Logpath); err != nil {
		log.Fatalf("Error opening logfile: %v", err)
	} else {
		defer f.Close()
	}

	uri, err := url.Parse(BackendURL)
	if err != nil {
		log.Fatal(err)
	}

	reverseProxy := initReverseProxy(uri, wrapAuthorization, wrapAuthentication)
	http.Handle("/", reverseProxy)
	if err = http.ListenAndServe(FrontendURL, nil); err != nil {
		log.Fatal(err)
	}
}
