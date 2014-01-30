/*
Elastic Guardian implements a tiny reverse proxy that hopefully is easy to understand
and extend.

It currently offers:
 - an authentication (using HTTP Basic Auth) layer;
 - an authorization layer (based on the (user, HTTP verb, HTTP path) set).
*/
package main

import (
	"flag"
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// BackendURL points to the target of the reverse proxy.
var BackendURL string

// FrontendURL points to the URL the proxy will accept incoming requests on.
var FrontendURL string

// wrapAuthentication wraps given h Handler with an authentication layer.
func wrapAuthentication(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ok, user := aa.BasicAuthPassed(r.Header.Get("Authorization")); ok {
			go log.Println("Authentication passed, user is", user)
			r.Header.Set("X-Authenticated-User", user)
			h.ServeHTTP(w, r)
		} else {
			go log.Println("Authentication failed")
			http.Error(w, "401 Forbidden (authentication)", http.StatusForbidden)
		}
	})
}

// wrapAuthorization wraps given h Handler with an authorization layer.
func wrapAuthorization(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if az.AuthorizationPassed(r.Header.Get("X-Authenticated-User"), r.Method, r.URL.Path) {
			go log.Println("Authorization passed")
			h.ServeHTTP(w, r)
		} else {
			go log.Println("Authorization failed")
			http.Error(w, "401 Forbidden (authorization)", http.StatusForbidden)
		}
	})
}

// processCmdLineFlags processes the command line flags. If none given it will use the default
// values:
//
//   backend: "http://localhost:9200"
//   frontend: ":9600"
func processCmdLineFlags() {
	flag.StringVar(&BackendURL, "backend", "http://localhost:9200", "Backend URL (where to proxy requests to)")
	flag.StringVar(&FrontendURL, "frontend", ":9600", "Frontend URL (where to expose the proxied backend)")
	flag.Parse()
}

// initReverseProxy initializes the reverseProxy, including applying any handlers/wrappers around it.
func initReverseProxy(uri *url.URL) (rp http.Handler) {
	rp = httputil.NewSingleHostReverseProxy(uri)
	rp = wrapAuthorization(rp)
	rp = wrapAuthentication(rp)

	return
}

func main() {
	processCmdLineFlags()

	uri, err := url.Parse(BackendURL)
	if err != nil {
		log.Fatal(err)
	}

	http.Handle("/", initReverseProxy(uri))
	if err = http.ListenAndServe(FrontendURL, nil); err != nil {
		log.Fatal(err)
	}
}
