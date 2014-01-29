package main

import (
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// BackendUrl points to the target of the reverse proxy.
// TODO: Make it configurable (via command line flag?)
const BackendURL = "http://localhost:9200"

// FrontendURL points to the URL the proxy will accept incoming requests on.
const FrontendURL = ":9600"

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

func main() {
	uri, err := url.Parse(BackendURL)
	if err != nil {
		log.Fatal(err)
	}

	var reverseProxy http.Handler
	reverseProxy = httputil.NewSingleHostReverseProxy(uri)
	reverseProxy = wrapAuthorization(reverseProxy)
	reverseProxy = wrapAuthentication(reverseProxy)

	http.Handle("/", reverseProxy)

	if err = http.ListenAndServe(FrontendURL, nil); err != nil {
		log.Fatal(err)
	}
}
