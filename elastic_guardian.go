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
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
)

// handlerWrapper captures the signature of a http.Handler wrapper function.
type handlerWrapper func(http.Handler) http.Handler

// BackendURL points to the target of the reverse proxy.
var BackendURL string

// FrontendURL points to the URL the proxy will accept incoming requests on.
var FrontendURL string

// Realm holds the Basic Auth realm.
var Realm string

// LogPath holds the path to the logfile.
var LogPath string

// CredentialsPath holds the path to the credentials file.
var CredentialsPath string

// AuthorizationsPath holds the path to the authorizations file.
var AuthorizationsPath string

// initReverseProxy initializes the reverseProxy, including applying any handlers passed.
func initReverseProxy(uri *url.URL, handlers ...handlerWrapper) (rp http.Handler) {
	rp = httputil.NewSingleHostReverseProxy(uri)
	for _, handler := range handlers {
		rp = handler(rp)
	}

	return
}

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
			go logPrint(r, "202 Accepted")
			h.ServeHTTP(w, r)
		} else {
			go logPrint(r, "403 Forbidden (authorization)")
			http.Error(w, "403 Forbidden (authorization)", http.StatusForbidden)
		}
	})
}

func main() {
	processCmdLineFlags()

	if err := initCredentials(inlineCredentials, CredentialsPath); err != nil {
		log.Fatal("Cannot open the credentials file:", err)
	}

	if err := initAuthorizations(inlineAuthorizations, AuthorizationsPath); err != nil {
		log.Fatal("Cannot open the authorizations file:", err)
	}

	if f, err := redirectLogsToFile(LogPath); err != nil {
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
