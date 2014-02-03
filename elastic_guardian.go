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

It currently supports loading the authentication and authorization data from two different backends:
	inline variables (see settings.go) or
	external files (filenames passed via commandline flags)

Whether the external files are used or not can be controled (at compile time) via AllowAuthFromFiles
constant. See that constant definition for further details.

Please see authentication and authorization packages for further details.

Commandline help can be accessed with:
	elastic_guardian -h

That will also display the default values for all flags. Log output will go to console (stdout)
by default.
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
	"runtime"
	"strings"
)

// AllowAuthFromFiles controls whether the files specified via command lien flags for
// authentication and authorization will actually be used. Can be used to lock down
// access to only the credentials stored at compile time (effectively disallow overriding
// them at runtime). May come in handy in some scenarios.
const AllowAuthFromFiles = true

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

func initReverseProxy(uri *url.URL, handlers ...handlerWrapper) (rp http.Handler) {
	rp = httputil.NewSingleHostReverseProxy(uri)
	for _, handler := range handlers {
		rp = handler(rp)
	}

	return
}

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

func processCmdLineFlags() {
	flag.StringVar(&BackendURL, "backend", "http://localhost:9200", "Backend URL (where to proxy requests to)")
	flag.StringVar(&FrontendURL, "frontend", ":9600", "Frontend URL (where to expose the proxied backend)")
	flag.StringVar(&Realm, "realm", "Elasticsearch", "HTTP Basic Auth realm")
	flag.StringVar(&LogPath, "logpath", "", "Path to the logfile (if not set, will dump to stdout)")
	flag.StringVar(&CredentialsPath, "cpath", "", "Path to the credentials file")
	flag.StringVar(&AuthorizationsPath, "apath", "", "Path to the authorizations file")
	flag.Parse()
}

func redirectLogsToFile(path string) (f *os.File, err error) {
	if path == "" {
		return
	}

	f, err = os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0660)
	if err != nil {
		return
	}

	log.SetOutput(f)

	return
}

func logPrint(r *http.Request, msg string) {
	tokens := strings.Split(r.RemoteAddr, ":")
	log.Println(fmt.Sprintf("%s \"%s %s %s\" %s", tokens[0], r.Method, r.URL.Path, r.Proto, msg))
}

func setup() (uri *url.URL, f *os.File) {
	var err error

	runtime.GOMAXPROCS(runtime.NumCPU())

	if !AllowAuthFromFiles || CredentialsPath == "" {
		aa.LoadCredentials(inlineCredentials)
	} else if err = aa.LoadCredentials(CredentialsPath); err != nil {
		log.Fatal("Cannot open the credentials file:", err)
	}

	if !AllowAuthFromFiles || AuthorizationsPath == "" {
		az.LoadAuthorizations(inlineAuthorizations)
	} else if err = az.LoadAuthorizations(AuthorizationsPath); err != nil {
		log.Fatal("Cannot open the authorizations file:", err)
	}

	uri, err = url.Parse(BackendURL)
	if err != nil {
		log.Fatal(err)
	}

	if f, err = redirectLogsToFile(LogPath); err != nil {
		log.Fatalf("Error opening logfile: %v", err)
	}

	return
}

func main() {
	processCmdLineFlags()

	uri, f := setup()
	if f != nil {
		defer f.Close()
	}

	reverseProxy := initReverseProxy(uri, wrapAuthorization, wrapAuthentication)
	http.Handle("/", reverseProxy)
	if err := http.ListenAndServe(FrontendURL, nil); err != nil {
		log.Fatal(err)
	}
}
