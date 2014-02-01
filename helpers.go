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

// inlineCredentials defines credentials inline.
var inlineCredentials = aa.CredentialsStore{
	"foo": aa.Hash("bar"),
	"baz": aa.Hash("boo"),
}

// inlineAuthorizations defines the authorization rules inline.
var inlineAuthorizations = az.AuthorizationStore{
	"foo": az.AuthorizationRules{az.Allow, []string{"GET /_cluster/health"}},
	"baz": az.AuthorizationRules{az.Deny, []string{"GET /_cluster/health"}},
}

// initReverseProxy initializes the reverseProxy, including applying any handlers passed.
func initReverseProxy(uri *url.URL, handlers ...handlerWrapper) (rp http.Handler) {
	rp = httputil.NewSingleHostReverseProxy(uri)
	for _, handler := range handlers {
		rp = handler(rp)
	}

	return
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
	flag.StringVar(&LogPath, "logpath", "stdout", "Path to the logfile")
	flag.StringVar(&CredentialsPath, "cpath", "", "Path to the credentials file")
	flag.StringVar(&AuthorizationsPath, "apath", "", "Path to the authorizations file")
	flag.Parse()
}

func initCredentials(cs aa.CredentialsStore, fname string) (err error) {
	if fname == "" {
		return aa.LoadCredentials(cs)
	}

	f, err := os.Open(fname)
	if err != nil {
		return
	}

	return aa.LoadCredentials(f)
}

func initAuthorizations(as az.AuthorizationStore, fname string) (err error) {
	if fname == "" {
		return az.LoadAuthorizations(as)
	}

	f, err := os.Open(fname)
	if err != nil {
		return
	}

	return az.LoadAuthorizations(f)
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
