package main

import (
	"flag"
	"fmt"
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
	"log"
	"net/http"
	"os"
	"strings"
)

// processCmdLineFlags processes the command line flags.
// If none given it will use the default values set below (3rd parameter).
func processCmdLineFlags() {
	flag.StringVar(&BackendURL, "backend", "http://localhost:9200", "Backend URL (where to proxy requests to)")
	flag.StringVar(&FrontendURL, "frontend", ":9600", "Frontend URL (where to expose the proxied backend)")
	flag.StringVar(&Realm, "realm", "Elasticsearch", "HTTP Basic Auth realm")
	flag.StringVar(&LogPath, "logpath", "", "Path to the logfile (if not set, will dump to stdout)")
	flag.StringVar(&CredentialsPath, "cpath", "", "Path to the credentials file")
	flag.StringVar(&AuthorizationsPath, "apath", "", "Path to the authorizations file")
	flag.Parse()
}

func initCredentials(cs aa.CredentialsStore, fname string) (err error) {
	if fname == "" {
		return aa.LoadCredentials(cs)
	}

	return aa.LoadCredentials(fname)
}

func initAuthorizations(as az.AuthorizationStore, fname string) (err error) {
	if fname == "" {
		return az.LoadAuthorizations(as)
	}

	return az.LoadAuthorizations(fname)
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
