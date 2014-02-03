package main

import (
	"encoding/base64"
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type testCase struct {
	url, header, body string
}

var foobar, foobogus, bazboo = base64.StdEncoding.EncodeToString([]byte("foo:bar")),
	base64.StdEncoding.EncodeToString([]byte("foo:bogus")),
	base64.StdEncoding.EncodeToString([]byte("baz:boo"))

var testCases = map[string]testCase{
	"request_authentication_if_blank": {"whatever", "", "401 Unauthorized\n"},
	"fail_with_incorrect_credentials": {"whatever", "Basic " + foobogus, "403 Forbidden (authentication)\n"},
	"pass_when_blacklisting_allows":   {"/_cluster/stats", "Basic " + foobar, ""},
	"fail_when_blacklisting_forbids":  {"/_cluster/health", "Basic " + foobar, "403 Forbidden (authorization)\n"},
	"pass_when_whitelisting_allows":   {"/_cluster/health", "Basic " + bazboo, ""},
	"fail_when_whitelisting_forbids":  {"/_cluster/stats", "Basic " + bazboo, "403 Forbidden (authorization)\n"},
}

func loadCredentials() {
	aa.LoadCredentials(aa.CredentialsStore{
		"foo": aa.Hash("bar"),
		"baz": aa.Hash("boo"),
	})
}

func loadAuthorizations() {
	az.LoadAuthorizations(az.AuthorizationStore{
		"foo": az.AuthorizationRules{az.Allow, []string{"GET /_cluster/health"}},
		"baz": az.AuthorizationRules{az.Deny, []string{"GET /_cluster/health"}},
	})
}

// Test wrappers
func TestShouldRequestAuthenticationIfBlank(t *testing.T) {
	assertPassesTestCase(t, testCases["request_authentication_if_blank"])
}

func TestShouldFailWithIncorrectCredentials(t *testing.T) {
	assertPassesTestCase(t, testCases["fail_with_incorrect_credentials"])
}

func TestShouldPassWhenBlacklistingAllows(t *testing.T) {
	assertPassesTestCase(t, testCases["pass_when_blacklisting_allows"])
}

func TestShouldFailWhenBlacklistingForbids(t *testing.T) {
	assertPassesTestCase(t, testCases["fail_when_blacklisting_forbids"])
}

func TestShouldPassWhenWhitelistingAllows(t *testing.T) {
	assertPassesTestCase(t, testCases["pass_when_whitelisting_allows"])
}

func TestShouldFailWhenWhitelistingForbids(t *testing.T) {
	assertPassesTestCase(t, testCases["fail_when_whitelisting_forbids"])
}

func assertPassesTestCase(t *testing.T, tc testCase) {
	loadCredentials()
	loadAuthorizations()

	uri, err := url.Parse("http://localhost:9000")
	if err != nil {
		t.Fail()
	}

	handler := initReverseProxy(uri, wrapAuthorization, wrapAuthentication)
	recorder := httptest.NewRecorder()

	req, err := http.NewRequest("GET", tc.url, nil)
	if err != nil {
		t.Error("Failed to perform the request:", err)
	}

	if tc.header != "" {
		req.Header.Set("Authorization", tc.header)
	}

	handler.ServeHTTP(recorder, req)

	if expectedBody, actualBody := tc.body, recorder.Body.String(); actualBody != expectedBody {
		t.Error("Expected", expectedBody, "got", actualBody)
	}
}

// Test command line
func TestCmdLineFlagDefaults(t *testing.T) {
	processCmdLineFlags()

	if BackendURL != "http://localhost:9200" {
		t.Error("Failed to set BackendURL, got", BackendURL)
	}

	if FrontendURL != ":9600" {
		t.Error("Failed to set FrontendURL, got", FrontendURL)
	}

	if Realm != "Elasticsearch" {
		t.Error("Failed to set Realm, got", Realm)
	}

	if LogPath != "" {
		t.Error("Failed to set LogPath, got", LogPath)
	}
}

// Test logging
func TestLogpathEmpty(t *testing.T) {
	f, err := redirectLogsToFile("")

	if f != nil {
		t.Error("Should have NOT returned a file pointer on empty path")
	}
	if err != nil {
		t.Error("Should have NOT returned an error on empty path")
	}
}

func TestLogpathInvalid(t *testing.T) {
	_, err := redirectLogsToFile("what/a/bogus/path/this/is")

	if err == nil {
		t.Error("Should have returned error on invalid path")
	}
}

func TestLogpathValid(t *testing.T) {
	f, err := redirectLogsToFile("test.test")

	if f == nil {
		t.Error("Should have returned a file pointer on valid path")
	}
	if err != nil {
		t.Error("Should NOT have returned error on valid path")
	}
}

// Test setup
func TestSetupInline(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "", "", ""

	uri, f := setup()
	if f != nil {
		defer f.Close()
		t.Error("Log should not be redirected when logpath empty")
	}

	if uri == nil {
		t.Error("Uri should not be nil")
	}
}

func TestSetupWithFilePaths(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "authentication/authentication_test.txt", "authorization/authorization_test.txt", "test.test"

	uri, f := setup()
	if f != nil {
		defer f.Close()
	} else {
		t.Error("Log should be redirected to file when logpath NOT empty")
	}

	if uri == nil {
		t.Error("Uri should not be nil")
	}
}
