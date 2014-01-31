package main

import (
	"encoding/base64"
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

	if Logpath != "./elastic_guardian.log" {
		t.Error("Failed to set Logpath, got", Logpath)
	}
}
