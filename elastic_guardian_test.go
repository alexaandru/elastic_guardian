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
	assertions := []([]string){
		{"BackendURL", BackendURL, "http://localhost:9200"},
		{"FrontendURL", FrontendURL, ":9600"},
		{"Realm", Realm, "Elasticsearch"},
		{"LogPath", LogPath, ""},
	}

	for _, row := range assertions {
		label, actual, expected := row[0], row[1], row[2]
		if actual != expected {
			t.Errorf("Failed to set %s: expected %s got %s", label, expected, actual)
		}
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

	uri, f, err := setup()
	if f != nil {
		defer f.Close()
		t.Error("Log should not be redirected when logpath empty")
	}

	if uri == nil {
		t.Error("Uri should not be nil")
	}

	if err != nil {
		t.Error("Error should be nil")
	}
}

func TestSetupWithCorrectFilePaths(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "authentication/authentication_test.txt", "authorization/authorization_test.txt", "test.test"

	uri, f, err := setup()
	if f != nil {
		defer f.Close()
	} else {
		t.Error("Log should be redirected to file when logpath NOT empty")
	}

	if uri == nil {
		t.Error("Uri should not be nil")
	}

	if err != nil {
		t.Error("Error should be nil")
	}
}

func TestSetupWithIncorrectAuthenticationFilePath(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "authentication/bogus/authentication_test.txt", "authorization/authorization_test.txt", "test.test"

	_, f, err := setup()
	if f != nil {
		defer f.Close()
	}

	expected := "open authentication/bogus/authentication_test.txt: no such file or directory"
	if err == nil {
		t.Error("Error should NOT be nil")
	} else if err.Error() != expected {
		t.Errorf("Expected %s error got %v", expected, err)
	}
}

func TestSetupWithIncorrectAuthorizationFilePath(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "authentication/authentication_test.txt", "authorization/bogus/authorization_test.txt", "test.test"

	_, f, err := setup()
	if f != nil {
		defer f.Close()
	}

	expected := "open authorization/bogus/authorization_test.txt: no such file or directory"
	if err == nil {
		t.Error("Error should NOT be nil")
	} else if err.Error() != expected {
		t.Errorf("Expected %s error got %v", expected, err)
	}
}

func TestSetupWithIncorrectURI(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "", "", ""

	BackendURL = "%BOGUS"
	_, f, err := setup()
	if f != nil {
		defer f.Close()
	}
	BackendURL = ""

	expected := "parse %BOGUS: invalid URL escape \"%BO\""
	if err == nil {
		t.Error("Error should NOT be nil")
	} else if err.Error() != expected {
		t.Errorf("Expected %s error got %v", expected, err)
	}
}

func TestSetupWithIncorrectLogPath(t *testing.T) {
	CredentialsPath, AuthorizationsPath, LogPath = "", "", "bogus/bogus"

	_, f, err := setup()
	if f != nil {
		defer f.Close()
	}

	expected := "open bogus/bogus: no such file or directory"
	if err == nil {
		t.Error("Error should NOT be nil")
	} else if err.Error() != expected {
		t.Errorf("Expected %s error got %v", expected, err)
	}
}
