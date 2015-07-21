package authentication

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
)

type NastyReader struct{}

func (nr NastyReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("won't happen")
}

var foobar, foobogus = base64.StdEncoding.EncodeToString([]byte("foo:bar")),
	base64.StdEncoding.EncodeToString([]byte("foo:bogus"))

func loadCredentials() {
	LoadCredentials(CredentialsStore{
		"foo": Hash("bar"),
		"baz": Hash("boo"),
	})
}

// Test loading credentials
func TestLoadCredentialsFromVar(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	loadCredentials()
	if credentials["foo"] == "" {
		t.Error("credentials should have been loaded")
	}
}

func TestLoadCredentialsFromString(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	LoadCredentials("authentication_test.txt")
	if credentials["foo"] == "" {
		t.Error("credentials should have been loaded")
	}
}

func TestLoadCredentialsFromWrongString(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	err := LoadCredentials("authentication_test.xxx")
	if err == nil {
		t.Error("Loading credentials from invlid filename should error out")
	}
}

func TestLoadCredentialsFromReaderWrapper(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	if f, e := os.Open("authentication_test.txt"); e == nil {
		LoadCredentials(f)
		if credentials["foo"] == "" {
			t.Error("credentials should have been loaded")
		}
	} else {
		t.Error("Failed to open credentials file for testing")
	}
}

func TestLoadCredentialsFromBadInterface(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	err := LoadCredentials(42)
	if err == nil {
		t.Error("Loading credentials from int should've errored out")
	}
}

func TestLoadCredentialsFromReader(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	reader := strings.NewReader("foo:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9\nbaz:6446d58d6dfafd58586d3ea85a53f4a6b3cc057f933a22bb58e188a74ac8f663\n")
	err := LoadCredentialsFromReader(reader)

	if credentials["foo"] == "" {
		t.Error("credentials should have been loaded")
	}

	if err != nil {
		t.Error("loading failed", err)
	}
}

func TestLoadCredentialsFromNastyReader(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	err := LoadCredentialsFromReader(NastyReader{})
	if err == nil {
		t.Error("Loading credentials from a reader that errors out should error out")
	}
}

// Test Hash
func TestHash(t *testing.T) {
	expectedHash := "af2bdbe1aa9b6ec1e2ade1d694f41fc71a831d0268e9891562113d8a62add1bf"
	if actualHash := Hash("sample"); expectedHash != actualHash {
		t.Errorf("Hashing failed: expected %s got %s", expectedHash, actualHash)
	}
}

// Test BasicAuthPassed
func TestShouldFailIfAuthHeaderEmpty(t *testing.T) {
	loadCredentials()
	req := mockReq("Basic ", "", t)
	if status, _ := BasicAuthPassed(req); status != NotAttempted {
		t.Error("BasicAuthPassed() should fail with", NotAttempted, "got", status)
	}
}

func TestShouldFailIfNonDecodableHeader(t *testing.T) {
	loadCredentials()
	req := mockReq("Basic garbage", "", t)
	if status, _ := BasicAuthPassed(req); status != NotAttempted {
		t.Error("BasicAuthPassed() should fail with", NotAttempted, "got", status)
	}
}

func TestShouldFailWithIncorrectPasswordInHeader(t *testing.T) {
	loadCredentials()
	req := mockReq("Basic "+foobogus, "", t)
	if status, _ := BasicAuthPassed(req); status != Failed {
		t.Error("BasicAuthPassed() should fail with", Failed, "got", status)
	}
}

func TestShouldPassWithCorrectHeader(t *testing.T) {
	loadCredentials()
	req := mockReq("Basic "+foobar, "", t)
	if status, u := BasicAuthPassed(req); status != Passed {
		t.Error("BasicAuthPassed() should succeed, got", status)
	} else if u != "foo" {
		t.Error("Expected user foo, got", u)
	}
}

func TestShouldFailWithBadPasswordInURL(t *testing.T) {
	loadCredentials()
	req := mockReq("", "https://foo:bogus@example.com", t)
	if status, _ := BasicAuthPassed(req); status != Failed {
		t.Error("BasicAuthPassed() should fail with", Failed, "got", status)
	}
}
func TestShouldPassWithCorrectPasswordInURL(t *testing.T) {
	loadCredentials()
	req := mockReq("", "https://foo:bar@example.com", t)
	if status, u := BasicAuthPassed(req); status != Passed {
		t.Error("BasicAuthPassed() should succeed, got", status)
	} else if u != "foo" {
		t.Error("Expected user foo, got", u)
	}
}

// helpers

func mockReq(hdr, uri string, t *testing.T) *http.Request {
	var err error
	req := http.Request{Header: http.Header{}}
	if hdr != "" {
		req.Header.Add("Authorization", hdr)
	}
	if uri != "" {
		req.URL, err = url.Parse(uri)
		if err != nil {
			t.Fatal(err)
		}
	}

	return &req
}
