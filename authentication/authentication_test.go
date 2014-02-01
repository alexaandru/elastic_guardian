package authentication

import (
	"encoding/base64"
	"strings"
	"testing"
)

var foobar, foobogus = base64.StdEncoding.EncodeToString([]byte("foo:bar")),
	base64.StdEncoding.EncodeToString([]byte("foo:bogus"))

func loadCredentials() {
	LoadCredentials(CredentialsStore{
		"foo": Hash("bar"),
		"baz": Hash("boo"),
	})
}

func TestLoadCredentials(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	loadCredentials()
	if credentials["foo"] == "" {
		t.Error("credentials should have been loaded")
	}
}

func TestLoadCredentialsFromFile(t *testing.T) {
	credentials = CredentialsStore{}
	if credentials["foo"] != "" {
		t.Error("credentials should be empty")
	}

	reader := strings.NewReader("foo:fcde2b2edba56bf408601fb721fe9b5c338d10ee429ea04fae5511b68fbf8fb9\nbaz:6446d58d6dfafd58586d3ea85a53f4a6b3cc057f933a22bb58e188a74ac8f663\n")
	err := LoadCredentialsFromFile(reader)

	if credentials["foo"] == "" {
		t.Error("credentials should have been loaded")
	}

	if err != nil {
		t.Error("loading failed", err)
	}
}

func TestShouldFailIfAuthHeaderEmpty(t *testing.T) {
	loadCredentials()
	if status, _ := BasicAuthPassed(""); status != NotAttempted {
		t.Error("BasicAuthPassed() should be false with empty header")
	}
}

func TestShouldFailIfNotBasicAuth(t *testing.T) {
	loadCredentials()
	if status, _ := BasicAuthPassed("Basicx foo"); status != NotBasic {
		t.Error("BasicAuthPassed() should be false with non Basic header")
	}
}

func TestShouldFailIfNonDecodable(t *testing.T) {
	loadCredentials()
	if status, _ := BasicAuthPassed("Basic garbageHere"); status != Failed {
		t.Error("BasicAuthPassed() should be false with non Base64 data")
	}
}

func TestShouldFailWithIncorrectPassword(t *testing.T) {
	loadCredentials()
	if status, _ := BasicAuthPassed("Basic " + foobogus); status != Failed {
		t.Error("BasicAuthPassed() should be false with incorrect password")
	}
}

func TestShouldPass(t *testing.T) {
	loadCredentials()
	if status, _ := BasicAuthPassed("Basic " + foobar); status != Passed {
		t.Error("BasicAuthPassed() should be true with correct password")
	}
}
