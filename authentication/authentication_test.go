package authentication

import (
	"encoding/base64"
	"errors"
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
