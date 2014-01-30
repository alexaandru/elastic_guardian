package authentication

import (
	"encoding/base64"
	"testing"
)

var foobar, foobogus = base64.StdEncoding.EncodeToString([]byte("foo:bar")),
	base64.StdEncoding.EncodeToString([]byte("foo:bogus"))

func TestShouldFailIfAuthHeaderEmpty(t *testing.T) {
	if status, _ := BasicAuthPassed(""); status != NotAttempted {
		t.Error("BasicAuthPassed() should be false with empty header")
	}
}

func TestShouldFailIfNotBasicAuth(t *testing.T) {
	if status, _ := BasicAuthPassed("Basicx foo"); status != NotBasic {
		t.Error("BasicAuthPassed() should be false with non Basic header")
	}
}

func TestShouldFailIfNonDecodable(t *testing.T) {
	if status, _ := BasicAuthPassed("Basic garbageHere"); status != Failed {
		t.Error("BasicAuthPassed() should be false with non Base64 data")
	}
}

func TestShouldFailWithIncorrectPassword(t *testing.T) {
	if status, _ := BasicAuthPassed("Basic " + foobogus); status != Failed {
		t.Error("BasicAuthPassed() should be false with incorrect password")
	}
}

func TestShouldPass(t *testing.T) {
	if status, _ := BasicAuthPassed("Basic " + foobar); status != Passed {
		t.Error("BasicAuthPassed() should be true with correct password")
	}
}
