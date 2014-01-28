package authentication

import (
	// "encoding/base64"
	// "log"
	// "strings"
	"testing"
)

func TestShouldFailIfAuthHeaderEmpty(t *testing.T) {
	if ok, _ := BasicAuthPassed(""); ok {
		t.Error("BasicAuthPassed() should be false with empty header")
	}
}

func TestShouldFailIfNotBasicAuth(t *testing.T) {
	if ok, _ := BasicAuthPassed("Basicx foo"); ok {
		t.Error("BasicAuthPassed() should be false with non Basic header")
	}
}

func TestShouldFailIfNonDecodable(t *testing.T) {
	if ok, _ := BasicAuthPassed("Basic garbageHere"); ok {
		t.Error("BasicAuthPassed() should be false with non Base64 data")
	}
}

func TestShouldFailWithIncorrectPassword(t *testing.T) {
	if ok, _ := BasicAuthPassed("Basic Zm9vOmJhcnM="); ok {
		t.Error("BasicAuthPassed() should be false with incorrect password")
	}
}

func TestShouldPass(t *testing.T) {
	if ok, _ := BasicAuthPassed("Basic Zm9vOmJhcg=="); !ok {
		t.Error("BasicAuthPassed() should be true with correct password")
	}
}
