package authorization

import (
	"errors"
	"os"
	"strings"
	"testing"
)

type NastyReader struct{}

func (nr NastyReader) Read(p []byte) (n int, err error) {
	return 0, errors.New("won't happen")
}

func loadAuthorizations() {
	LoadAuthorizations(AuthorizationStore{
		"foo": AuthorizationRules{Allow, []string{"GET /_cluster/health"}},
		"baz": AuthorizationRules{Deny, []string{"GET /_cluster/health"}},
	})
}

// Test loading authorizations
func TestLoadAuthorizationsFromVar(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	loadAuthorizations()
	if authorizations["foo"].isEmpty() {
		t.Error("authorizations should have been loaded")
	}
}

func TestLoadAuthorizationsFromString(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	LoadAuthorizations("authorization_test.txt")
	if authorizations["foo"].isEmpty() {
		t.Error("authorizations should have been loaded")
	}
}

func TestLoadAuthorizationsFromWrongString(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	err := LoadAuthorizations("authorization_test.xxx")
	if err == nil {
		t.Error("Loading authorizations from invlid filename should error out")
	}
}

func TestLoadAuthorizationsFromReaderWrapper(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	if f, e := os.Open("authorization_test.txt"); e == nil {
		LoadAuthorizations(f)
		if authorizations["foo"].isEmpty() {
			t.Error("authorizations should have been loaded")
		}
	} else {
		t.Error("Failed to open authorizations file for testing")
	}
}

func TestLoadAuthorizationsFromBadInterface(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	err := LoadAuthorizations(42)
	if err == nil {
		t.Error("Loading authorizations from int should've errored out")
	}
}

func TestLoadAuthorizationsFromReader(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	reader := strings.NewReader("foo:allow:GET /_cluster/health\nbaz:deny:GET /_cluster/health\n")
	LoadAuthorizationsFromReader(reader)

	if authorizations["foo"].isEmpty() {
		t.Error("authorizations should have been loaded")
	}

	reader = strings.NewReader("foo:allow:GET /_cluster/health\nbaz\n")
	err := LoadAuthorizationsFromReader(reader)
	if err.Error() != "Invalid authorization line: baz" {
		t.Error("Should've errored out on baz line")
	}

	reader = strings.NewReader("foo:allow:GET /_cluster/health\nbaz:denyes:GET /_cluster/health\n")
	err = LoadAuthorizationsFromReader(reader)
	if err.Error() != "Unknown default rule denyes" {
		t.Error("Should've errored out on baz line")
	}
}

func TestLoadAuthorizationsFromNastyReader(t *testing.T) {
	authorizations = AuthorizationStore{}
	if !authorizations["foo"].isEmpty() {
		t.Error("authorizations var should start empty")
	}

	err := LoadAuthorizationsFromReader(NastyReader{})
	if err == nil {
		t.Error("Loading authorizations from a reader that errors out should error out")
	}
}

// Test AuthorizationRules methods
func TestIsEmpty(t *testing.T) {
	loadAuthorizations()
	ar := AuthorizationRules{}
	if !ar.isEmpty() {
		t.Error("isEmpty() should be true with empty authorizationRules")
	}

	ar.DefaultRule = Allow
	if ar.isEmpty() {
		t.Error("isEmpty() should be false with NON empty authorizationRules")
	}

	ar.DefaultRule = Deny
	ar.Rules = append(ar.Rules, "GET /foo")
	if ar.isEmpty() {
		t.Error("isEmpty() should be false with NON empty authorizationRules")
	}
}

func TestHasRule(t *testing.T) {
	loadAuthorizations()
	ar := AuthorizationRules{Allow, []string{"GET /foobar"}}

	if ar.hasRule("GET", "bar") {
		t.Error("hasRule() should not have GET bar")
	}

	if !ar.hasRule("GET", "/foobar") {
		t.Error("hasRule() should have GET /foobar")
	}
}

func TestHasNoRule(t *testing.T) {
	loadAuthorizations()
	ar := AuthorizationRules{Allow, []string{"GET /foobar"}}

	if !ar.hasNoRule("GET", "bar") {
		t.Error("hasNoRule() should not have GET bar")
	}

	if ar.hasNoRule("GET", "/foobar") {
		t.Error("hasNoRule() should have GET /foobar")
	}
}

func TestAllowWithWhitelist(t *testing.T) {
	loadAuthorizations()
	ar := AuthorizationRules{Deny, []string{"GET /foobar"}}

	// Should deny EVERYTHING except defined rules
	if !ar.allows("GET", "/foobar") {
		t.Error("allows() should allow GET /foobar")
	}

	if ar.allows("GET", "/foobars") {
		t.Error("allows() should NOT allow GET /foobars")
	}
}

func TestAllowWithBlacklist(t *testing.T) {
	loadAuthorizations()
	ar := AuthorizationRules{Allow, []string{"GET /foobar"}}

	// Should allow EVERYTHING except defined rules
	if ar.allows("GET", "/foobar") {
		t.Error("allows() should NOT allow GET /foobar")
	}

	if !ar.allows("GET", "/foobars") {
		t.Error("allows() should allow GET /foobars")
	}
}

// Test AuthorizationPassed
func TestAuthorizationFailsWithEmptyUser(t *testing.T) {
	loadAuthorizations()
	if AuthorizationPassed("", "GET", "whatever") {
		t.Error("Authorization should fail with empty user")
	}
}

func TestAuthorizationFailsWithEmptyRules(t *testing.T) {
	loadAuthorizations()
	if AuthorizationPassed("bogus", "GET", "whatever") {
		t.Error("Authorization should fail with empty rules for user")
	}
}

func TestAuthorizationPassed(t *testing.T) {
	loadAuthorizations()
	if !AuthorizationPassed("foo", "GET", "whatever") {
		t.Error("Authorization should pass with correct user")
	}
}
