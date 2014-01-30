package authorization

import "testing"

func TestIsEmpty(t *testing.T) {
	ar := authorizationRules{}
	if !ar.isEmpty() {
		t.Error("isEmpty() should be true with empty authorizationRules")
	}

	ar.defaultRule = allow
	if ar.isEmpty() {
		t.Error("isEmpty() should be false with NON empty authorizationRules")
	}

	ar.defaultRule = deny
	ar.rules = append(ar.rules, "GET /foo")
	if ar.isEmpty() {
		t.Error("isEmpty() should be false with NON empty authorizationRules")
	}
}

func TestHasRule(t *testing.T) {
	ar := authorizationRules{allow, []string{"GET /foobar"}}

	if ar.hasRule("GET", "bar") {
		t.Error("hasRule() should not have GET bar")
	}

	if !ar.hasRule("GET", "/foobar") {
		t.Error("hasRule() should have GET /foobar")
	}
}

func TestHasNoRule(t *testing.T) {
	ar := authorizationRules{allow, []string{"GET /foobar"}}

	if !ar.hasNoRule("GET", "bar") {
		t.Error("hasNoRule() should not have GET bar")
	}

	if ar.hasNoRule("GET", "/foobar") {
		t.Error("hasNoRule() should have GET /foobar")
	}
}

func TestAllowWithWhitelist(t *testing.T) {
	ar := authorizationRules{deny, []string{"GET /foobar"}}

	// Should deny EVERYTHING except defined rules
	if !ar.allows("GET", "/foobar") {
		t.Error("allows() should allow GET /foobar")
	}

	if ar.allows("GET", "/foobars") {
		t.Error("allows() should NOT allow GET /foobars")
	}
}

func TestAllowWithBlacklist(t *testing.T) {
	ar := authorizationRules{allow, []string{"GET /foobar"}}

	// Should allow EVERYTHING except defined rules
	if ar.allows("GET", "/foobar") {
		t.Error("allows() should NOT allow GET /foobar")
	}

	if !ar.allows("GET", "/foobars") {
		t.Error("allows() should allow GET /foobars")
	}
}

func TestAuthorizationFailsWithEmptyUser(t *testing.T) {
	if AuthorizationPassed("", "GET", "whatever") {
		t.Error("Authorization should fail with empty user")
	}
}

func TestAuthorizationFailsWithEmptyRules(t *testing.T) {
	if AuthorizationPassed("bogus", "GET", "whatever") {
		t.Error("Authorization should fail with empty rules for user")
	}
}

func TestAuthorizationPassed(t *testing.T) {
	if !AuthorizationPassed("foo", "GET", "whatever") {
		t.Error("Authorization should pass with correct user")
	}
}
