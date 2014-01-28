/*
	authorization implements a basic authorization "engine".

	It comes with a builtin, proof of concept, authorization rules
	container/storage.
*/
package authorization

// authorizationRules groups together authorization rules for one use.
//
// It is implemented as a combination of defaultRule and a list of
// exception rules, as follows:
//
// 1. if defaultRule == true; then rules is used as a blacklisting mechanism;
// 2. if defaultRule == false; then rules is used as a whitelisting mechanism.
//
// These combined allow for flexible and granular access control.
type authorizationRules struct {
	defaultRule bool
	rules       []string
}

// Small shortcut constants, for clarity.
const allow, deny = true, false

// A proof of concept authorization rules container.
// Not intended for production!
var poorMansAuthorizationRules = map[string]authorizationRules{
	"foo": authorizationRules{allow, []string{"GET /_cluster/health"}},
	"baz": authorizationRules{deny, []string{"GET /_cluster/health"}},
}

// isEmpty determines if the given authorizationRules structure is empty.
func (ar authorizationRules) isEmpty() bool {
	return !ar.defaultRule && len(ar.rules) == 0
}

// hasRule determine if the given ar has a rule referring to verb + path.
func (ar authorizationRules) hasRule(verb, path string) bool {
	cannonicalRule := verb + " " + path
	for _, rule := range ar.rules {
		if rule == cannonicalRule {
			return true
		}
	}

	return false
}

// hasNoRule see hasRule and negate that.
func (ar authorizationRules) hasNoRule(verb, path string) bool {
	return !ar.hasRule(verb, path)
}

// Allows determines if a give verb + path combination is allowed by ar.
func (ar authorizationRules) allows(verb, path string) bool {
	if ar.defaultRule {
		return ar.hasNoRule(verb, path)
	}

	return ar.hasRule(verb, path)
}

// AuthorizationPassed determines if a give user is authorized to access
// path via verb.
func AuthorizationPassed(user, verb, path string) bool {
	if user == "" {
		return false
	}

	ar := poorMansAuthorizationRules[user]
	if ar.isEmpty() {
		return false
	}

	return ar.allows(verb, path)
}
