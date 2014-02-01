/*
Package authorization implements a basic authorization "engine".

It comes with a builtin, proof of concept, authorization rules container/storage.
*/
package authorization

import (
	"errors"
	"io"
	"io/ioutil"
	"strings"
)

/*
AuthorizationRules groups together authorization rules for one use.

It is implemented as a combination of DefaultRule and a list of
exception rules, as follows:

1. if DefaultRule == true; then rules is used as a blacklisting mechanism;
2. if DefaultRule == false; then rules is used as a whitelisting mechanism.

These combined allow for flexible and granular access control.
*/
type AuthorizationRules struct {
	DefaultRule bool
	Rules       []string
}

// AuthorizationStore implements a type for storing all authorization rules.
type AuthorizationStore map[string]AuthorizationRules

// Small shortcut constants, for clarity.
const Allow, Deny = true, false

// holds the authorizations
var authorizations AuthorizationStore

// LoadAuthorizations loads the given authorizations into the library.
func LoadAuthorizations(backend interface{}) (err error) {
	switch v := backend.(type) {
	case AuthorizationStore:
		authorizations = v
	case io.Reader:
		err = LoadAuthorizationsFromReader(v)
	default:
		err = errors.New("don't know how to handle backend")
	}

	return
}

// LoadAuthorizationsFromReader loads the authorizations from the given r io.Reader into the library.
// The file must have the format:
//
// 		username:default_rule:rule1:...:ruleN
func LoadAuthorizationsFromReader(r io.Reader) (err error) {
	rawData, err := ioutil.ReadAll(r)
	if err == nil {
		lines, as := strings.Split(strings.Trim(string(rawData), "\n"), "\n"), AuthorizationStore{}
		for _, line := range lines {
			tokens := strings.Split(strings.Trim(line, " "), ":")
			if len(tokens) < 2 {
				return errors.New("Invalid authorization line: " + line)
			}

			user := tokens[0]

			rule := false
			if tokens[1] == "allow" {
				rule = Allow
			} else if tokens[1] == "deny" {
				rule = Deny
			} else {
				return errors.New("Unknown default rule " + tokens[1])
			}

			as[user] = AuthorizationRules{rule, tokens[2:]}
		}

		return LoadAuthorizations(as)
	}

	return
}

// isEmpty determines if the given AuthorizationRules structure is empty.
func (ar AuthorizationRules) isEmpty() bool {
	return !ar.DefaultRule && len(ar.Rules) == 0
}

// hasRule determine if the given ar has a rule referring to verb + path.
func (ar AuthorizationRules) hasRule(verb, path string) bool {
	cannonicalRule := verb + " " + path
	for _, rule := range ar.Rules {
		if rule == cannonicalRule {
			return true
		}
	}

	return false
}

// hasNoRule see hasRule and negate that.
func (ar AuthorizationRules) hasNoRule(verb, path string) bool {
	return !ar.hasRule(verb, path)
}

// Allows determines if a give verb + path combination is allowed by ar.
func (ar AuthorizationRules) allows(verb, path string) bool {
	if ar.DefaultRule {
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

	ar := authorizations[user]
	if ar.isEmpty() {
		return false
	}

	return ar.allows(verb, path)
}
