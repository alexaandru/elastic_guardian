/*
Package authentication implements a very minimal (and incomplete) HTTP Basic Auth
verification mechanism.

It includes a proof of concept of a credentials store, which should be taken
as it is - just a demo.
*/
package authentication

import (
	"encoding/base64"
	"log"
	"strings"
)

// The possible statuses of authentication process
const (
	_ = iota
	NotAttempted
	NotBasic
	Failed
	Passed
)

// This is just a proof of concept. Not for production use!
var poorMansCredentialStore = map[string]string{
	"foo": "bar",
	"baz": "boo",
}

// BasicAuthPassed verifies an authHeader to see if it passed HTTP Basic Auth.
func BasicAuthPassed(authHeader string) (status int, user string) {
	if authHeader == "" {
		return NotAttempted, user
	}

	tokens := strings.Split(authHeader, " ")
	if len(tokens) != 2 || tokens[0] != "Basic" {
		return NotBasic, user
	}

	data, err := base64.StdEncoding.DecodeString(tokens[1])
	if err != nil {
		log.Println(err)
		return Failed, user
	}

	tokens = strings.Split(string(data), ":")
	user, pass := tokens[0], tokens[1]

	if poorMansCredentialStore[user] == pass {
		return Passed, user
	}
	return Failed, user
}
