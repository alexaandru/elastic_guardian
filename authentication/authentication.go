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

// This is just a proof of concept. Not for production use!
var poorMansCredentialStore = map[string]string{
	"foo": "bar",
	"baz": "boo",
}

// BasicAuthPassed verifies an authHeader to see if it passed HTTP Basic Auth.
func BasicAuthPassed(authHeader string) (ok bool, user string) {
	if authHeader == "" {
		return
	}

	tokens := strings.Split(authHeader, " ")
	method, token := tokens[0], tokens[1]
	if method != "Basic" {
		return
	}

	data, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		log.Println(err)
		return
	}

	tokens = strings.Split(string(data), ":")
	user, pass := tokens[0], tokens[1]

	return poorMansCredentialStore[user] == pass, user
}
