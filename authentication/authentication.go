/*
Package authentication implements a very minimal HTTP Basic Auth header
verification mechanism.

Before it can operate it needs to load the credentials from a backend via
LoadCredentials().

Currently supported backends:

	a CredentialsStore variable directly
	a Reader which can deliver data as specified in LoadCredentialsFromReader()

Once credentials are loaded the main functionality is available via BasicAuthPassed()
which can report if a given Authorization header matches any of the loaded credentials.
*/
package authentication

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

// CredentialsStore defines the storage type for credentials.
type CredentialsStore map[string]string

// The possible statuses of authentication process
const (
	_ = iota
	NotAttempted
	NotBasic
	Failed
	Passed
)

var credentials CredentialsStore

// LoadCredentials loads the given credentials into the library.
func LoadCredentials(backend interface{}) (err error) {
	switch v := backend.(type) {
	case CredentialsStore:
		credentials = v
	case io.Reader:
		err = LoadCredentialsFromReader(v)
	case string:
		f, e := os.Open(v)
		if e != nil {
			return e
		}

		LoadCredentials(f)

	default:
		err = errors.New("don't know how to handle backend")
	}

	return
}

// LoadCredentialsFromReader loads the credentials from the given r io.Reader into the library.
// The file must have the format:
//
// 		username:sha256_of_password
func LoadCredentialsFromReader(r io.Reader) (err error) {
	rawData, err := ioutil.ReadAll(r)
	if err == nil {
		lines, cs := strings.Split(strings.Trim(string(rawData), "\n"), "\n"), CredentialsStore{}
		for _, line := range lines {
			tokens := strings.Split(strings.Trim(line, " "), ":")
			user, pass := tokens[0], tokens[1]
			cs[user] = pass
		}

		return LoadCredentials(cs)
	}

	return
}

// Hash generates a hash of the given string. Used for hashing passwords.
func Hash(str string) (hash string) {
	h := sha256.New()
	io.WriteString(h, str)

	return fmt.Sprintf("%x", h.Sum(nil))
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
	user, pass := tokens[0], Hash(tokens[1])

	if credentials[user] == pass {
		return Passed, user
	}
	return Failed, user
}
