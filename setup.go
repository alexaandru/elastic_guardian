package main

import (
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
)

var inlineCredentials = aa.CredentialsStore{
	"foo": aa.Hash("bar"),
	"baz": aa.Hash("boo"),
}

var inlineAuthorizations = az.AuthorizationStore{
	"foo": az.AuthorizationRules{az.Allow, []string{"GET /_cluster/health"}},
	"baz": az.AuthorizationRules{az.Deny, []string{"GET /_cluster/health"}},
}
