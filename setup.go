package main

import (
	aa "github.com/alexaandru/elastic_guardian/authentication"
	az "github.com/alexaandru/elastic_guardian/authorization"
)

var inlineCredentials = aa.CredentialsStore{
// "foo": aa.Hash("bar"), // user foo can log in with password bar
// "baz": aa.Hash("boo"), //  ~~  baz             ~~           boo
}

var inlineAuthorizations = az.AuthorizationStore{
// Blacklisting example: user foo can access EVERYTHING except GET /secret
// "foo": az.AuthorizationRules{az.Allow, []string{"GET /secret"}},
// Whitelisting example: user baz can access NOTHING except GET /public
// "baz": az.AuthorizationRules{az.Deny, []string{"GET /public"}},
}
