Elastic Guardian
================

[![Build Status](https://travis-ci.org/alexaandru/elastic_guardian.png?branch=master)](https://travis-ci.org/alexaandru/elastic_guardian)
[![GoDoc](https://godoc.org/github.com/alexaandru/elastic_guardian?status.png)](https://godoc.org/github.com/alexaandru/elastic_guardian)
[![status](https://sourcegraph.com/api/repos/github.com/alexaandru/elastic_guardian/badges/status.png)](https://sourcegraph.com/github.com/alexaandru/elastic_guardian)
[![Coverage Status](https://coveralls.io/repos/alexaandru/elastic_guardian/badge.png?branch=master)](https://coveralls.io/r/alexaandru/elastic_guardian?branch=master)

**Elastic Guardian** is a tiny reverse proxy that can offer authentication (using HTTP Basic Auth) as well as authorization.

While it was originally meant as a thin layer between **Elasticsearch** (which has no builtin authentication/authorization) and the World,
there is nothing specific to **Elasticsearch** (other than a few defaults which can be changed via command line flags).

The generic use case for **Elastic Guardian** is to restrict access to a HTTP API with HTTP Basic Auth and authorization rules.

TODO
----

 1. implement graceful shutdown;
 2. improve docs (add examples where applicable, etc.).
