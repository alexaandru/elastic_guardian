Elastic Guardian
================

[![Build Status](https://travis-ci.org/alexaandru/elastic_guardian.png?branch=master)](https://travis-ci.org/alexaandru/elastic_guardian)

**Elastic Guardian** is a tiny reverse proxy that can offer authentication (using HTTP Basic Auth) as well as authorization.

While it was originally meant as a thin layer between **Elasticsearch** (which has no builtin authentication/authorization) and the World,
there is nothing specific to **Elasticsearch**. The generic use case for **Elastic Guardian** is to restrict
access to a HTTP API with HTTP Basic Auth and authorization rules.

TODO
----

 1. add functional tests (via net/http/httptest);
 1. implement swappable backends for auth*;
 1. implement two proof of concept auth backends: go/struct (current) and file based (htpasswd like);
 1. encrypt credentials at rest;
 1. more meaningful (simpler/one line?) log entries.
