Elasticguardian
===============

**Elasticsearch Guardian** - a tiny reverse proxy that can offer authentication (using HTTP Basic Auth) as well as authorization.

TODO
----

 1. add tests (incl net/http/httptest aka functional tests);
 1. logging must be async;
 1. implement swappable backends for auth*;
 1. implement two proof of concept auth backends: go/struct (current) and file based (htpasswd like);
 1. encrypt credentials at rest;
 1. Make BackendURL/FrontendURL configurable (via command line flag?/env var?/ini file?/etc.).
