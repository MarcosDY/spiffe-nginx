#!/bin/bash

export LD_LIBRARY_PATH="/go/src/github.com/spiffe/ngx_http_fetch_spiffe_certs_module:$LD_LIBRARY_PATH"
exec ./nginx -c /opt/nginx-dev/spiffe-support/$1
