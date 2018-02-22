#!/bin/bash

set -x

declare -r NGINX_VERSION="1.12.2"
declare -r OPENSSL_VERSION="1.0.2k"
declare -r PCRE_VERSION="8.41"
declare -r ZLIB_VERSION="1.2.11"

# The PCRE library – required by NGINX Core and Rewrite modules and provides support for regular expressions
curl --silent --location pcre-${PCRE_VERSION}.tar.gz ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-${PCRE_VERSION}.tar.gz | tar xzf -
cd pcre-${PCRE_VERSION}
./configure
make
make install
cd ..

# The zlib library – required by NGINX Gzip module for headers compression
curl --silent --location zlib-${ZLIB_VERSION}.tar.gz http://zlib.net/zlib-${ZLIB_VERSION}.tar.gz | tar xzf -
cd zlib-${ZLIB_VERSION}
./configure
make
make install
cd ..

# The OpenSSL library – required by NGINX SSL modules to support the HTTPS protocol
curl --silent --location openssl-${OPENSSL_VERSION}.tar.gz http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz | tar xzf -
cd openssl-${OPENSSL_VERSION}
./config
make
make install
cd ..

# gRPC
git clone https://github.com/grpc/grpc
cd grpc
git submodule update --init
make
make install
cd ..

# Protocol Buffers
git clone https://github.com/google/protobuf
cd protobuf
./autogen.sh
./configure
make
make check
make install
ldconfig # refresh shared library cache.
cd ..

# Build Nginx
curl --silent --location nginx-${NGINX_VERSION}.tar.gz http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz | tar xzf -
cd nginx-${NGINX_VERSION}
./configure --with-http_ssl_module --with-openssl="../openssl-${OPENSSL_VERSION}" --with-debug --with-ld-opt="-lstdc++"
make
