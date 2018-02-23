#!/bin/bash

declare -r NGINX_VERSION="1.12.2"
declare -r NGINX_URL="http://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz"

set -e
[[ $DEBUG ]] && set -x

if [[ ! -d nginx-${NGINX_VERSION} ]]; then
	curl --progress-bar --location ${NGINX_URL} | tar -xzf -
fi

cd nginx-${NGINX_VERSION}

case $1 in
	configure)
		./configure $_config \
			--with-debug \
			--with-cc-opt="" \
			--with-ld-opt="-lstdc++ -lssl -lcrypto"
		;;
	make)
		make
		cp objs/nginx ..
		;;
	clean)
		make clean
		;;
esac


