#!/bin/bash

declare -r OPENSSL_VERSION="1.0.2k"
declare -r OPENSSL_URL="http://www.openssl.org/source/openssl-${OPENSSL_VERSION}.tar.gz"
declare -r PCRE_VERSION="8.41"
declare -r PCRE_URL="ftp://ftp.csx.cam.ac.uk/pub/software/programming/pcre/pcre-${PCRE_VERSION}.tar.gz"
declare -r ZLIB_VERSION="1.2.11"
declare -r ZLIB_URL="http://zlib.net/zlib-${ZLIB_VERSION}.tar.gz"
declare -r VENDOR_DIR="/tmp/vendor"

set -e
[[ ${DEBUG} ]] && set -x

untar_url() {
	curl --progress-bar --location $1 | tar --directory ${VENDOR_DIR} -xzf -
}

do_pcre() {
	untar_url ${PCRE_URL}
	(
		cd ${VENDOR_DIR}/pcre-${PCRE_VERSION}
		./configure --prefix=/usr
		make
		make install
	)
}

do_zlib() {
	untar_url ${ZLIB_URL}
	(
		cd ${VENDOR_DIR}/zlib-${ZLIB_VERSION}
		./configure --prefix=/usr
		make
		make install
	)
}

do_openssl() {
	untar_url ${OPENSSL_URL}
	(
		cd ${VENDOR_DIR}/openssl-${OPENSSL_VERSION}
		./config shared --prefix=/usr --openssldir=/usr
		make
		make install
	)
}

mkdir -p ${VENDOR_DIR}
do_pcre
do_zlib
do_openssl
rm -rf ${VENDOR_DIR}
