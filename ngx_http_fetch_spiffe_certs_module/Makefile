.PHONY: all utils build clean distclean

build:
	go build \
	-buildmode=c-shared \
	-o ngx_http_fetch_spiffe_certs_module.so \
	ngx_http_fetch_spiffe_certs_module.go

all: utils vendor build

utils:
	go get github.com/Masterminds/glide

vendor: glide.yaml glide.lock
	glide install

clean:
	go clean

distclean:
	go clean -i
	rm -rf vendor dist
