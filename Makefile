
docker = docker run -v $(docker_volume) -it
docker_volume := $(shell echo $${PWD}):/opt/nginx-dev
docker_image = spiffe-nginx:latest

all: build

container: Dockerfile
	docker build -t $(docker_image) .

build:
	$(docker) --name spiffe-nginx-build --rm $(docker_image) ./build.sh make

configure:
	$(docker) --name spiffe-nginx-build --rm $(docker_image) ./build.sh configure

clean:
	$(docker) --name spiffe-nginx-build --rm $(docker_image) ./build.sh clean

shell:
	$(docker) --name spiffe-nginx-shell --privileged -p 8088:80 $(docker_image) /bin/bash

.PHONY: build configure clean shell
