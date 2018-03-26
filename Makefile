
docker = docker run --name spiffe-nginx -v $(docker_volume) -p 80:80 -it $(docker_image)
docker_volume := $(shell echo $${PWD}):/opt/nginx-dev
docker_image = spiffe-nginx:latest

all: build

container: Dockerfile
	docker build -t $(docker_image) .

build:
	$(docker) ./build.sh make

configure:
	$(docker) ./build.sh configure

clean:
	$(docker) ./build.sh clean

shell:
	$(docker) /bin/bash

.PHONY: build configure clean shell
