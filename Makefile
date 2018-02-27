
docker = docker run -v $(docker_volume) -it $(docker_image)
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
