FROM ubuntu:xenial

RUN apt-get update && apt-get -y install \
    curl unzip git build-essential autoconf automake dh-autoreconf libtool pkg-config libssl-dev g++
WORKDIR /opt/nginx-dev

COPY build_nginx.sh .
RUN ./build_nginx.sh
