#!/bin/bash

declare -r SPIRE_VERSION="0.4"
declare -r SPIRE_URL="https://github.com/spiffe/spire/releases/download/${SPIRE_VERSION}/spire-${SPIRE_VERSION}-linux-x86_64-glibc.tar.gz"
declare -r SPIRE_DIR="/opt/spire"

curl --progress-bar --location ${SPIRE_URL} | tar xzf -
rm -rf ${SPIRE_DIR}
mv -v spire-${SPIRE_VERSION} /opt/spire/
chmod -R 777 ${SPIRE_DIR}
mkdir ${SPIRE_DIR}/.data
cp ./spire_server.conf ${SPIRE_DIR}/conf/server/server.conf
cp ./spire_agent.conf ${SPIRE_DIR}/conf/agent/agent.conf
