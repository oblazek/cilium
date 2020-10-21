#!/bin/bash
set -e
set -x

PROVISIONSRC="/tmp/provision"

# IP address at which the clustermesh-apiserver service is reachable at
CLUSTER_IP="192.168.36.11"

CILIUM_OPTS=" --debug --ipv4-node 192.168.36.10"
CILIUM_OPTS+=" --join-cluster"
CILIUM_OPTS+=" --kvstore etcd --kvstore-opt etcd.config=/var/lib/cilium/etcd/config.yaml"

# Build docker image
DOCKER_BUILDKIT=1 make -C /home/vagrant/go/src/github.com/cilium/cilium dev-docker-image

mkdir -p /var/lib/cilium/etcd
cp "${PROVISIONSRC}"/externalworkload-client-ca.crt /var/lib/cilium/etcd/ca.crt
cp "${PROVISIONSRC}"/externalworkload-client-tls.crt /var/lib/cilium/etcd/tls.crt
cp "${PROVISIONSRC}"/externalworkload-client-tls.key /var/lib/cilium/etcd/tls.key
tee /var/lib/cilium/etcd/config.yaml <<EOF
---
trusted-ca-file: /var/lib/cilium/etcd/ca.crt
cert-file: /var/lib/cilium/etcd/tls.crt
key-file: /var/lib/cilium/etcd/tls.key
endpoints:
- https://clustermesh-apiserver.cilium.io:32379
EOF

# Etcd TLS config needs hostname IP mapping
CLUSTER_HOST="clustermesh-apiserver.cilium.io:$CLUSTER_IP"

DOCKER_OPTS=" -d --log-driver syslog --restart always"
DOCKER_OPTS+=" --privileged --network host --cap-add NET_ADMIN --cap-add SYS_MODULE"
DOCKER_OPTS+=" --volume /var/lib/cilium/etcd:/var/lib/cilium/etcd"
DOCKER_OPTS+=" --volume /var/run/cilium:/var/run/cilium"
DOCKER_OPTS+=" --volume /boot:/boot"
DOCKER_OPTS+=" --volume /lib/modules:/lib/modules"
DOCKER_OPTS+=" --volume /sys/fs/bpf:/sys/fs/bpf"
DOCKER_OPTS+=" --volume /run/xtables.lock:/run/xtables.lock"
DOCKER_OPTS+=" --add-host $CLUSTER_HOST"

docker run --name cilium $DOCKER_OPTS cilium/cilium-dev:latest cilium-agent $CILIUM_OPTS

# Copy Cilium CLI
docker cp cilium:/usr/bin/cilium /usr/bin/cilium
