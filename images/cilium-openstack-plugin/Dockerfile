# syntax=docker/dockerfile:1.2

ARG GOLANG_IMAGE=docker.io/library/golang:1.18.6@sha256:f1741ed3855b1a558f3c057f777667a4b73ff250c4f1bee7f0388cc2d1224079
ARG UBUNTU_IMAGE=docker.io/library/ubuntu:22.04@sha256:4b1d0c4a2d2aaf63b37111f34eb9fa89fa1bf53dd6e4ca954d47caebca4005c2


FROM --platform=${BUILDPLATFORM} ${GOLANG_IMAGE} as builder
ARG TARGETARCH
ARG TARGETOS
ARG NOSTRIP
ARG NOOPT
ARG LOCKDEBUG
ARG RACE

RUN \
    apt-get update && \
    apt-get upgrade -y --no-install-recommends && \
    apt-get install -y --no-install-recommends \
      libvirt-dev \
      make && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

WORKDIR /go/src/github.com/cilium/cilium/plugins/cilium-openstack
RUN --mount=type=bind,readwrite,target=/go/src/github.com/cilium/cilium --mount=target=/root/.cache,type=cache --mount=target=/go/pkg,type=cache \
    make GOARCH=${TARGETARCH} RACE=${RACE} NOSTRIP=${NOSTRIP} NOOPT=${NOOPT} LOCKDEBUG=${LOCKDEBUG} \
    && mkdir -p /out/${TARGETOS}/${TARGETARCH}/usr/bin && mv cilium-openstack /out/${TARGETOS}/${TARGETARCH}/usr/bin

FROM ${UBUNTU_IMAGE}

ARG TARGETARCH
ARG TARGETOS
LABEL maintainer="infra8@firma.seznam.cz"
RUN \
    apt-get update && \
    apt-get install -y --no-install-recommends \
      libvirt-dev && \
    apt-get purge --auto-remove && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

COPY --from=builder /out/${TARGETOS}/${TARGETARCH}/usr/bin/cilium-openstack /usr/bin/cilium-openstack

WORKDIR /
CMD ["/usr/bin/cilium-openstack"]
