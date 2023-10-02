FROM alpine:3.18

RUN apk add --update --no-cache wireguard-tools net-tools nftables iproute2

ARG TARGETOS TARGETARCH
ADD dist/webmesh-cni_${TARGETOS}_${TARGETARCH}*/webmesh-cni /webmesh-cni-node

# Create symlinks as install and plugin executables.
RUN ln -s /webmesh-cni-node /webmesh-cni-install && \
    ln -s /webmesh-cni-node /webmesh

ENTRYPOINT ["/webmesh-cni-node"]