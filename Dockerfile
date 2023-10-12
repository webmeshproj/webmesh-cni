FROM ghcr.io/webmeshproj/alpine:3.18

ARG TARGETOS=linux TARGETARCH=amd64
ADD dist/webmesh-cni_${TARGETOS}_${TARGETARCH}*/webmesh-cni /webmesh-cni-node

# Create symlink as install executable
RUN ln -s /webmesh-cni-node /webmesh-cni-install

ENTRYPOINT ["/webmesh-cni-node"]