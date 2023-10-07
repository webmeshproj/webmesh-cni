# webmesh-cni

This is a CNI plugin for Kubernetes that allows you to connect pods to a Webmesh network.
You may then optionally expose the nodes running the CNI plugin to remote users or networks.

## Installation

The [bundle](deploy/bundle.yaml) in this repository and alongside the [published releases](https://github.com/webmeshproj/webmesh-cni/releases) can be used to install the CNI into your cluster.
The signatures of the signed bundles can be verified using cosign:

```bash
# Change this to a specific release version if you'd like
DOWNLOAD_URL="https://github.com/webmeshproj/webmesh-cni/releases/latest/download"
# Download the bundle manifest.
curl -JLO ${DOWNLOAD_URL}/bundle.yaml
# Verify the bundle signature.
export COSIGN_EXPERIMENTAL=1
cosign verify-blob \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity-regexp="github\.com/webmeshproj/webmesh-cni" \
    --signature="${DOWNLOAD_URL}/bundle.yaml.sig" \
    --certificate="${DOWNLOAD_URL}/bundle.yaml.sig.cert" \
    bundle.yaml

# Should return: Verified OK
```

The container images are also signed and can be verified using cosign:

```bash
export COSIGN_EXPERIMENTAL=1
cosign verify --output=text \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com \
    --certificate-identity-regexp="github\.com/webmeshproj/webmesh-cni" \
    ghcr.io/webmeshproj/webmesh-cni:latest
```

First remove any existing CNI installations, then you can install the downloaded bundle or directly from the releases with:

```bash
kubectl apply -f https://github.com/webmeshproj/webmesh-cni/releases/latest/download/bundle.yaml
```

## Configuration

The CNI is configured via the `webmesh-cni` daemonset and configmap found [here](deploy/cni/cni.yaml) as well as in the bundle.
The configmap contains configurations to apply to container interfaces, and the daemonset runs the CNI plugin on each node.
The daemonset can be configured with command-line flags and environment variables.
To see the available options, you can run the container with the `--help` flag.

```bash
docker run ghcr.io/webmeshproj/webmesh-cni:latest --help
```

## Development

A [Makefile](Makefile) is provided to build and test the CNI plugin.
A [Kind configuration](deploy/kindconfig.yaml) is also provided for creating test clusters locally capable of running the CNI.

To see all available options in the Makefile, run:

```bash
make help
```
