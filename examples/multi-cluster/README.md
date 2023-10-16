# Multi Cluster Example

This example shows how to deploy the Webmesh CNI to multiple clusters and connect them together.
The example uses two dual-stack clusters with IPv4 and IPv6 enabled.
Authentication for bridging is currently only supported with kubernetes authentication, but the other Webmesh authentication methods will be added in future releases.

## Usage

As with the [simple-example](../simple-example/), this example assumes you have either a local Kubernetes cluster or [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) installed.
If not using a `kind` cluster, ensure you patch the deployment manifests to match the domain and subnets of your cluster.

This example comes with setup and teardown scripts to facilitate the creation and deletion of the clusters more easily.
But the general flow of the initial setup is as follows:

- Create two clusters with `kind`
- Write the credentials for each cluster to the other
- Install the Webmesh CNI on each cluster

First we'll run the `setup.sh` script to create the clusters and install the Webmesh CNI:

```bash
./scripts/setup.sh
```

When this is done you should have two separate clusters with the Webmesh CNI installed.
Their kubeconfigs will be stored in this directory as `cluster-one-kubeconfig.yaml` and `cluster-two-kubeconfig.yaml`.
You can use these to interact with the clusters using `kubectl`.
The kubeconfigs are automatically set to default to the `kube-system` namespace.

```bash
$ kubectl --kubeconfig cluster-one-kubeconfig.yaml get pod -o wide
$ kubectl --kubeconfig cluster-two-kubeconfig.yaml get pod -o wide
```

### Bridge the Clusters

We can now bridge the clusters using the custom resources in each of the deploy directories.
Only one side needs to be configured with the bridge, but we'll do both for this example.
The bridge is configured with the `RemoteNetwork` custom resource.

```bash
kubectl --kubeconfig cluster-one-kubeconfig.yaml apply -f deploy/cluster-one/cluster-two-peering.yaml
kubectl --kubeconfig cluster-two-kubeconfig.yaml apply -f deploy/cluster-two/cluster-one-peering.yaml
```

The clusters should now be bridged.
We can verify this by querying either of the running MeshDNS servers to see if it can resolve domains on both ends.

```bash

```
