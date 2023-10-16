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
# View pods and their IPs in the first cluster
kubectl --kubeconfig cluster-one-kubeconfig.yaml get pod -o wide
# View pods and their IPs in the second cluster
kubectl --kubeconfig cluster-two-kubeconfig.yaml get pod -o wide
```

### Bridge the Clusters

We can now bridge the clusters using the custom resources in each of the deploy directories.
Only one side should be configured with the bridge, but this will be changed to support both sides in future releases.
The bridge is configured with the `RemoteNetwork` custom resource.

```bash
# Create the bridge in the first cluster
kubectl --kubeconfig cluster-one-kubeconfig.yaml apply -f deploy/cluster-one/cluster-two-peering.yaml
#
# OR
#
# Create the bridge in the second cluster
kubectl --kubeconfig cluster-two-kubeconfig.yaml apply -f deploy/cluster-two/cluster-one-peering.yaml
```

The clusters should now be bridged.
We can verify this by querying either of the running MeshDNS servers to see if it can resolve domains on both ends.

```bash
# Query the MeshDNS server in the first cluster
$ dig -p 5351 @localhost kubernetes.default.svc.cluster-one.local +short
10.96.0.1
$ dig -p 5351 @localhost kubernetes.default.svc.cluster-two.local +short
10.97.0.1

# Query the MeshDNS server in the second cluster
$ dig -p 5352 @localhost kubernetes.default.svc.cluster-one.local +short
10.96.0.1
$ dig -p 5352 @localhost kubernetes.default.svc.cluster-two.local +short
10.97.0.1
```

### Deploy Apps to Each Cluster

An example `whoami` app is included in the `deploy/` directory.
We can install it to either cluster, then launch a pod to test the connectivity between the clusters.

```bash
# Deploy the app to the first cluster
kubectl --kubeconfig cluster-one-kubeconfig.yaml apply -f deploy/example-app.yaml
```

Launch a debug container in the second cluster and you should be able to curl the `whoami` app in the first cluster.

```bash
# Launch a debug container in the second cluster
kubectl --kubeconfig cluster-two-kubeconfig.yaml run -it --rm --restart=Never --image=alpine:latest -- sh
# From the debug container, curl the whoami app in the first cluster
$ apk add --update curl
$ curl -sS whoami.default.svc.cluster-one.local
```
