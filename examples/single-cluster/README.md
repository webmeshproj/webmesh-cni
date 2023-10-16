# Single Cluster

This example shows how to deploy the webmesh CNI to a single cluster.
The example uses a dual-stack cluster with IPv4 and IPv6 enabled.

## Usage

This and all other examples assume you have either a local Kubernetes cluster or [kind](https://kind.sigs.k8s.io/docs/user/quick-start/) installed.
If not using a `kind` cluster, ensure you patch the deployment manifests to match the domain and subnets of your cluster.
For an example of this, see the [multi-cluster](../multi-cluster/) example.

To create a cluster for the example:

```bash
# You can change the cluster name to whatever you want
kind create cluster --config kindconfig.yaml --name webmesh-cni
```

The cluster will be setup without any CNI installed.
You can use the `kustomization` in the [deploy](deploy/) directory to install the webmesh CNI:

```bash
kubectl kustomize deploy | kubectl apply -f -
```

After a few seconds, the webmesh CNI should be installed and running.
You can verify this by ensuring the `webmesh-node` and `coredns` pods are all ready.

```bash
$ kubectl get pod -A
NAMESPACE            NAME                                                READY   STATUS    RESTARTS   AGE
kube-system          coredns-5d78c9869d-wnrrt                            1/1     Running   0          40s
kube-system          coredns-5d78c9869d-xvchg                            1/1     Running   0          40s
kube-system          etcd-webmesh-cni-control-plane                      1/1     Running   0          53s
kube-system          kube-apiserver-webmesh-cni-control-plane            1/1     Running   0          55s
kube-system          kube-controller-manager-webmesh-cni-control-plane   1/1     Running   0          53s
kube-system          kube-proxy-cw5c6                                    1/1     Running   0          40s
kube-system          kube-proxy-z5227                                    1/1     Running   0          36s
kube-system          kube-scheduler-webmesh-cni-control-plane            1/1     Running   0          54s
kube-system          webmesh-node-6n6qd                                  1/1     Running   0          21s
kube-system          webmesh-node-xvh76                                  1/1     Running   0          21s
local-path-storage   local-path-provisioner-6bc4bddd6b-cztfz             1/1     Running   0          40s
```

At this point you have little-more than a WireGuard networked cluster.
In the `kind` examples, the webmesh API is exposed at `localhost:8443` and can be queried with the `wmctl` utility from the [webmesh](https://webmeshproj.github.io/documentation/installation-instructions/) package.

```bash
# Retrieve the status of the main node
wmctl --tls-skip-verify --server localhost:8443 status
# List all the current "nodes" in the cluster. A "node" is created for each container.
wmctl --tls-skip-verify --server localhost:8443 get nodes
# Visualize a graph of the cluster
wmctl --tls-skip-verify --server localhost:8443 get graph | dot -Tsvg > graph.svg
```

When you are finished, you can delete the cluster:

```bash
kind delete cluster --name webmesh-cni
```
