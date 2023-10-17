# ID Authentication Example

This example is similar to the [single-cluster](../single-cluster/) example, but it enables ID authentication on the CNI and allows external Webmesh users to connect to the cluster as an "App Service".

The Webmesh core supports multiple authentication mechanisms, with more possible via plugins.
The current built-in mechanisms are Basic, LDAP, mTLS, and ID authentication.
This example uses ID authentication, which (when combined with TLS) is among the more secure and flexible authentication mechanisms.
For more information on how the ID authentication works, refer to the [idauth-example](https://github.com/webmeshproj/webmesh/tree/main/examples/idauth-plugin) in the Webmesh repo.

## Usage

Usage is similar to the [single-cluster](../single-cluster/) example.
First we'll create a `kind` cluster with the configuration in this directory.

```bash
kind create cluster --config kindconfig.yaml --name webmesh-cni
```

We are going to install two things into the cluster.
The main CNI components, and a secret containing a list of allowed IDs that will be mounted into the CNI node.
The ID in the secret is the ID corresponding to the private key in the `example-user.key` file in this directory.
You can generate the ID with `wmctl`.

```bash
wmctl keyid < example-user.key
```

We'll use `kustomize` to install the manifests in the [deploy](deploy/) directory.

```bash
kubectl kustomize deploy | kubectl apply -f -
```

After a few seconds, the webmesh CNI should be installed and running.
You can verify this by ensuring all pods are ready and running.

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

## Deploy an App

An example whoami app is provided in the [deploy](deploy/) directory.
We'll install it with `kubectl`.

```bash
kubectl apply -f deploy/example-app.yaml
```

The app will have the cluster address `whoami.default.svc.cluster.local`.

## Connect to the Cluster

Since the Webmesh APIs and WireGuard ports are exposed in the kind configuration, we can connect to the cluster from outside.
We can use either a regular `webmesh-node` or `wmctl` to connect to the cluster.
For this example, we'll just use `wmctl`.

```bash
# View the status of the main node
wmctl --tls-skip-verify --server localhost:8443 --id-auth-key example-user.key status

# Connect to the cluster via WireGuard
sudo wmctl --tls-skip-verify --server localhost:8443 --id-auth-key example-user.key connect --use-mesh-dns
```

Once connected, you should be able to access the app from your local machine via its cluster address.

```bash
$ curl whoami.default.svc.cluster.local
Hostname: whoami-56466f5d68-zgmxr
IP: 127.0.0.1
IP: ::1
IP: 10.42.0.5
IP: fd00:10:42:429f:acd4:58d6:793c:0
RemoteAddr: 10.42.0.1:35370
GET / HTTP/1.1
Host: whoami.default.svc.cluster.local
User-Agent: curl/8.4.0
Accept: */*
```

When you are finished, you can delete the cluster:

```bash
kind delete cluster --name webmesh-cni
```
