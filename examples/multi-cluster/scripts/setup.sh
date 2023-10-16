#!/bin/bash

CLUSTER_NAME_PREFIX=${CLUSTER_NAME_PREFIX:-multi-cluster}
KUBECONFIG_ONE=${KUBECONFIG_ONE:-cluster-one-kubeconfig.yaml}
KUBECONFIG_TWO=${KUBECONFIG_TWO:-cluster-two-kubeconfig.yaml}

set -ex

# Create the clusters

kind create cluster \
    --name ${CLUSTER_NAME_PREFIX}-one \
    --kubeconfig ${KUBECONFIG_ONE} \
    --config ./cluster-one.yaml
kubectl --kubeconfig ${KUBECONFIG_ONE} config set-context --current --namespace kube-system

# Set the server address to the docker IP so the kubeconfig will work
# inside the docker network
DOCKER_IP=$(docker inspect \
    -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    ${CLUSTER_NAME_PREFIX}-one-control-plane)
sed -i "s/127\.0\.0\.1:.*$/${DOCKER_IP}:6443/g" ${KUBECONFIG_ONE}

kind create cluster \
    --name ${CLUSTER_NAME_PREFIX}-two \
    --kubeconfig ${KUBECONFIG_TWO} \
    --config ./cluster-two.yaml
kubectl --kubeconfig ${KUBECONFIG_TWO} config set-context --current --namespace kube-system

DOCKER_IP=$(docker inspect \
    -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' \
    ${CLUSTER_NAME_PREFIX}-two-control-plane)
sed -i "s/127\.0\.0\.1:.*$/${DOCKER_IP}:6443/g" ${KUBECONFIG_TWO}

# Install each kubernetes configuration to the opposite cluster
# In a real world situation this should be a kubeconfig with
# credentials restricted to webmesh objects only. For an example
# see the RBAC manifests in the bundle. These are the the objects
# provided by the bundle in the storage-provider and the CNI APIs.

kubectl --kubeconfig ${KUBECONFIG_ONE} --namespace kube-system \
        create secret generic cluster-two-credentials --from-file=kubeconfig=${KUBECONFIG_TWO}

kubectl --kubeconfig ${KUBECONFIG_TWO} --namespace kube-system \
        create secret generic cluster-one-credentials --from-file=kubeconfig=${KUBECONFIG_ONE}

# Install the CNI to both clusters

kubectl kustomize deploy-one | kubectl --kubeconfig ${KUBECONFIG_ONE} apply -f -
kubectl kustomize deploy-two | kubectl --kubeconfig ${KUBECONFIG_TWO} apply -f -
