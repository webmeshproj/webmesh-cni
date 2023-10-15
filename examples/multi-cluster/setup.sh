#!/bin/bash

CLUSTER_NAME_PREFIX=${CLUSTER_NAME_PREFIX:-multi-cluster}

set -ex

# Create the clusters

kind create cluster \
    --name ${CLUSTER_NAME_PREFIX}-one \
    --config ./cluster-one.yaml \
    --kubeconfig ./cluster-one.kubeconfig
kubectl --kubeconfig ./cluster-one.kubeconfig \
        config set-context --current --namespace kube-system

kind create cluster \
    --name ${CLUSTER_NAME_PREFIX}-two \
    --config ./cluster-two.yaml \
    --kubeconfig ./cluster-two.kubeconfig
kubectl --kubeconfig ./cluster-two.kubeconfig \
        config set-context --current --namespace kube-system

# Install each kubernetes configuration to the opposite cluster
# In a real world situation this should be a kubeconfig with
# credentials restricted to webmesh objects only. For an example
# see the RBAC manifests in the bundle. These are the the objects
# provided by the bundle in the storage-provider and the CNI APIs.

kubectl --kubeconfig ./cluster-one.kubeconfig \
        --namespace kube-system \
        create secret generic cluster-two-credentials \
        --from-file=kubeconfig=./cluster-two.kubeconfig

kubectl --kubeconfig ./cluster-two.kubeconfig \
        --namespace kube-system \
        create secret generic cluster-one-credentials \
        --from-file=kubeconfig=./cluster-one.kubeconfig

# Install the CNI to both clusters

kubectl kustomize deploy-one | kubectl --kubeconfig ./cluster-one.kubeconfig apply -f -
kubectl kustomize deploy-two | kubectl --kubeconfig ./cluster-two.kubeconfig apply -f -
