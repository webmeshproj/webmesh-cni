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

# Install the kubernetes configurations to each cluster

kubectl --kubeconfig ./cluster-one.kubeconfig \
        --namespace kube-system \
        create secret generic cluster-two-credentials \
        --from-file=kubeconfig=./cluster-two.kubeconfig

kubectl --kubeconfig ./cluster-two.kubeconfig \
        --namespace kube-system \
        create secret generic cluster-one-credentials \
        --from-file=kubeconfig=./cluster-one.kubeconfig
