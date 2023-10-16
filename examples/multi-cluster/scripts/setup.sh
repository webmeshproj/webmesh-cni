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

kind create cluster \
    --name ${CLUSTER_NAME_PREFIX}-two \
    --kubeconfig ${KUBECONFIG_TWO} \
    --config ./cluster-two.yaml

kubectl --kubeconfig ${KUBECONFIG_TWO} config set-context --current --namespace kube-system

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
