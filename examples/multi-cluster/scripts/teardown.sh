#!/bin/bash

CLUSTER_NAME_PREFIX=${CLUSTER_NAME_PREFIX:-multi-cluster}
KUBECONFIG_ONE=${KUBECONFIG_ONE:-cluster-one-kubeconfig.yaml}
KUBECONFIG_TWO=${KUBECONFIG_TWO:-cluster-two-kubeconfig.yaml}

set -ex

kind delete cluster --name ${CLUSTER_NAME_PREFIX}-one
kind delete cluster --name ${CLUSTER_NAME_PREFIX}-two
rm -f ${KUBECONFIG_ONE} ${KUBECONFIG_TWO}

