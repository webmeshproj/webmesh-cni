#!/bin/bash

CLUSTER_NAME_PREFIX=${CLUSTER_NAME_PREFIX:-multi-cluster}

set -ex

kind delete cluster --name ${CLUSTER_NAME_PREFIX}-one
kind delete cluster --name ${CLUSTER_NAME_PREFIX}-two
rm -f cluster-one.kubeconfig cluster-two.kubeconfig
