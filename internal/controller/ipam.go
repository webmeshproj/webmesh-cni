/*
Copyright 2023 Avi Zimmerman <avi.zimmerman@gmail.com>.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"context"
	"fmt"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	coordinationv1client "k8s.io/client-go/kubernetes/typed/coordination/v1"
	corev1client "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IPAMLockID is the ID used for the IPAM lock.
const IPAMLockID = "webmesh-cni-ipam"

// IPAMLock is the interface for taking a distributed lock during IPAM
// allocations.
type IPAMLock struct {
	resourcelock.Interface
	config    ManagerConfig
	lockHeld  bool
	lockCount int
	rlock     Lock
	mu        sync.Mutex
}

// NewIPAMLock creates a new IPAM lock.
func NewIPAMLock(cfg *rest.Config, config ManagerConfig) (*IPAMLock, error) {
	corev1client, err := corev1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create corev1 client: %w", err)
	}
	coordinationClient, err := coordinationv1client.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("create coordinationv1 client: %w", err)
	}
	// Create the IPAM lock.
	rlock, err := resourcelock.New(
		"leases",
		config.Namespace,
		IPAMLockID,
		corev1client,
		coordinationClient,
		resourcelock.ResourceLockConfig{
			Identity: config.NodeName,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("create resource lock interface: %w", err)
	}
	ipamlock := &IPAMLock{
		Interface: rlock,
		config:    config,
	}
	ipamlock.rlock = &ipamLock{IPAMLock: ipamlock}
	return ipamlock, nil
}

// Acquire attempts to acquire the lock.
func (l *IPAMLock) Acquire(ctx context.Context) (Lock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	log := log.FromContext(ctx).WithName("ipam-lock")
	if l.lockHeld {
		log.V(1).Info("Lock already held, incrementing lock count")
		// Try to update the lock with a renew time.
		lock, _, err := l.Interface.Get(ctx)
		if err == nil {
			lock.RenewTime = metav1.Now()
			err = l.Interface.Update(ctx, *lock)
			if err == nil {
				l.lockCount++
				return l.rlock, nil
			}
			log.Error(err, "Failed to renew IPAM lock")
			// We'll still let a current holder try to release the lock.
			return nil, fmt.Errorf("failed to renew IPAM lock: %w", err)
		}
		// Something very bad happened, we'll try to acquire the lock again next time.
		log.Error(err, "Failed to get IPAM lock")
		l.lockHeld = false
		l.lockCount = 0
		return nil, fmt.Errorf("failed to acquire IPAM lock: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.IPAMLockTimeout)
	defer cancel()
	for {
		// Check if the lock has already been created.
		lock, _, err := l.Interface.Get(ctx)
		if err == nil {
			// Check if there is a holder for the lock.
			if lock.HolderIdentity != "" {
				// Check if the lock expired.
				if !lock.RenewTime.IsZero() && time.Now().Before(lock.RenewTime.Time) {
					log.V(1).Info("Lock currently held, retrying...", "holder", lock.HolderIdentity)
					goto Retry
				}
				if !lock.AcquireTime.IsZero() && time.Now().Before(lock.AcquireTime.Time.Add(l.config.IPAMLockDuration)) {
					log.V(1).Info("Lock currently held, retrying...", "holder", lock.HolderIdentity)
					goto Retry
				}
			}
			// Try to update the lock.
			lock.LeaseDurationSeconds = int(l.config.IPAMLockDuration.Seconds())
			lock.HolderIdentity = l.config.NodeName
			lock.AcquireTime = metav1.Now()
			err = l.Interface.Update(ctx, *lock)
			if err == nil {
				// We acquired the lock.
				l.lockHeld = true
				l.lockCount = 1
				return l.rlock, nil
			}
			log.Error(err, "Failed to acquire IPAM lock, retrying...")
			goto Retry
		}
		// Try to create the lock.
		lock = &resourcelock.LeaderElectionRecord{
			HolderIdentity:       l.config.NodeName,
			LeaseDurationSeconds: int(l.config.IPAMLockDuration.Seconds()),
		}
		err = l.Interface.Create(ctx, *lock)
		if err == nil {
			l.lockHeld = true
			l.lockCount = 1
			return l.rlock, nil
		}
		log.Error(err, "Failed to acquire IPAM lock, retrying...")
	Retry:
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("failed to acquire IPAM lock: %w", ctx.Err())
		default:
			time.Sleep(time.Second)
		}
	}
}

type Lock interface {
	// Release releases the lock.
	Release(ctx context.Context)
}

type ipamLock struct {
	*IPAMLock
}

func (l *ipamLock) Release(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lockHeld {
		return
	}
	l.lockCount--
	if l.lockCount <= 0 {
		l.lockHeld = false
		err := l.Interface.Update(ctx, resourcelock.LeaderElectionRecord{
			HolderIdentity:       "",
			LeaseDurationSeconds: int(l.config.IPAMLockDuration.Seconds()),
		})
		if err != nil {
			log.FromContext(ctx).WithName("ipam-lock").Error(err, "Failed to release IPAM lock")
		}
	}
}
