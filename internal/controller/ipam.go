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
	"sync/atomic"
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

// IPAMLocker is the interface for taking a distributed lock during IPv4 allocations.
type IPAMLocker interface {
	// Acquire attempts to acquire the lock. If a lock is already acquired, the
	// lock count is incremented. When the lock is released, the lock count is
	// decremented. When the lock count reaches 0, the lock is released.
	Acquire(ctx context.Context) error
	// Release releases the lock. This decrements the lock count. When the lock
	// count reaches 0, the lock is released.
	Release(ctx context.Context)
}

// Lock is the interface for a lock.
type Lock interface {
	// Release releases the lock.
	Release(ctx context.Context)
}

// NewIPAMLock creates a new IPAM lock.
func NewIPAMLock(cfg *rest.Config, config ManagerConfig) (IPAMLocker, error) {
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
	ipamlock := &ipamLock{
		rlock:  rlock,
		config: config,
	}
	return ipamlock, nil
}

type ipamLock struct {
	rlock     resourcelock.Interface
	config    ManagerConfig
	lockCount atomic.Int32
	mu        sync.Mutex
}

// Acquire attempts to acquire the lock.
func (l *ipamLock) Acquire(ctx context.Context) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	log := log.FromContext(ctx).WithName("ipam-lock")
	if l.lockCount.Load() > 0 {
		log.V(1).Info("Lock already held, attempting to renew and increment lock count")
		// Try to update the lock with a renew time.
		lock, _, err := l.rlock.Get(ctx)
		if err == nil {
			lock.RenewTime = metav1.NewTime(time.Now().UTC())
			err = l.rlock.Update(ctx, *lock)
			if err == nil {
				l.lockCount.Add(1)
				return nil
			}
			log.Error(err, "Failed to renew IPAM lock")
			l.lockCount.Store(0)
			return fmt.Errorf("failed to renew IPAM lock: %w", err)
		}
		log.Error(err, "Failed to get IPAM lock")
		l.lockCount.Store(0)
		return fmt.Errorf("failed to acquire IPAM lock: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.IPAMLockTimeout)
	defer cancel()
	for {
		// Check if the lock has already been created.
		lock, _, err := l.rlock.Get(ctx)
		if err == nil {
			// Check if there is a holder for the lock.
			if lock.HolderIdentity != "" {
				// Check if the lock expired.
				if !lock.RenewTime.IsZero() || !lock.AcquireTime.IsZero() {
					var lockExpiry time.Time
					if !lock.RenewTime.IsZero() {
						lockExpiry = lock.RenewTime.Add(time.Duration(lock.LeaseDurationSeconds) * time.Second)
					} else {
						lockExpiry = lock.AcquireTime.Add(time.Duration(lock.LeaseDurationSeconds) * time.Second)
					}
					if lockExpiry.After(time.Now().UTC()) {
						log.V(1).Info("Lock currently held, retrying...", "holder", lock.HolderIdentity)
						goto Retry
					}
					// The lock has expired, try to acquire it.
				}
			}
			// Try to update the lock.
			lock.LeaseDurationSeconds = int(l.config.IPAMLockDuration.Seconds())
			lock.HolderIdentity = l.config.NodeName
			lock.AcquireTime = metav1.NewTime(time.Now().UTC())
			lock.RenewTime = metav1.NewTime(time.Now().UTC())
			err = l.rlock.Update(ctx, *lock)
			if err == nil {
				// We acquired the lock.
				l.lockCount.Add(1)
				return nil
			}
			log.Error(err, "Failed to acquire IPAM lock, retrying...")
			goto Retry
		}
		// Try to create the lock.
		lock = &resourcelock.LeaderElectionRecord{
			HolderIdentity:       l.config.NodeName,
			LeaseDurationSeconds: int(l.config.IPAMLockDuration.Seconds()),
		}
		err = l.rlock.Create(ctx, *lock)
		if err == nil {
			l.lockCount.Add(1)
			return nil
		}
		log.Error(err, "Failed to acquire IPAM lock, retrying...")
	Retry:
		select {
		case <-ctx.Done():
			return fmt.Errorf("failed to acquire IPAM lock: %w", ctx.Err())
		default:
			time.Sleep(time.Second)
		}
	}
}

func (l *ipamLock) Release(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	lockCount := l.lockCount.Load()
	if lockCount <= 0 {
		return
	}
	lockCount--
	l.lockCount.Store(lockCount)
	if lockCount > 0 {
		return
	}
	err := l.rlock.Update(ctx, resourcelock.LeaderElectionRecord{
		HolderIdentity:       "",
		LeaseDurationSeconds: int(l.config.IPAMLockDuration.Seconds()),
	})
	if err != nil {
		log.FromContext(ctx).WithName("ipam-lock").Error(err, "Failed to release IPAM lock")
	}
}
