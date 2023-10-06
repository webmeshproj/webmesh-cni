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
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

// IPAMLock is the interface for taking a distributed lock during IPAM
// allocations.
type IPAMLock struct {
	resourcelock.Interface
	config    ManagerConfig
	lockHeld  bool
	lockCount int
	curLock   Lock
	mu        sync.Mutex
}

// Acquire attempts to acquire the lock.
func (l *IPAMLock) Acquire(ctx context.Context) (Lock, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.lockHeld {
		l.lockCount++
		return l.curLock, nil
	}
	ctx, cancel := context.WithTimeout(ctx, l.config.IPAMLockTimeout)
	defer cancel()
	for {
		lock := resourcelock.LeaderElectionRecord{
			HolderIdentity:       l.config.NodeName,
			LeaseDurationSeconds: int(l.config.IPAMLockDuration.Seconds()),
			AcquireTime:          metav1.Now(),
		}
		err := l.Interface.Create(ctx, lock)
		if err == nil {
			l.lockHeld = true
			l.lockCount = 1
			l.curLock = &ipamLock{IPAMLock: l, acquiredAt: lock.AcquireTime}
			return l.curLock, nil
		}
		log.FromContext(ctx).WithName("ipam-lock").Error(err, "Failed to acquire IPAM lock, retrying...")
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("failed to acquire IPAM lock: %w", ctx.Err())
		default:
			time.Sleep(time.Millisecond * 500)
		}
	}
}

type Lock interface {
	// Release releases the lock.
	Release(ctx context.Context)
}

type ipamLock struct {
	*IPAMLock
	acquiredAt metav1.Time
}

func (l *ipamLock) Release(ctx context.Context) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lockHeld {
		return
	}
	l.lockCount--
	if l.lockCount == 0 {
		l.lockHeld = false
		err := l.Interface.Update(ctx, resourcelock.LeaderElectionRecord{
			HolderIdentity: "",
		})
		if err != nil {
			log.FromContext(ctx).WithName("ipam-lock").Error(err, "Failed to release IPAM lock")
		}
	}
}
