// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

//go:build integration_tests

package clustermesh

import (
	"context"
	"crypto/sha256"
	"os"
	"path"
	"time"

	. "gopkg.in/check.v1"

	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/testutils"
)

const (
	content1 = "endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n"
	content2 = "endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2380\n"
)

func writeFile(c *C, name, content string) {
	err := os.WriteFile(name, []byte(content), 0644)
	c.Assert(err, IsNil)
}

func expectExists(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	c.Assert(cm.clusters[name], Not(IsNil))
}

func expectChange(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	cluster := cm.clusters[name]
	cm.mutex.RUnlock()
	c.Assert(cluster, Not(IsNil))

	select {
	case <-cluster.changed:
	case <-time.After(time.Second):
		c.Fatal("timeout while waiting for changed event")
	}
}

func expectNoChange(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	cluster := cm.clusters[name]
	cm.mutex.RUnlock()
	c.Assert(cluster, Not(IsNil))

	select {
	case <-cluster.changed:
		c.Fatal("unexpected changed event detected")
	case <-time.After(100 * time.Millisecond):
	}
}

func expectNotExist(c *C, cm *ClusterMesh, name string) {
	cm.mutex.RLock()
	defer cm.mutex.RUnlock()
	c.Assert(cm.clusters[name], IsNil)
}

func (s *ClusterMeshTestSuite) TestWatchConfigDirectory(c *C) {
	skipKvstoreConnection = true
	defer func() {
		skipKvstoreConnection = false
	}()

	dir1, err := os.MkdirTemp("", "multicluster-1")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir1)

	dir2, err := os.MkdirTemp("", "multicluster-2")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir2)

	file1 := path.Join(dir1, "cluster1")
	file2 := path.Join(dir2, "whatever")
	file3 := path.Join(dir1, "cluster3")
	file2SL := path.Join(dir1, "cluster2")

	writeFile(c, file1, content1)
	writeFile(c, file2, content1)
	c.Assert(os.Symlink(file2, file2SL), IsNil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	ipc := ipcache.NewIPCache(&ipcache.Configuration{
		Context: ctx,
	})
	defer ipc.Shutdown()
	cm, err := NewClusterMesh(Configuration{
		Name:                  "test1",
		ConfigDirectory:       dir,
		NodeKeyCreator:        testNodeCreator,
		RemoteIdentityWatcher: mgr,
		IPCache:               ipc,
	})
	c.Assert(err, IsNil)
	c.Assert(cm, Not(IsNil))
	defer cm.Close()

	// wait for cluster1 and cluster2 to appear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 2
	}, time.Second), IsNil)
	expectExists(c, cm, "cluster1")
	expectExists(c, cm, "cluster2")
	expectNotExist(c, cm, "cluster3")

	err = os.RemoveAll(file1)
	c.Assert(err, IsNil)

	// wait for cluster1 to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 1
	}, time.Second), IsNil)

	writeFile(c, file3, content1)

	// wait for cluster3 to appear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 2
	}, time.Second), IsNil)
	expectNotExist(c, cm, "cluster1")
	expectExists(c, cm, "cluster2")
	expectExists(c, cm, "cluster3")

	// Test renaming of file from cluster3 to cluster1
	err = os.Rename(file3, file1)
	c.Assert(err, IsNil)

	// wait for cluster1 to appear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return cm.clusters["cluster1"] != nil
	}, time.Second), IsNil)
	expectExists(c, cm, "cluster2")
	expectNotExist(c, cm, "cluster3")

	// touch file
	err = os.Chtimes(file1, time.Now(), time.Now())
	c.Assert(err, IsNil)
	expectNoChange(c, cm, "cluster1")

	// update file content
	writeFile(c, file2, content2)
	c.Assert(err, IsNil)
	expectChange(c, cm, "cluster2")

	err = os.RemoveAll(file1)
	c.Assert(err, IsNil)
	err = os.RemoveAll(file2)
	c.Assert(err, IsNil)

	// wait for all clusters to disappear
	c.Assert(testutils.WaitUntil(func() bool {
		cm.mutex.RLock()
		defer cm.mutex.RUnlock()
		return len(cm.clusters) == 0
	}, time.Second), IsNil)
	expectNotExist(c, cm, "cluster1")
	expectNotExist(c, cm, "cluster2")
	expectNotExist(c, cm, "cluster3")

	// Ensure that per-config watches are removed properly
	wl := cm.configWatcher.watcher.WatchList()
	c.Assert(wl, HasLen, 1)
	c.Assert(wl[0], Equals, dir1)
}

func (s *ClusterMeshTestSuite) TestIsEtcdConfigFile(c *C) {
	dir, err := os.MkdirTemp("", "etcdconfig")
	c.Assert(err, IsNil)
	defer os.RemoveAll(dir)

	validPath := path.Join(dir, "valid")
	content := []byte("endpoints:\n- https://cluster1.cilium-etcd.cilium.svc:2379\n")
	err = os.WriteFile(validPath, content, 0644)
	c.Assert(err, IsNil)

	isConfig, hash := isEtcdConfigFile(validPath)
	c.Assert(isConfig, Equals, true)
	c.Assert(hash, Equals, fhash(sha256.Sum256(content)))

	invalidPath := path.Join(dir, "valid")
	err = os.WriteFile(invalidPath, []byte("sf324kj234lkjsdvl\nwl34kj23l4k\nendpoints"), 0644)
	c.Assert(err, IsNil)

	isConfig, hash = isEtcdConfigFile(validPath)
	c.Assert(isConfig, Equals, false)
	c.Assert(hash, Equals, fhash{})

	isConfig, hash = isEtcdConfigFile(dir)
	c.Assert(isConfig, Equals, false)
	c.Assert(hash, Equals, fhash{})
}
