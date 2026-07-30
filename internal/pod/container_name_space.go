// Copyright 2026 The HuaTuo Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package pod

import (
	"huatuo-bamai/internal/cgroups/subsystem"
	"huatuo-bamai/internal/log"
)

// ContainerMeta is the kernel metadata used to resolve an event's container.
// The fields are ordered by resolution priority.
type ContainerMeta struct {
	MemoryCgroupCSSAddr uint64
	NetNamespaceCookie  uint64
	NetNamespaceInode   uint64
}

// ResolveContainerIDFromMeta resolves a container ID from kernel metadata.
// It prefers the memory cgroup CSS address, then the net namespace cookie,
// and finally the net namespace inode.
func ResolveContainerIDFromMeta(meta ContainerMeta) string {
	if meta.MemoryCgroupCSSAddr != 0 {
		container, err := ContainerByCSS(meta.MemoryCgroupCSSAddr, subsystem.SubsystemMemory)
		if err != nil {
			log.Debugf("container metadata: CSS lookup 0x%x: %v", meta.MemoryCgroupCSSAddr, err)
		} else if container != nil {
			return container.ID
		}
	}

	if meta.NetNamespaceCookie != 0 {
		container, err := ContainerByNetCookie(meta.NetNamespaceCookie)
		if err != nil {
			log.Debugf("container metadata: net_cookie lookup %d: %v", meta.NetNamespaceCookie, err)
		} else if container != nil {
			return container.ID
		}
	}

	if meta.NetNamespaceInode != 0 {
		container, err := ContainerByNetInode(meta.NetNamespaceInode)
		if err != nil {
			log.Debugf("container metadata: net_inum lookup %d: %v", meta.NetNamespaceInode, err)
		} else if container != nil {
			return container.ID
		}
	}

	return ""
}
