// Copyright 2016-2017 Authors of Cilium
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cidrmap

/*
#cgo CFLAGS: -I../../../bpf/include
#include <linux/bpf.h>
*/
import "C"

import (
	"fmt"
	"net"
	"unsafe"

	"github.com/cilium/cilium/pkg/bpf"
)

const (
	MapName = "cilium_cidr_"
)

type CIDRMap struct {
	path string
	Fd   int
}

func (cm *CIDRMap) DeepCopy() *CIDRMap {
	return &CIDRMap{
		path: cm.path,
		Fd:   cm.Fd,
	}
}

const (
	MAX_KEYS = 1024
)

func (pe *PolicyEntry) String() string {
	return string(pe.Action)
}

type PolicyEntry struct {
	Action  uint32
	Pad     uint32
	Packets uint64
	Bytes   uint64
}

func (pe *PolicyEntry) Add(oPe PolicyEntry) {
	pe.Packets += oPe.Packets
	pe.Bytes += oPe.Bytes
}

type CIDRKey struct {
	Prefixlen uint32
	Net       [16]byte
}

func (cm *CIDRMap) AllowCIDR(cidr net.IPNet) error {
	ones, bits := cidr.Mask.Size()
	bytes := (bits-1)/8 + 1
	var key CIDRKey
	key.Prefixlen = uint32(ones)
	copy(key.Net[:], cidr.IP[0:bytes])
	entry := PolicyEntry{Action: 1}
	return bpf.UpdateElement(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry), 0)
}

func (cm *CIDRMap) CIDRExists(cidr net.IPNet) bool {
	ones, bits := cidr.Mask.Size()
	bytes := (bits-1)/8 + 1
	var key CIDRKey
	key.Prefixlen = uint32(ones)
	copy(key.Net[:], cidr.IP[0:bytes])
	var entry PolicyEntry
	return bpf.LookupElement(cm.Fd, unsafe.Pointer(&key), unsafe.Pointer(&entry)) == nil
}

func (cm *CIDRMap) String() string {
	return cm.path
}

// Close closes the FD of the given CIDRMap
func (cm *CIDRMap) Close() error {
	return bpf.ObjClose(cm.Fd)
}

func OpenMap(path string, prefixlen int) (*CIDRMap, bool, error) {
	if prefixlen <= 0 {
		return nil, false, fmt.Errorf("prefixlen must be > 0.")
	}
	bytes := (prefixlen-1)/8 + 1
	fd, isNewMap, err := bpf.OpenOrCreateMap(
		path,
		C.BPF_MAP_TYPE_LPM_TRIE,
		uint32(unsafe.Sizeof(uint32(0))+uintptr(bytes)),
		uint32(unsafe.Sizeof(PolicyEntry{})),
		MAX_KEYS,
		C.BPF_F_NO_PREALLOC,
	)

	if err != nil {
		return nil, false, err
	}

	m := &CIDRMap{path: path, Fd: fd}

	return m, isNewMap, nil
}
