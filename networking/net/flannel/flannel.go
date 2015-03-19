// Copyright 2014 CoreOS, Inc.
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

package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"

	rktnet "github.com/coreos/rocket/networking/net"
	"github.com/coreos/rocket/networking/util"
)

const defaultSubnetFile = "/run/flannel/subnet.env"

type Net struct {
	rktnet.Net
	SubnetFile string `json:"subnetFile"`
}

type subnetEnv struct {
	sn     *net.IPNet
	mtu    uint
	ipmasq bool
}

func init() {
	// this ensures that main runs only on main thread (thread group leader).
	// since namespace ops (unshare, setns) are done for a single thread, we
	// must ensure that the goroutine does not jump from OS thread to thread
	runtime.LockOSThread()
}

func loadConf(path string) (*Net, error) {
	n := &Net{
		SubnetFile: defaultSubnetFile,
	}
	if err := rktnet.LoadNet(path, n); err != nil {
		return nil, fmt.Errorf("failed to load %q: %v", path, err)
	}
	return n, nil
}

func loadFlannelSubnetEnv(fn string) (*subnetEnv, error) {
	f, err := os.Open(fn)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	se := &subnetEnv{}

	s := bufio.NewScanner(f)
	for s.Scan() {
		parts := strings.SplitN(s.Text(), "=", 2)
		switch parts[0] {
		case "FLANNEL_SUBNET":
			_, se.sn, err = net.ParseCIDR(parts[1])
			if err != nil {
				return nil, err
			}

		case "FLANNEL_MTU":
			mtu, err := strconv.ParseUint(parts[1], 10, 32)
			if err != nil {
				return nil, err
			}
			se.mtu = uint(mtu)

		case "FLANNEL_IPMASQ":
			se.ipmasq = parts[1] == "true"
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return se, nil
}

func cmdAdd(args *util.CmdArgs) error {
	n, err := loadConf(args.NetConf)
	if err != nil {
		return err
	}

	fenv, err := loadFlannelSubnetEnv(n.SubnetFile)
	if err != nil {
		return err
	}

	// overwrite NetConf with the synthesized version
	f, err := os.Create(args.NetConf)
	if err != nil {
		return err
	}

	// if flannel is not doing ipmasq, we should
	ipmasq := fmt.Sprint(!fenv.ipmasq)

	_, err = fmt.Fprintf(f, `{
		"name": %q,
		"type": "bridge",
		"isGateway": true,
		"ipMasq": %v,
		"mtu": %v,
		"ipam": {
			"type": "static",
			"subnet": %q
		}
	}`, n.Name, ipmasq, fenv.mtu, fenv.sn)
	if err != nil {
		return err
	}

	return util.ExecPlugin("bridge")
}

func cmdDel(args *util.CmdArgs) error {
	return util.ExecPlugin("bridge")
}

func main() {
	util.PluginMain(cmdAdd, cmdDel)
}
