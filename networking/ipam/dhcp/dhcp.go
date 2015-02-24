// Copyright 2015 CoreOS, Inc.
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
	"net"

	"github.com/coreos/rocket/networking/ipam"
	"github.com/coreos/rocket/Godeps/_workspace/src/github.com/d2g/dhcp4"
)

const (
	dhcpOptionSubnetMask           = 1
	dhcpOptionRouter               = 3
	dhcpOptionStaticRoute          = 33
	dhcpOptionClasslessStaticRoute = 121
)

func parseRouter(opts dhcp4.Options) net.IP {
	if opts, ok := opts[dhcpOptionRouter]; ok {
		if len(opts) == 4 {
			return net.IP(opts)
		}
	}
	return nil
}

func classfulSubnet(sn net.IP) net.IPNet {
	return net.IPNet{
		IP:   sn,
		Mask: sn.DefaultMask(),
	}
}

func parseRoutes(opts dhcp4.Options) []ipam.Route {
	// StaticRoutes format: pairs of:
	// Dest = 4 bytes; Classful IP subnet
	// Router = 4 bytes; IP address of router

	routes := []ipam.Route{}
	if opt, ok := opts[dhcpOptionStaticRoute]; ok {
		for len(opt) >= 8 {
			sn := opt[0:4]
			r := opt[4:8]
			rt := ipam.Route{
				Dst:     classfulSubnet(sn),
				Gateway: r,
			}
			routes = append(routes, rt)
			opt = opt[8:]
		}
	}

	return routes
}

func parseCIDRRoutes(opts dhcp4.Options) []ipam.Route {
	// See RFC4332 for format (http://tools.ietf.org/html/rfc3442)

	routes := []ipam.Route{}
	if opt, ok := opts[dhcpOptionClasslessStaticRoute]; ok {
		for len(opt) >= 5 {
			width := int(opt[0])
			if width > 32 {
				// error: can't have more than /32
				return nil
			}
			// network bits are compacted to avoid zeros
			octets := 0
			if width > 0 {
				octets = (width-1)/8 + 1
			}

			if len(opt) < 1+octets+4 {
				// error: too short
				return nil
			}

			sn := make([]byte, 4)
			copy(sn, opt[1:octets+1])

			gw := net.IP(opt[octets+1 : octets+5])

			rt := ipam.Route{
				Dst: net.IPNet{
					IP:   net.IP(sn),
					Mask: net.CIDRMask(width, 32),
				},
				Gateway: gw,
			}
			routes = append(routes, rt)

			opt = opt[octets+5 : len(opt)]
		}
	}
	return routes
}
