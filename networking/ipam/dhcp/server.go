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
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/rpc"
	"os"
	"strconv"
	"time"

	"github.com/coreos/rocket/Godeps/_workspace/src/github.com/d2g/dhcp4"
	"github.com/coreos/rocket/Godeps/_workspace/src/github.com/d2g/dhcp4client"
	"github.com/coreos/rocket/Godeps/_workspace/src/github.com/vishvananda/netlink"
	"github.com/coreos/rocket/networking/ipam"
	"github.com/coreos/rocket/networking/util"
)

const listenFdsStart = 3
const tries = 3

type DHCP struct{}

func recvOffer(c *dhcp4client.Client) (*dhcp4.Packet, error) {
	for i := 0; i < tries; i++ {
		discover, err := c.SendDiscoverPacket()
		if err == nil {
			offer, err := c.GetOffer(&discover)
			if err == nil {
				return &offer, nil
			} else {
				log.Printf("Failed to receive DHCPOFFER: %v", err)
			}
		} else {
			log.Printf("Error sending DHCPDISCOVER: %v", err)
		}

		time.Sleep(time.Second)
	}

	return nil, errors.New("failed to receive DHCP offer")
}

func lockinOffer(c *dhcp4client.Client, offer *dhcp4.Packet) (*dhcp4.Packet, error) {
	for i := 0; i < tries; i++ {
		req, err := c.SendRequest(offer)
		if err == nil {
			ack, err := c.GetAcknowledgement(&req)
			if err == nil {
				if isNACK(&ack) {
					// This shouldn't happen -- it would violate RFC
					log.Print("DHCP server sent NACK on it's offer")
				} else {
					return &ack, nil
				}
			} else {
				log.Print("failed to receive DHCP(N)ACK")
			}
		} else {
			log.Printf("failed to send DHCPOFFER: %v", err)
		}
	}

	return nil, errors.New("failed to commit DHCP offer")
}

func isNACK(a *dhcp4.Packet) bool {
	opts := a.ParseOptions()
	return dhcp4.MessageType(opts[dhcp4.OptionDHCPMessageType][0]) == dhcp4.NAK
}

func (d *DHCP) Add(args *util.CmdArgs, reply *ipam.IPConfig) error {
	log.Print("Acquiring DHCP Lease...")

	return util.WithNetNSPath(args.Netns, func(_ *os.File) error {
		link, err := netlink.LinkByName(args.IfName)
		if err != nil {
			return fmt.Errorf("error looking up %q", args.IfName)
		}

		log.Printf("%#v", link.Attrs())

		c := &dhcp4client.Client{
			MACAddress:  link.Attrs().HardwareAddr,
			Timeout:     5 * time.Second,
			Ifindex:     link.Attrs().Index,
			NoBcastFlag: true,
		}

		if err = c.ConnectPkt(); err != nil {
			return fmt.Errorf("error binding to UDP port 68: %v", err)
		}
		defer c.Close()

		offer, err := recvOffer(c)
		if err != nil {
			return err
		}

		ack, err := lockinOffer(c, offer)
		if err != nil {
			return err
		}

		opts := ack.ParseOptions()

		reply.IP = &net.IPNet{
			IP:   ack.YIAddr(),
			Mask: net.IPMask(opts[dhcpOptionSubnetMask]),
		}
		reply.Gateway = parseRouter(opts)
		reply.Routes = parseRoutes(opts)
		reply.Routes = append(reply.Routes, parseCIDRRoutes(opts)...)

		return nil
	})
}

func (d *DHCP) Del(args *util.CmdArgs, reply *struct{}) error {
	log.Print("Releasing DHCP Lease...")
	return nil
}

func getListener() (net.Listener, error) {
	s := os.Getenv("LISTEN_FDS")
	if s == "" {
		return nil, errors.New("LISTEN_FDS not set")
	}

	lfds, err := strconv.ParseInt(s, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("Error parsing LISTEN_FDS env var: %v", err)
	}
	if lfds < 1 {
		return nil, errors.New("LISTEN_FDS < 1")
	}

	return net.FileListener(os.NewFile(uintptr(listenFdsStart), "listen"))
}

func runServer() {
	l, err := getListener()
	if err != nil {
		log.Printf("Error getting listener: %v", err)
		return
	}

	dhcp := new(DHCP)
	rpc.Register(dhcp)
	rpc.HandleHTTP()
	http.Serve(l, nil)
}
