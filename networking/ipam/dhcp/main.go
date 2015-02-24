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
	"fmt"
	"log"
	"net"
	"net/rpc"
	"os"
	"os/exec"
	"syscall"

	"github.com/coreos/rocket/networking/ipam"
	"github.com/coreos/rocket/networking/util"
)

// Use annonymous socket to avoid unlinking it
const socketPath = "\000/tmp/rkt-dhcp.sock"

func main() {
	if len(os.Args) > 1 && os.Args[1] == "server" {
		runServer()
	} else {
		util.PluginMain(cmdAdd, cmdDel)
	}
}

func launchServer() error {
	log.Print("LAUNCH server")
	// use socket activation protocol to avoid race-condition of
	// service becoming ready
	l, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: socketPath})
	if err != nil {
		if err.(*net.OpError).Err.(*os.SyscallError).Err == syscall.EADDRINUSE {
			log.Print("DHCP daemon already running, not starting")
			// assume server already running
			return nil
		}
		return err
	}

	defer l.Close()

	lf, err := l.File()
	if err != nil {
		return err
	}

	log.Print("DHCP daemon not running, starting")

	args := []string{"/proc/self/exe"}
	args = append(args, "server")

	cmd := exec.Cmd{
		Path:       args[0],
		Args:       args,
		Env:        append(os.Environ(), "LISTEN_FDS=1"),
		ExtraFiles: []*os.File{lf},
		Stdout:     nil,
		Stderr:     os.Stderr,
	}
	return cmd.Start()
}

func cmdAdd(args *util.CmdArgs) error {
	if err := launchServer(); err != nil {
		return err
	}

	client, err := rpc.DialHTTP("unix", socketPath)
	if err != nil {
		return fmt.Errorf("error dialing DHCP daemon: %v", err)
	}

	ipConf := &ipam.IPConfig{}
	err = client.Call("DHCP.Add", args, ipConf)
	if err != nil {
		return fmt.Errorf("error calling DHCP.Add: %v", err)
	}

	return ipam.PrintIPConfig(ipConf)
}

func cmdDel(args *util.CmdArgs) error {
	if err := launchServer(); err != nil {
		return err
	}

	client, err := rpc.DialHTTP("unix", socketPath)
	if err != nil {
		return fmt.Errorf("error dialing DHCP daemon: %v", err)
	}

	dummy := struct{}{}
	err = client.Call("DHCP.Del", args, &dummy)
	if err != nil {
		return fmt.Errorf("error calling DHCP.Del: %v", err)
	}

	return nil
}
