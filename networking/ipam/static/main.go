package main

import (
	"errors"

	"github.com/coreos/rocket/networking/ipam"
	"github.com/coreos/rocket/networking/ipam/static/backend/disk"
	"github.com/coreos/rocket/networking/util"
)

func main() {
	util.PluginMain(cmdAdd, cmdDel)
}

func cmdAdd(args *util.CmdArgs) error {
	ipamConf, err := NewIPAMConfig(args.NetConf)
	if err != nil {
		return err
	}

	store, err := disk.New(ipamConf.Name)
	if err != nil {
		return err
	}
	defer store.Close()

	allocator, err := NewIPAllocator(ipamConf, store)
	if err != nil {
		return err
	}

	var ipConf *ipam.IPConfig

	switch ipamConf.Type {
	case "static":
		ipConf, err = allocator.Get(args.ContID.String())
	case "static-ptp":
		ipConf, err = allocator.GetPtP(args.ContID.String())
	default:
		return errors.New("Unsupported IPAM plugin type")
	}

	if err != nil {
		return err
	}

	return ipam.PrintIPConfig(ipConf)
}

func cmdDel(args *util.CmdArgs) error {
	ipamConf, err := NewIPAMConfig(args.NetConf)
	if err != nil {
		return err
	}

	store, err := disk.New(ipamConf.Name)
	if err != nil {
		return err
	}
	defer store.Close()

	allocator, err := NewIPAllocator(ipamConf, store)
	if err != nil {
		return err
	}

	return allocator.Release(args.ContID.String())
}
