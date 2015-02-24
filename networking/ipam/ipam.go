package ipam

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/coreos/rocket/Godeps/_workspace/src/github.com/vishvananda/netlink"

	"github.com/coreos/rocket/networking/util"
)

type Route struct {
	Dst     net.IPNet
	Gateway net.IP // if nil, def gw is used
}

type route struct {
	Dst     string `json:"dst"`
	Gateway string `json:"gw,omitempty"`
}

// L3 config value for interface
type IPConfig struct {
	IP      *net.IPNet
	Gateway net.IP
	Routes  []Route
}

type ipConfig struct {
	IP      string  `json:"ip"`
	Gateway string  `json:"gateway,omitempty"`
	Routes  []Route `json:"routes,omitempty"`
}

func (r *Route) UnmarshalJSON(data []byte) error {
	rr := route{}
	if err := json.Unmarshal(data, &rr); err != nil {
		return err
	}

	_, dst, err := net.ParseCIDR(rr.Dst)
	if err != nil {
		return fmt.Errorf("error parsing dst: %v", err)
	}

	r.Dst = *dst

	if rr.Gateway != "" {
		r.Gateway = net.ParseIP(rr.Gateway)
		if r.Gateway == nil {
			return fmt.Errorf("error parsing Gateway: %v", err)
		}
	}

	return nil
}

func (r *Route) MarshalJSON() ([]byte, error) {
	rr := route{
		Dst: r.Dst.String(),
	}

	if r.Gateway != nil {
		rr.Gateway = r.Gateway.String()
	}

	return json.Marshal(rr)
}

func (c *IPConfig) UnmarshalJSON(data []byte) error {
	ipc := ipConfig{}
	if err := json.Unmarshal(data, &ipc); err != nil {
		return err
	}

	ip, err := util.ParseCIDR(ipc.IP)
	if err != nil {
		return err
	}

	var gw net.IP
	if ipc.Gateway != "" {
		if gw = net.ParseIP(ipc.Gateway); gw == nil {
			return fmt.Errorf("error parsing Gateway")
		}
	}

	c.IP = ip
	c.Gateway = gw
	c.Routes = ipc.Routes

	return nil
}

func (c *IPConfig) MarshalJSON() ([]byte, error) {
	if c.IP == nil {
		return nil, fmt.Errorf("IPConfig.IP cannot be nil")
	}

	ipc := ipConfig{
		IP:     c.IP.String(),
		Routes: c.Routes,
	}

	if c.Gateway != nil {
		ipc.Gateway = c.Gateway.String()
	}

	return json.Marshal(ipc)
}

func findIPAMPlugin(plugin string) string {
	// try 3rd-party path first
	paths := strings.Split(os.Getenv("RKT_NETPLUGIN_IPAMPATH"), ":")

	for _, p := range paths {
		fullname := filepath.Join(p, plugin)
		if fi, err := os.Stat(fullname); err == nil && fi.Mode().IsRegular() {
			return fullname
		}
	}

	return ""
}

// Executes IPAM plugin, assuming RKT_NETPLUGIN_COMMAND == ADD.
// Parses and returns resulting IPConfig
func ExecPluginAdd(plugin string) (*IPConfig, error) {
	if os.Getenv("RKT_NETPLUGIN_COMMAND") != "ADD" {
		return nil, fmt.Errorf("RKT_NETPLUGIN_COMMAND is not ADD")
	}

	pluginPath := findIPAMPlugin(plugin)
	if pluginPath == "" {
		return nil, fmt.Errorf("could not find %q plugin", plugin)
	}

	stdout := &bytes.Buffer{}

	c := exec.Cmd{
		Path:   pluginPath,
		Args:   []string{pluginPath},
		Stdout: stdout,
		Stderr: os.Stderr,
	}
	if err := c.Run(); err != nil {
		log.Printf("IPAM exited with err: %v", err)
		return nil, err
	}

	ipConf := &IPConfig{}
	err := json.Unmarshal(stdout.Bytes(), ipConf)
	return ipConf, err
}

// Executes IPAM plugin, assuming RKT_NETPLUGIN_COMMAND == DEL.
func ExecPluginDel(plugin string) error {
	if os.Getenv("RKT_NETPLUGIN_COMMAND") != "DEL" {
		return fmt.Errorf("RKT_NETPLUGIN_COMMAND is not DEL")
	}

	pluginPath := findIPAMPlugin(plugin)
	if pluginPath == "" {
		return fmt.Errorf("could not find %q plugin", plugin)
	}

	c := exec.Cmd{
		Path:   pluginPath,
		Args:   []string{pluginPath},
		Stderr: os.Stderr,
	}
	return c.Run()
}

func ApplyIPConfig(ifName string, ipConf *IPConfig) error {
	link, err := netlink.LinkByName(ifName)
	if err != nil {
		return fmt.Errorf("failed to lookup %q: %v", ifName, err)
	}

	if err := netlink.LinkSetUp(link); err != nil {
		return fmt.Errorf("failed too set %q UP: %v", ifName, err)
	}

	addr := &netlink.Addr{IPNet: ipConf.IP, Label: ""}
	if err = netlink.AddrAdd(link, addr); err != nil {
		return fmt.Errorf("failed to add IP addr to %q: %v", ifName, err)
	}

	for _, r := range ipConf.Routes {
		gw := ipConf.Gateway
		if r.Gateway != nil {
			gw = r.Gateway
		}
		if err = util.AddRoute(&r.Dst, gw, link); err != nil {
			// we skip over duplicate routes as we assume the first one wins
			if !os.IsExist(err) {
				return fmt.Errorf("failed to add route '%v via %v dev %v': %v", r.Dst.String(), gw.String(), ifName, err)
			}
		}
	}

	return nil
}

func PrintIPConfig(c *IPConfig) error {
	data, err := json.MarshalIndent(c, "", "    ")
	if err != nil {
		return err
	}

	_, err = os.Stdout.Write(data)
	return err
}
