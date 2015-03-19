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

package util

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

func findPlugin(plugin string) string {
	// try 3rd-party path first
	paths := strings.Split(os.Getenv("RKT_NETPLUGIN_PATH"), ":")

	for _, p := range paths {
		fullname := filepath.Join(p, plugin)
		if fi, err := os.Stat(fullname); err == nil && fi.Mode().IsRegular() {
			return fullname
		}
	}

	return ""
}

// RunPlugin for/execs a plugin found in RKT_NETPLUGIN_PATH
func RunPlugin(plugin string, stdout io.Writer) error {
	pluginPath := findPlugin(plugin)
	if pluginPath == "" {
		return fmt.Errorf("could not find %q plugin", plugin)
	}

	c := exec.Cmd{
		Path:   pluginPath,
		Args:   []string{pluginPath},
		Stdout: stdout,
		Stderr: os.Stderr,
	}
	if err := c.Run(); err != nil {
		return err
	}

	return nil
}

// ExecPlugin execs (in existing process) a plugin found in RKT_NETPLUGIN_PATH
func ExecPlugin(plugin string) error {
	pluginPath := findPlugin(plugin)
	if pluginPath == "" {
		return fmt.Errorf("could not find %q plugin", plugin)
	}

	args := []string{pluginPath}
	return syscall.Exec(pluginPath, args, os.Environ())
}
