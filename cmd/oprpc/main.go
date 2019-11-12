// Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2015-2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"

	opdclient "github.com/danos/opd/client"
)

type RPC struct {
	Command string `json:"command"`
	Path    string `json:"args"`
}

type RPCReply struct {
	Output string `json:"output"`
}

func argsToPath(args ...string) string {
	for i, v := range args {
		args[i] = url.QueryEscape(v)
	}
	s := strings.Join(args, "/")
	s = "/" + s
	return s
}

func userPath(path string) string {
	args := strings.Split(path, "/")
	for i, v := range args {
		args[i], _ = url.QueryUnescape(v)
	}
	return strings.Join(args, " ")
}

func handleError(err error) {
	if err == nil {
		return
	}
	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func run() {
	var srpc RPC
	var buf bytes.Buffer
	c, err := opdclient.Dial("/var/run/vyatta/opd/main.sock", false)
	handleError(err)

	enc := json.NewEncoder(os.Stdout)
	dec := json.NewDecoder(os.Stdin)
	handleError(dec.Decode(&srpc))

	args := append([]string{srpc.Command}, strings.Split(srpc.Path, " ")...)
	cmd := argsToPath(args...)
	expcmd, err := c.Expand(cmd)
	handleError(err)
	if cmd != argsToPath(expcmd...) {
		handleError(fmt.Errorf("invalid command: %s", userPath(cmd)))
	}

	ec, err := c.Run(cmd, os.Environ(), false, nil, &buf)
	handleError(err)

	if ec != 0 {
		handleError(fmt.Errorf("command failed: %s", &buf))
	}
	handleError(enc.Encode(&RPCReply{Output: buf.String()}))
}

func main() {
	run()
	os.Exit(0)
}
