// Copyright (c) 2019, 2021 AT&T Intellectual Property.
// All rights reserved.
//
// Copyright (c) 2013-2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: MPL-2.0

package client

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/danos/opd/rpc"
	"github.com/danos/utils/pathutil"
)

type passFdConn struct {
	*net.UnixConn
	file   *os.File
	passed bool
}

func (c *passFdConn) Write(p []byte) (int, error) {
	if c.passed {
		return c.UnixConn.Write(p)
	}

	n, _, err := c.UnixConn.WriteMsgUnix(
		p, syscall.UnixRights(int(c.file.Fd())), nil)
	c.passed = err == nil

	return n, err
}

//Client represents an RPC client calls against the client stub functions are
//sent to the server to be fulfilled and a response of the appropriate type
//is returned.
type Client struct {
	conn  net.Conn
	id    uint
	debug bool
}

//Close the client's connection
func (c *Client) Close() {
	c.conn.Close()
}

//Perform RPC request and response
func (c *Client) doRpcOnConn(conn net.Conn, req *rpc.Request) (*rpc.Response, error) {
	var resp *rpc.Response = new(rpc.Response)
	var err error

	c.id = c.id + 1
	req.Id = c.id

	/*setup socket handlers*/
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	if c.debug {
		fmt.Printf("%#v\n", req)
	}
	/*Send a request*/
	err = enc.Encode(req)
	if err != nil {
		return nil, err
	}

	/*Get a response*/
	err = dec.Decode(resp)
	if err != nil {
		return nil, err
	}

	if c.debug {
		fmt.Printf("%#v\n", resp)
		fmt.Println("type:", reflect.TypeOf(resp.Result))
	}

	if resp.Error != "" {
		return nil, fmt.Errorf("%s", resp.Error)
	}

	return resp, nil
}

func (c *Client) doRpc(req *rpc.Request) (*rpc.Response, error) {
	return c.doRpcOnConn(c.conn, req)
}

//Send the request and get a string or error
func (c *Client) stringRequest(fn rpc.Fn, argv []string) (string, error) {
	var req rpc.Request
	var resp *rpc.Response
	var err error

	req = rpc.Request{Op: fn, Args: argv}
	resp, err = c.doRpc(&req)

	if err != nil {
		return "", err
	}

	if res, ok := resp.Result.(string); ok {
		return res, nil
	}

	return "", fmt.Errorf("invalid return type")
}

//Send the request and get an int or error
func (c *Client) intRequestOnConn(conn net.Conn, fn rpc.Fn, argv []string) (int, error) {
	var req rpc.Request
	var resp *rpc.Response
	var err error

	req = rpc.Request{Op: fn, Args: argv}
	resp, err = c.doRpcOnConn(conn, &req)

	if err != nil {
		return -1, err
	}

	if res, ok := resp.Result.(float64); ok {
		return int(res), nil
	}

	return -1, fmt.Errorf("invalid return type")
}

func (c *Client) intRequest(fn rpc.Fn, argv []string) (int, error) {
	return c.intRequestOnConn(c.conn, fn, argv)
}

//Send the request and get an []string or error
func (c *Client) arrayRequest(fn rpc.Fn, argv []string) (out []string, err error) {
	var req rpc.Request
	var resp *rpc.Response

	out = make([]string, 0)

	req = rpc.Request{Op: fn, Args: argv}
	resp, err = c.doRpc(&req)

	if err != nil {
		return nil, err
	}

	if res, ok := resp.Result.([]interface{}); ok {
		for _, v := range res {
			if val, ok := v.(string); ok {
				out = append(out, val)
			} else {
				out = append(out, fmt.Sprintf("%v", v))
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("invalid return type")
}

//Send the request and get an map[string]string or error
func (c *Client) mapRequest(fn rpc.Fn, argv []string) (out map[string]string, err error) {
	var req rpc.Request
	var resp *rpc.Response

	out = make(map[string]string)

	req = rpc.Request{Op: fn, Args: argv}
	resp, err = c.doRpc(&req)

	if err != nil {
		return nil, err
	}

	if res, ok := resp.Result.(map[string]interface{}); ok {
		for k, v := range res {
			if val, ok := v.(string); ok {
				out[k] = val
			} else {
				out[k] = fmt.Sprintf("%v", v)
			}
		}
		return out, nil
	}
	return nil, fmt.Errorf("invalid return type")
}

func (c *Client) generateCommandsFromMatches(cmd string, nextElement string) []string {
	allowed, _ := c.Allowed(cmd)
	cmds := []string{}
	cur := pathutil.Makepath(cmd)
	for _, a := range allowed {
		// Always return on exact match found
		if diff := strings.Compare(nextElement, a); diff == 0 {
			return []string{pathutil.Pathstr(pathutil.CopyAppend(cur, a))}
		}
		matches, _ := regexp.Match("^"+nextElement+"$", []byte(a))
		if matches {
			cmds = append(cmds, pathutil.Pathstr(pathutil.CopyAppend(cur, a)))
		}
	}
	if len(cmds) == 0 {
		cmds = append(cmds, pathutil.Pathstr(pathutil.CopyAppend(cur, nextElement)))
	}
	return cmds
}

func (c *Client) generateCommandsFromPreviousCommands(prevCmds []string, nextElement string) []string {
	out := []string{}
	for _, curcmd := range prevCmds {
		out = append(out, c.generateCommandsFromMatches(curcmd, nextElement)...)
	}
	return out
}

func (c *Client) generateCommands(path string) []string {
	elems := pathutil.Makepath(path)
	cmds := []string{}
	for _, elem := range elems {
		if len(cmds) == 0 {
			cmds = []string{elem}
			continue
		}
		cmds = c.generateCommandsFromPreviousCommands(cmds, elem)
	}
	return cmds
}

//Run takes a '/' separated path, the type of the connecting terminal (typically this is the TERM environment variable)
//, the number of rows and cols in the connecting terminal, and returns the remote exitcode or 1 on error.
func (c *Client) Run(path string, env []string, tty bool, input io.Reader, output io.Writer) (int, error) {
	var i int

	// Regexp expand commands
	cmds := c.generateCommands(path)

	// Gather relevant env params
	ttystr := strconv.FormatBool(tty)
	for i, v := range env {
		env[i] = url.QueryEscape(v)
	}
	envs := strings.Join(env, ":")

	for _, xpandedpath := range cmds {
		// Need to open a terminal connection per command as opd
		// closes connection after successful command
		termpath, done, err := OpenTerminal(input, output, tty)
		if err != nil {
			return 1, err
		}
		argv := []string{xpandedpath, termpath, envs, ttystr}
		i, err = c.intRequest(rpc.FnRun, argv)
		if err != nil {
			return 1, err
		}
		<-done //wait for copiers to exit, this ensures the whole output is copied
	}
	return i, nil
}

//Complete takes a '/' separated path and returns a list of possible completions.It is the client implementation's
//job to prefix filter this list. This is a convenience for the CLI bash implementation. It does in one call what
//would take several using the other methods, and may be useful for other user interfaces.
func (c *Client) Complete(path string) ([]string, error) {
	argv := []string{path}
	return c.arrayRequest(rpc.FnComplete, argv)
}

//Help takes a '/' separated path and returns a map of completions and their help text.
//It is the client implementation's job to prefix filter this list.This is a convenience for
//the CLI bash implementation. It does in one call what would take several using the other methods,
//and may be useful for other user interfaces.
func (c *Client) Help(path string) (map[string]string, error) {
	argv := []string{path}
	return c.mapRequest(rpc.FnHelp, argv)
}

//Expand takes a '/' separated path and returns the unambiguous expansion of that path;
//[sh int e eth0] will become [show interfaces ethernet eth0] for instance. If the given path is invalid or, ambiguous
//an error message will be returned.
func (c *Client) Expand(path string) ([]string, error) {
	argv := []string{path}
	return c.arrayRequest(rpc.FnExpand, argv)
}

//Tmpl takes a '/' separated path and retruns a map[string]string containg the template (<field>,<value>) pairs.
func (c *Client) Tmpl(path string) (map[string]string, error) {
	argv := []string{path}
	return c.mapRequest(rpc.FnTmpl, argv)
}

//Children takes a  '/' separated path and returns a []string containg the the children of a given path.
func (c *Client) Children(path string) ([]string, error) {
	argv := []string{path}
	return c.arrayRequest(rpc.FnChildren, argv)
}

//Allowed takes a '/' separated path and retruns a []string containg the allowed values for a tag node,
//or an error if called on a non tag node.
func (c *Client) Allowed(path string) ([]string, error) {
	argv := []string{path}
	return c.arrayRequest(rpc.FnAllowed, argv)
}

//GetPerms returns the permissions for the current user
func (c *Client) GetPerms() (map[string]string, error) {
	return c.mapRequest(rpc.FnGetPerms, []string{"/"})
}

//Dial connects to an RPC server at the specified path. Only unix sockets are supported since we use SO_PEERCRED
//to do authorization.
func Dial(sockpath string, debug bool) (*Client, error) {
	var c *Client = &Client{}
	conn, err := net.Dial("unix", sockpath)
	if err != nil {
		return nil, err
	}

	c.conn = conn
	if debug {
		c.debug = debug
	}

	return c, nil
}
