// Copyright (c) 2017-2020, AT&T Intellectual Property.
// All rights reserved.
//
// Copyright (c) 2013-2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/danos/op/tmpl"
	"github.com/danos/op/tmpl/tree"
	"github.com/danos/op/yang"
	"github.com/danos/opd/rpc"
	"github.com/danos/utils/audit"
	"github.com/danos/utils/os/group"
	"github.com/danos/utils/pathutil"
	"github.com/danos/utils/shell"
	"github.com/danos/utils/tty"
)

type AuthEnv struct {
	Tty string
}

//Auth struct is a request to the authorization service
type Auth struct {
	//Method that is being called
	Method string
	//Path that is being requested
	P tree.Path
	//Attributes of the requested path
	PAttrs *pathutil.PathAttrs
	//User that is making the request
	Uid uint32
	//Groups that this user belongs to
	Groups []*group.Group
	//Is the request to run the command
	Run bool
	//Channel to send the response back on
	Resp chan *AuthResp
}

type AcctReq struct {
	//Path that is being requested
	Path tree.Path
	//Attributes of the requested path
	PathAttrs *pathutil.PathAttrs
	//User that is making the request
	Uid uint32
	//Groups that this user belongs to
	Groups []*group.Group
	//Authorization environment attributes
	Env AuthEnv
	//Response channel
	Resp chan *AcctResp
}

//PermReq is a request for the permission subset for your user
type PermReq struct {
	//User that is making the request
	Uid uint32
	//Groups that this user belongs to
	Groups []*group.Group
	//Channel to send the response back on
	Resp chan map[string]string
}

type ucred struct {
	syscall.Ucred
	Groups []*group.Group
}

const accessDenied = "Access to the requested protocol operation or data " +
	"model is denied because authorization failed."

const spath = "/usr/local/bin:/usr/bin:/bin:/usr/local/sbin:/usr/sbin:/sbin"
const vpath = "/opt/vyatta/bin:/opt/vyatta/sbin"
const pathEnv = "PATH=" + spath + ":" + vpath

func newUcred(c *syscall.Ucred) *ucred {
	uids := strconv.Itoa(int(c.Uid))

	groups, err := group.LookupUid(uids)
	if err != nil {
		return nil
	}

	return &ucred{*c, groups}
}

type AcctResp struct {
	Accounter TaskAccounter
	Err       error
}

func newAcctResp(accounter TaskAccounter, err error) *AcctResp {
	return &AcctResp{Accounter: accounter, Err: err}
}

type AuthResp struct {
	Permitted bool
	Err       error
}

func newAuthResp(permitted bool, err error) *AuthResp {
	return &AuthResp{Permitted: permitted, Err: err}
}

func permitted(permitted bool, err error) bool {
	return permitted && err == nil
}

func envAllowed(tmpl *tmpl.OpTmpl, env string) bool {

	ev := strings.Split(env, "=")
	if len(ev) < 2 {
		return false
	}
	switch ev[0] {
	case "SSH_CLIENT", "SSH_CONNECTION", "SSH_TTY",
		"TERM", "XDG_RUNTIME_DIR", "XDG_SESSION_ID",
		"vyatta_origin_tty", "OPT_YES":
		return true
	case "OPC_ARGS":
		return tmpl.PassOpcArgs()
	default:
		// 'VII_*' required for the installer to work properly
		if strings.HasPrefix(ev[0], "VII_") {
			return true
		}
	}
	return false
}

//SrvConn represents a connection to the server.
//It embeds a net.UnixConn, has a reference to the server that created it
//and holds other nesscary state for processing rpc requests.
type SrvConn struct {
	*net.UnixConn
	Srv  *Server
	uid  uint32
	cred *syscall.Ucred
	enc  *json.Encoder
	dec  *json.Decoder
}

//Send an rpc response with appropriate data or an error
func (conn *SrvConn) sendResponse(resp *rpc.Response) error {
	if conn.Srv.Debug {
		log.Printf("%#v\n", resp)
	}

	err := conn.enc.Encode(&resp)
	return err

}

//Receive an rpc request and do some preprocessing.
func (conn *SrvConn) readRequest(req *rpc.Request) error {
	err := conn.dec.Decode(req)
	if err != nil {
		return err
	}

	if conn.Srv.Debug {
		conn.Srv.Logf("%#v\n", req)
	}
	return nil
}

func (conn *SrvConn) preProcessRequest(req *rpc.Request, cred *ucred) (tree.Path, error) {
	var path tree.Path
	if len(req.Args) == 0 {
		return nil, fmt.Errorf("Invalid number of arguments: %d\n", len(req.Args))
	}

	paths := req.Args[0]
	path = strings.Split(paths, "/")
	if path[0] == "" {
		path = path[1:] //strip leading '/'
	}
	for i, v := range path {
		t, e := url.QueryUnescape(v)
		if e != nil {
			continue
		}
		path[i] = t
	}
	return conn.Srv.Expand(path, cred)
}

//Grab the credentials off of the unix socet using SO_PEERCRED and store them int the SrvConn
func (conn *SrvConn) getCreds() error {
	uf, err := conn.File()
	if err != nil {
		return err
	}
	cred, err := syscall.GetsockoptUcred(
		int(uf.Fd()),
		syscall.SOL_SOCKET,
		syscall.SO_PEERCRED)
	if err != nil {
		conn.Srv.LogError(err)
		return err
	}
	uf.Close()
	conn.cred = cred
	u, e := audit.GetPidLoginuid(cred.Pid)
	if e == nil {
		conn.cred.Uid = u
	}

	return nil
}

//Handle is the main loop for a connection. It receives the requests, authorizes the request, calls the
//requeste method and retruns the response to the client.
func (conn *SrvConn) Handle() {
	defer conn.Close()

	conn.dec = json.NewDecoder(conn)
	conn.enc = json.NewEncoder(conn)

	err := conn.getCreds()
	if err != nil {
		return
	}

	var cred = newUcred(conn.cred)
	if cred == nil {
		return
	}

	for {
		var err error
		var result interface{}
		var path tree.Path

		var req = new(rpc.Request)
		err = conn.readRequest(req)
		if err != nil {
			if err != io.EOF {
				conn.Srv.Logf(err.Error())
			}
			break
		}

		path, err = conn.preProcessRequest(req, cred)
		if err != nil {
			err := conn.sendResponse(rpc.NewResponse(result, err, req.Id))
			if err != nil {
				return
			} else {
				continue
			}
		}

		switch req.Op {
		case rpc.FnRun:
			result, err = conn.Srv.Run(path, req.Args, cred)
		case rpc.FnComplete:
			result, err = conn.Srv.Complete(path, cred)
		case rpc.FnHelp:
			result, err = conn.Srv.Help(path, cred)
		case rpc.FnExpand:
			result, err = path, nil
		case rpc.FnTmpl:
			result, err = conn.Srv.Tmpl(path)
		case rpc.FnChildren:
			result, err = conn.Srv.Children(path, cred)
		case rpc.FnAllowed:
			result, err = conn.Srv.Allowed(path, cred)
		case rpc.FnGetPerms:
			result, err = conn.Srv.GetPerms(cred)
		}

		err = conn.sendResponse(rpc.NewResponse(result, err, req.Id))
		if err != nil {
			return
		}
	}
}

//Server is a representation of the listener and contains the shared template tree.
//It embeds a net.UnixListener.
type Server struct {
	*net.UnixListener
	//Shared template tree
	T *tree.OpTree
	//Yang schema tree
	Y *yang.Yang
	//Authorization channel if non nil authorization requests will be sent across this
	Achan chan *Auth
	//permission channel
	Pchan chan *PermReq
	//Accounting channel
	AcctChan chan *AcctReq
	auditer  audit.Auditer
	//Debug enables rpc request/response tracing
	Debug       bool
	testallowed bool
}

//NewServer creates a new Server and return a reference.
func NewServer(l *net.UnixListener, tree *tree.OpTree, yang *yang.Yang, achan chan *Auth,
	pchan chan *PermReq, acctChan chan *AcctReq, dbg bool) *Server {
	return &Server{l, tree, yang, achan, pchan, acctChan, audit.NewAudit(), dbg, false}
}

//Log is a common place to do logging so that the implementation may change in the future.
func (d *Server) Logf(fmt string, v ...interface{}) {
	log.Printf(fmt, v...)
}

//LogError logs an error if the passed in value is non nil
func (d *Server) LogError(err error) {
	if err != nil {
		d.Logf("%s", err)
	}
}

//Serve is the server main loop. It accepts connections and spawns a goroutine to handle that connection.
func (d *Server) Serve() error {
	var err error
	for {
		conn, err := d.AcceptUnix()
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Temporary() {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			d.LogError(err)
			break
		}
		sconn := d.NewConn(conn)

		go sconn.Handle()
	}
	return err
}

//NewConn creates a new SrvConn and returns a reference to it.
func (d *Server) NewConn(conn *net.UnixConn) *SrvConn {
	return &SrvConn{conn, d, 0, nil, nil, nil}
}

//getNode is an internal helper function that will walk a tree and return the node for a given path
func (d *Server) getNode(path tree.Path) (node *tree.OpTree, err error) {
	node, err = d.T.Descendant(path)
	if err != nil {
		return nil, err
	}

	return node, nil
}

//getTmpl is an internal helper function that will get a node and return its value
func (d *Server) getTmpl(path tree.Path) (*tmpl.OpTmpl, error) {
	tmpl, err := d.Y.TmplGet(path)
	if tmpl != nil {
		return tmpl, err
	}
	node, err := d.getNode(path)
	if err != nil {
		return nil, err
	}

	tmpl = node.Value()
	if tmpl == nil {
		return nil, fmt.Errorf("No template found %v", path)
	}

	return tmpl, nil
}

//getField is an internal helper function that will return a given field from a node's template
func (d *Server) getField(field string, path tree.Path) (reply string, err error) {
	t, err := d.getTmpl(path)
	if err != nil {
		return
	}

	return t.GetField(field)
}

func (d *Server) AttrsForPath(path tree.Path) *pathutil.PathAttrs {
	attrs := pathutil.NewPathAttrs()

	for i, _ := range path {
		tmpl, err := d.getTmpl(path[:i+1])
		if err != nil {
			return nil
		}

		eattrs := pathutil.NewPathElementAttrs()
		eattrs.Secret = tmpl.Secret()
		attrs.Attrs = append(attrs.Attrs, eattrs)
	}

	return &attrs
}

func (d *Server) auth(areq *Auth) (bool, error) {
	areq.Resp = make(chan *AuthResp)
	d.Achan <- areq
	aresp := <-areq.Resp
	if d.Debug {
		d.Logf("server authorize: got response %v", aresp)
	}
	return aresp.Permitted, aresp.Err

}

func (d *Server) account(path tree.Path, cred *ucred) {
	attrs := d.AttrsForPath(path)
	ttyName, err := tty.TtyNameForPid(int(cred.Pid))
	d.LogError(err)
	authEnv := &AuthEnv{Tty: ttyName}

	areq := &AcctReq{Path: path, PathAttrs: attrs, Uid: cred.Uid, Groups: cred.Groups, Env: *authEnv}
	areq.Resp = make(chan *AcctResp)
	d.AcctChan <- areq

	resp := <-areq.Resp
	if resp.Err == nil {
		resp.Accounter.AccountStop(nil)
	}
}

//authorize is an internal helper that will preform authorization request and return the value from the response channel
func (d *Server) authorize(path tree.Path, cred *ucred) (bool, error) {
	areq := &Auth{Method: "", P: path, PAttrs: nil, Uid: cred.Uid, Groups: cred.Groups}
	return d.auth(areq)
}

func (d *Server) authorizeRun(path tree.Path, cred *ucred) (bool, error) {
	attrs := d.AttrsForPath(path)
	areq := &Auth{Method: "", P: path, PAttrs: attrs, Uid: cred.Uid, Groups: cred.Groups, Run: true}
	return d.auth(areq)
}

func (d *Server) yangAuthoriser(cred *ucred) yang.Authoriser {
	return func(path []string) (bool, error) {
		return d.authorize(path, cred)
	}
}

//Run starts the process specified by the 'run' field in the template of the node at the given path.
//The pid of this process is returned to the client so that it may start up a cmdclient and attach to the remote pty.
func (d *Server) Run(path tree.Path, args []string, cred *ucred) (reply int, err error) {
	var com string
	var setuid bool
	var auditstr string

	if len(args) < 4 {
		return -1, fmt.Errorf("Invalid number of arguments: %d\n", len(args))
	}
	termpath := args[1]
	clientenv := args[2]
	ttystr := args[3]

	env := strings.Split(clientenv, ":")
	for i, v := range env {
		s, e := url.QueryUnescape(v)
		if e != nil {
			continue
		}
		env[i] = s
	}

	istty, err := strconv.ParseBool(ttystr)
	if err != nil {
		return -1, err
	}

	tmpl, err := d.getTmpl(path)
	if err != nil {
		return -1, err
	}

	/* We don't know the result of the execution. We consider the scheduling of Run() always
	   as succesful in scope of the audit system.
	*/
	auditstr = fmt.Sprintf("run: %s, for user: %d", path.StringByAttrs(d.AttrsForPath(path)), cred.Uid)

	resp, err := d.authorizeRun(path, cred)
	if err != nil {
		return -1, err
	}
	if !resp {
		d.auditer.LogUserCmd(auditstr, 0)
		return -1, fmt.Errorf(accessDenied)
	}
	d.auditer.LogUserCmd(auditstr, 1)

	if tmpl.Yang() {
		if ok, verr := d.Y.TmplValidateValues(path); !ok {
			return -1, verr
		}
	}
	com = tmpl.Run()

	if !tmpl.Priv() {
		setuid = true
	}

	if com == "" {
		return -1, fmt.Errorf("Incomplete command: %s", path)
	}

	u, err := user.LookupId(fmt.Sprint(cred.Uid))
	if err != nil {
		return -1, err
	}

	defer d.account(path, cred)

	var cenv []string
	for _, v := range env {
		if envAllowed(tmpl, v) {
			cenv = append(cenv, v)
		}
	}

	// Create sensible default for PWD
	pwd := u.HomeDir
	if _, err := os.Stat(pwd); os.IsNotExist(err) {
		pwd = "/"
	}
	cenv = append(cenv, "PWD="+pwd)

	cenv = append(cenv, "HOME="+u.HomeDir)
	cenv = append(cenv, "LOGNAME="+u.Username)

	cenv = append(cenv, rpc.Env...)
	cenv = append(cenv, pathEnv)

	/*This may not be clear 'sh -c' allows us to wrap text in a shell,
	  "opd" is $0, and the path is the rest of $@; this mimics the current behvaior*/
	var shargs = []string{"sh", "-c", com, "opd"}
	var argv = []string{"-user", u.Username}
	if setuid {
		argv = append(argv, "-setprivs")
	}
	argv = append(argv, shargs...)
	argv = append(argv, path...)

	var cmd = &Cmd{
		Path:     "/opt/vyatta/sbin/lu",
		Args:     argv,
		Env:      cenv,
		Uid:      cred.Uid,
		Setuid:   setuid,
		Istty:    istty,
		Termpath: termpath,
	}
	return Run(cmd)
}

func (d *Server) addYangCompletions(comps []string, path tree.Path, cred *ucred) ([]string, error) {
	helps, err := d.Y.Completion(path, d.yangAuthoriser(cred))
	for op, _ := range helps {
		comps = appenduniq(comps, op)
	}
	return comps, err
}

func (d *Server) addTemplateCompletions(comps []string, path tree.Path, cred *ucred) ([]string, error) {
	var err error
	var n *tree.OpTree

	if len(path) == 0 {
		n = d.T
	} else {
		n, err = d.getNode(path)
	}

	if err != nil {
		return comps, err
	}

	for it := tree.NewChildIterator(n); it.HasNext(); it.Next() {
		if c := it.Value(); c.Name() == "node.tag" {
			np := append(path, c.Name())
			if !permitted(d.authorize(np, cred)) {
				continue
			}
			vals, err := d.Allowed(np, cred)
			if err != nil {
				err = nil
				comps = appenduniq(comps, "<text>")
				continue
			}
			if len(vals) == 0 {
				vals = append(vals, "<text>")
			}
			comps = append(comps, vals...)
		} else {
			item := c.Name()
			np := append(path, item)
			if permitted(d.authorize(np, cred)) {
				comps = appenduniq(comps, item)
			}
		}
	}
	if s, e := d.getField("run", path); s != "" && e == nil {
		if permitted(d.authorizeRun(path, cred)) {
			comps = appenduniq(comps, "<Enter>")
		}
	}

	return comps, nil
}

//Complete returns a list of possible completions for a node at a given path.
func (d *Server) Complete(path tree.Path, cred *ucred) ([]string, error) {
	reply := make([]string, 0, 10)

	reply, err := d.addTemplateCompletions(reply, path, cred)
	reply, yerr := d.addYangCompletions(reply, path, cred)

	allow, _ := d.allowedInternal(path, cred, true)
	for _, a := range allow {
		reply = appenduniq(reply, a)
	}

	if err != nil && yerr != nil {
		return reply, err
	}
	sort.Strings(reply)
	return reply, nil
}

//Help returns a map of completions to their help text.
func (d *Server) Help(path tree.Path, cred *ucred) (map[string]string, error) {
	reply := make(map[string]string)
	if r, _ := d.Y.Completion(path, d.yangAuthoriser(cred)); r != nil {
		reply = r
	}
	comps, err := d.Complete(path, cred)
	if err != nil {
		for _, v := range comps {
			reply[v] = ""
		}
	}

	op, yerr := d.allowedInternal(path, cred, true)
	for _, v := range op {
		reply[v] = ""
	}

	node, err := d.getNode(path)
	if err == nil {
		f := func(n *tree.OpTree, v string) {
			t := n.Value()
			if t != nil {
				if ht, ok := reply[v]; ok {
					if ht != "" {
						return
					}
				}
				help := t.Help()
				reply[v] = help
			}
		}

		for _, v := range comps {
			if v == "<Enter>" {
				reply[v] = "Execute the current command"
				continue
			}
			if c, e := node.Child(v); e == nil {
				f(c, v)
			} else if c, e := node.Child("node.tag"); e == nil {
				f(c, v)
			}
		}
	}
	if err == nil || yerr == nil {
		yerr = nil
	}
	return reply, yerr
}

type match struct {
	node  *tree.OpTree
	isarg bool
}

func (m match) Name() string {
	return m.node.Name()
}

func (m match) Help() string {
	return m.node.Value().Help()
}

func (m match) IsArg() bool {
	return m.node.Name() == "node.tag"
}

func (d *Server) expandMatches(path tree.Path, cred *ucred) [][]yang.Match {
	var eMatches = make([][]yang.Match, 0)
	var np tree.Path = make(tree.Path, 0)
	c := d.T
	n := d.T

	for _, v := range path {
		var matches []yang.Match
		var t *tree.OpTree

		for i := tree.NewChildIterator(c); i.HasNext(); i.Next() {
			c = i.Value()
			if c.Name() == v {
				/*Exact match*/
				p := append(np, c.Name())
				if permitted(d.authorize(p, cred)) {
					matches = []yang.Match{match{node: c}}
					n = c
					break
				}
			} else if c.Name() == "node.tag" {
				t = c
				continue
			} else if strings.HasPrefix(c.Name(), v) {
				n = c
				p := append(np, c.Name())
				if permitted(d.authorize(p, cred)) {
					matches = append(matches, match{node: c})
				}
			}
		}

		switch len(matches) {
		case 0:
			/*No exact matches but we are a tag; accept all*/
			if t != nil {
				c = t
				np = append(np, v)
				eMatches = append(eMatches, []yang.Match{match{node: t, isarg: true}})
				continue
			}
			eMatches = append(eMatches, matches)
			return eMatches
		case 1:
			c = n
			np = append(np, c.Name())
			eMatches = append(eMatches, matches)
		default:
			eMatches = append(eMatches, matches)
			return eMatches
		}
	}
	return eMatches
}

//Expand takes an abbreviated path and expands it to the full path.
func (d *Server) Expand(path tree.Path, cred *ucred) (tree.Path, error) {
	var np tree.Path = make(tree.Path, 0)
	if len(path) == 1 && path[0] == "" {
		/*Root*/
		return np, nil
	}

	yng := d.Y.ExpandMatches(path, d.yangAuthoriser(cred))
	tmpl := d.expandMatches(path, cred)

	matches := yang.MergeMatches(yng, tmpl)

	return yang.ProcessMatches(path, matches)
}

//Tmpl returns a map of template fields to their value
func (d *Server) Tmpl(path tree.Path) (reply map[string]string, err error) {
	t, err := d.getTmpl(path)
	if err != nil {
		return
	}

	reply = t.Map()
	return
}

//Children returns a list of the childern for a node at the given path.
func (d *Server) Children(path tree.Path, cred *ucred) (reply []string, err error) {
	reply, yerr := d.Y.TmplGetChildren(path, d.yangAuthoriser(cred))
	node, err := d.getNode(path)
	if err != nil {
		return reply, yerr
	}

	for i := tree.NewChildIterator(node); i.HasNext(); i.Next() {
		c := i.Value()
		p := append(path, c.Name())
		if permitted(d.authorize(p, cred)) {
			reply = append(reply, c.Name())
		}
	}

	return
}

func quotePath(path []string) []string {
	for i, v := range path {
		path[i] = shell.Quote(v)
	}
	return path
}

func (d *Server) Allowed(path tree.Path, cred *ucred) ([]string, error) {
	return d.allowedInternal(path, cred, false)
}

func (d *Server) allowedInternal(path tree.Path, cred *ucred, helpmode bool) ([]string, error) {
	allow, err := d.Y.TmplGetAllowed(path)

	if err != nil {
		hp := path
		if helpmode {
			// We want allowed values from child node.tag, if it exists
			hp = append(hp, "node.tag")
		}
		n, err := d.getNode(hp)

		if err != nil {
			return nil, err
		}
		if n.Name() != "node.tag" {
			return nil, fmt.Errorf("Allowed called on non tag node")
		}

		t := n.Value()
		allow = t.Allowed()
	}

	if d.testallowed {
		if allow == "" {
			return nil, fmt.Errorf("No Allowed")
		}
		return strings.Split(allow, " "), nil
	}

	u, err := user.LookupId(fmt.Sprint(cred.Uid))
	if err != nil {
		return nil, err
	}

	cwords := strings.Join(quotePath(pathutil.Copypath([]string(path))), " ")
	comp_words := "COMP_WORDS=( " + cwords + " )"
	comp_cword := "COMP_CWORD=" + strconv.Itoa(len(path)-1)

	//BUG(jhs): workaround bash not allowing exported arrays
	allow = comp_words + "; " + allow

	var args = []string{"/opt/vyatta/sbin/lu", "-user", u.Username,
		"sh", "-c", allow, "opd"}
	args = append(args, path...)

	cmd := exec.Command(args[0], args[1:]...)
	cmd.Env = append(cmd.Env, rpc.Env...)
	cmd.Env = append(cmd.Env, comp_cword)
	cmd.Env = append(cmd.Env, pathEnv)

	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	buf := strings.Replace(string(out), "\n", " ", -1)
	reply := strings.Split(buf, " ")
	var tagvals = make([]string, 0, len(reply))
	for _, v := range reply {
		v = strings.Trim(v, " \n\t")
		if v == "" {
			continue
		}
		tagvals = append(tagvals, v)
	}
	reply = tagvals

	return reply, err
}

//GetPerms returns the permissions for the current user
func (d *Server) GetPerms(cred *ucred) (reply map[string]string, err error) {
	resp := make(chan map[string]string)
	preq := &PermReq{Uid: cred.Uid, Groups: cred.Groups, Resp: resp}
	d.Pchan <- preq
	presp := <-preq.Resp
	if d.Debug {
		d.Logf("server authorize: got response %v", presp)
	}
	return presp, nil
}

//appendunique is an internal helper function that will append an item to a slice iff it is not already in the slice
func appenduniq(in []string, item string) (out []string) {
	for _, i := range in {
		if i == item {
			return in
		}
	}
	return append(in, item)
}
