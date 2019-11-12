// Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2013-2014 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package rpc

//Fn is an enumeration used to identify RPC call handlers
type Fn uint

const (
	FnRun Fn = iota
	FnComplete
	FnHelp
	FnExpand
	FnTmpl
	FnChildren
	FnAllowed
	FnGetPerms
)

//fnMap allows pretty printing of Fn values
var fnMap = map[Fn]string{
	FnRun:      "Run",
	FnComplete: "Complete",
	FnHelp:     "Help",
	FnExpand:   "Expand",
	FnTmpl:     "Tmpl",
	FnChildren: "Children",
	FnAllowed:  "Allowed",
	FnGetPerms: "GetPerms",
}

//Request represents an RPC request
type Request struct {
	//Op is the method that was called via json rpc
	Op Fn `json:"method"`
	//Args is a list of arguments to that method
	Args []string `json:"args"`
	//Id is the unique request identifier
	Id uint `json:"id"`
}

//Response represents an RPC response
type Response struct {
	//Result is any value returned by the handler
	//The client library uses reflection to ensure it received the appropriate type.
	Result interface{} `json:"result"`
	//Error contains a message describing a problem
	Error string `json:"error"`
	//Id is the unique request identifier
	Id uint `json:"id"`
}

func NewResponse(result interface{}, err error, id uint) *Response {
	var resp Response
	if err != nil {
		resp = Response{Error: err.Error(), Id: id}
	} else {
		resp = Response{Result: result, Id: id}
	}
	return &resp
}

//Env is the environment needed to run vyatta commands.
var Env []string = []string{"vyatta_htmldir=/opt/vyatta/share/html",
	"vyatta_datadir=/opt/vyatta/share",
	"vyatta_op_templates=/opt/vyatta/share/vyatta-op/templates",
	"vyatta_sysconfdir=/opt/vyatta/etc",
	"vyatta_sharedstatedir=/opt/vyatta/com",
	"vyatta_sbindir=/opt/vyatta/sbin",
	"vyatta_cfg_templates=/opt/vyatta/share/vyatta-cfg/templates",
	"VYATTA_CFG_GROUP_NAME=vyattacfg",
	"vyatta_bindir=/opt/vyatta/bin",
	"VYATTA_USER_LEVEL_DIR=/opt/vyatta/etc/shell/level/admin",
	"vyatta_libdir=/opt/vyatta/lib",
	"vyatta_localstatedir=/opt/vyatta/var",
	"VYATTA_PAGER=less --buffers=64 --auto-buffers --no-lessopen --QUIT-AT-EOF --quit-if-one-screen --RAW-CONTROL-CHARS --squeeze-blank-lines --no-init",
	"vyatta_libexecdir=/opt/vyatta/libexec",
	"vyatta_prefix=/opt/vyatta",
	"vyatta_datarootdir=/opt/vyatta/share",
	"vyatta_configdir=/opt/vyatta/config",
	"vyatta_infodir=/opt/vyatta/share/info",
	"vyatta_localedir=/opt/vyatta/share/locale",
	"PERL5LIB=/opt/vyatta/share/perl5",
}
