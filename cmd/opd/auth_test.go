// Copyright (c) 2019-2021, AT&T Intellectual Property.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"fmt"
	"github.com/danos/utils/os/group"
	"github.com/danos/utils/pathutil"
	"testing"

	"github.com/danos/op/tmpl/tree"

	"github.com/danos/aaa"
)

type DummyPlugin struct {
	errorAuthorization bool
	errorValidUser     bool
	failAuthorization  bool
	failValidUser      bool
}

func (p *DummyPlugin) Setup() error {
	return nil
}

func (p *DummyPlugin) ValidUser(uid uint32, groups []string) (bool, error) {
	if p.errorValidUser {
		return false, fmt.Errorf("Dummy failure of ValidUser method.")
	}
	return !p.failValidUser, nil
}

func (p *DummyPlugin) Authorize(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs) (bool, error) {
	if p.errorAuthorization {
		return false, fmt.Errorf("Dummy failure of Authorization method.")
	}
	return !p.failAuthorization, nil
}

func (p *DummyPlugin) NewTask(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs, env map[string]string) (aaa.AAATask, error) {
	return nil, nil
}

func (p *DummyPlugin) Account(context string, uid uint32, groups []string, path []string,
	pathAttrs *pathutil.PathAttrs, env map[string]string) error {
	return nil
}

func newDummyAAA() (*aaa.AAA, *aaa.AAAPluginConfig, *DummyPlugin) {

	var aaaif aaa.AAA
	var protocol aaa.AAAProtocol
	name := "DummyAAA"
	plugin := DummyPlugin{false, false, false, false}

	aaaif.Protocols = make(map[string]*aaa.AAAProtocol)

	protocol.Plugin = &plugin
	protocol.Cfg = aaa.AAAPluginConfig{false, false, name}

	aaaif.Protocols[name] = &protocol

	return &aaaif, &protocol.Cfg, &plugin
}

func TestAaaAuthorizePath(t *testing.T) {

	adb := loadauth("", false)
	var uid uint32 = 2000
	var groups = make([]*group.Group, 0)
	var path = make(tree.Path, 0)
	pathAttrs := pathutil.NewPathAttrs()
	run := false

	aaaif, cfg, plugin := newDummyAAA()

	// 1. if command authorization is disabled -> false, true, nil
	cfg.CmdAuthor = false
	ret, skip, err := adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != false || skip != true || err != nil {
		t.Errorf("Unexpected return value if command authorization is disabled\n")
	}

	// 2. if the plugin fails to validate if it's responsible for the user
	//    -> false, true, nil
	cfg.CmdAuthor = true
	plugin.errorValidUser = true
	ret, skip, err = adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != false || skip != true || err != nil {
		t.Errorf("Unexpected return value if plugin fails to validate " +
			"if it's responsible for the user\n")
	}
	plugin.errorValidUser = false

	// 3. if user is not valid for any AAA plugin -> false, true, nil
	plugin.failValidUser = true
	ret, skip, err = adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != false || skip != true || err != nil {
		t.Errorf("Unexpected return value if user is not valid for any AAA plugin\n")
	}
	plugin.failValidUser = false

	// 4. if the command is a non-run command and executed by an AAA user
	//	-> true, false, nil
	//	Local ACM is supposed to get bypassed. AAA is authoritative.
	run = false
	ret, skip, err = adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != true || skip != false || err != nil {
		t.Errorf("Unexpected return value for a non-run command\n")
	}
	run = true

	// 5. if authorization request results in error -> false, false, !nil
	plugin.errorAuthorization = true
	ret, skip, err = adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != false || skip != false || err == nil {
		t.Errorf("Unexpected return value if authorization failed due to error\n")
	}
	plugin.errorAuthorization = false

	// 6. if authorization for the command is rejected -> false, false, nil
	plugin.failAuthorization = true
	ret, skip, err = adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != false || skip != false || err != nil {
		t.Errorf("Unexpected return value if authorization got rejected\n")
	}
	plugin.failAuthorization = false

	// 7. if authorization for the command is accepted -> true, false, nil
	ret, skip, err = adb.aaaAuthorizePath(aaaif, uid, groups, path, &pathAttrs, run)
	if ret != true || skip != false || err != nil {
		t.Errorf("Unexpected return value if authorization got rejected\n")
	}

}
