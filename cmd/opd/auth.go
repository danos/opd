// Copyright (c) 2018-2019, AT&T Intellectual Property.
// All rights reserved.
//
// Copyright (c) 2013, 2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"encoding/json"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/danos/utils/guard"
	"github.com/danos/utils/os/group"
	"github.com/danos/utils/pathutil"

	"github.com/danos/op/tmpl/tree"

	"github.com/danos/aaa"
)

type AuthPerm uint

const (
	P_CREATE AuthPerm = 1 << iota
	P_READ
	P_UPDATE
	P_DELETE
	P_EXECUTE
)

type AuthAction uint

const (
	AUTH_DENY AuthAction = 1 << iota
	AUTH_ALLOW
)

type Authdb struct {
	Enabled  bool `json:"enabled"`
	debug    bool
	Default  AuthAction `json:"exec-default"`
	Rulelist []*Rule    `json:"rules"`
}

func convertGroupsToStrings(groups []*group.Group) []string {
	ret := make([]string, len(groups))
	for i, v := range groups {
		ret[i] = v.Name
	}
	return ret
}

func (a *Authdb) aaaAccount(
	aaaif *aaa.AAA,
	uid uint32,
	groups []*group.Group,
	path []string,
	pathAttrs *pathutil.PathAttrs,
	env map[string]string,
) error {

	if aaaif == nil {
		return nil
	}

	groupsStr := convertGroupsToStrings(groups)

	for aaaName, proto := range aaaif.Protocols {
		if !proto.Cfg.CmdAcct {
			continue
		}

		// Assumes configuration will enforce only one accounting protocol.
		// The first protocol located to perform accounting will be used.
		err := guard.CatchPanicErrorOnly(func() error {
			return proto.Plugin.Account("op-mode", uid, groupsStr, path, pathAttrs, env)
		})
		if err != nil {
			a.logf("Accounting error via AAA protocol %s: %v", aaaName, err)
		}
		return err
	}

	return nil
}

func (a *Authdb) account(aaaif *aaa.AAA, uid uint32, groups []*group.Group,
	path []string, pathAttrs *pathutil.PathAttrs, env map[string]string) error {
	// For now accounting happens for *all* users by a AAA plugin
	return a.aaaAccount(aaaif, uid, groups, path, pathAttrs, env)
}

func authEnvToMap(env *AuthEnv) map[string]string {
	return map[string]string{"tty": env.Tty}
}

func account(a *Authdb, aaaif *aaa.AAA, req *AcctReq) {
	a.account(aaaif, req.Uid, req.Groups, req.Path, req.PathAttrs, authEnvToMap(&req.Env))
}

/* First bool returns the result, second if the result should be discarded and AAA
   authorization should be skipped. */
func (a *Authdb) aaaAuthorizePath(
	aaaif *aaa.AAA,
	uid uint32,
	groups []*group.Group,
	path []string,
	pathAttrs *pathutil.PathAttrs,
	run bool,
) (bool, bool, error) {

	var err error
	skip := true
	result := false

	/* (Remote) AAA protocol authorization only applied if any AAA plugin is enabled. */
	if aaaif != nil {
		for aaaName, proto := range aaaif.Protocols {
			if !proto.Cfg.CmdAuthor {
				continue
			}
			groupsStr := convertGroupsToStrings(groups)
			isValidUser, err := guard.CatchPanicBoolError(func() (bool, error) {
				return proto.Plugin.ValidUser(uid, groupsStr)
			})
			if err != nil {
				a.logf("Error validating user (%d) via AAA protocol %s: %v", uid, aaaName, err)
				continue
			}
			if !isValidUser {
				continue
			}

			// Bypass local ACM for non-run commands
			if !run {
				result = true
				skip = false
				return result, skip, err
			}

			// Assumes configuration will enforce only one authorisation protocol per user.
			// The first protocol located to authorise a user will provide the definitive
			// result.
			result, err = guard.CatchPanicBoolError(func() (bool, error) {
				return proto.Plugin.Authorize("op-mode", uid, groupsStr, path, pathAttrs)
			})

			if err != nil {
				a.logf("Authorization error via AAA protocol %s: %v", aaaName, err)
			}
			skip = false
			return result, skip, err
		}
	}

	return result, skip, err
}

func (a *Authdb) authorize(aaaif *aaa.AAA, uid uint32, groups []*group.Group,
	path tree.Path, pathAttrs *pathutil.PathAttrs, run bool) (bool, error) {

	/* (Remote) AAA protocol authorization commands */
	ret, skip, err := a.aaaAuthorizePath(aaaif, uid, groups, path, pathAttrs, run)
	if !skip {
		return ret, err
	}

	if !a.Enabled {
		return true, nil
	}

	if r, ok := a.match(uid, groups, path, run); ok {
		if a.debug {
			a.logf("authorize: matched rule %v", r)
		}
		if r.Log {
			a.logRule(uid, r)
		}

		switch r.Action {
		case AUTH_DENY:
			return false, nil
		case AUTH_ALLOW:
			return true, nil
		}
	}
	if a.Default == AUTH_ALLOW {
		return true, nil
	}
	return false, nil
}

func (a *Authdb) logRule(uid uint32, r *Rule) {
	log.Printf("Uid: %d, matched rule: %#v", uid, r)
}

func (a *Authdb) logf(fmt string, v ...interface{}) {
	log.Printf(fmt, v...)
}

func (a *Authdb) match(uid uint32, groups []*group.Group, path tree.Path, run bool) (*Rule, bool) {
	for _, r := range a.Rulelist {
		if a.matchPath(r.path, path, run, r.Action) && a.matchUid(uid, groups, r.Groups) {
			return r, true
		}
	}
	return nil, false
}

func (a *Authdb) matchUid(uid uint32, uidGroups []*group.Group, groups []string) bool {
	if uidGroups == nil {
		uidGroups, _ = group.LookupUid(strconv.Itoa(int(uid)))
	}
	if a.debug {
		a.logf("matchUid: comparing %v to %v", groups, uidGroups)
	}
	for _, v := range groups {
		for _, g := range uidGroups {
			if g.Name == v {
				if a.debug {
					a.logf("matchUid: found matching group %s", g.Name)
				}
				return true
			}
		}
	}
	return false
}

func (a *Authdb) matchPath(rulepath tree.Path, reqpath tree.Path, run bool, act AuthAction) bool {
	if len(rulepath) == 0 {
		a.logf("matchPath failed: empty rulepath")
		return false
	}
	if a.debug {
		a.logf("matchPath: comparing %v to %v", rulepath, reqpath)
	}
	var i int
	var v string
	for i, v = range rulepath {
		if v == "*" {
			if i == len(rulepath)-1 {
				return true
			}
			continue
		}
		if i >= len(reqpath) {
			if run {
				if a.debug {
					a.logf("matchPath failed: want run but not exact match")
				}
				return false
			}
			/*We need to allow completions for parents of allowed children*/
			switch act {
			case AUTH_ALLOW:
				return true
			/*but if the rule is deny, we shouldn't match the parent*/
			case AUTH_DENY:
				return false
			}
		}
		if v != reqpath[i] {
			if a.debug {
				a.logf("matchPath failed: %s != %s", v, reqpath[i])
			}
			return false
		}
	}
	if i < len(reqpath)-1 {
		if a.debug {
			a.logf("matchPath failed: i:%d < len(reqpath):%d", i, len(reqpath))
		}
		return false
	}
	return true
}

type Rule struct {
	Path   string `json:"path"`
	path   tree.Path
	Perm   AuthPerm   `json:"perm"`
	Action AuthAction `json:"action"`
	Log    bool       `json:"log"`
	Groups []string   `json:"groups"`
}

func loadauth(ruleset string, debug bool) *Authdb {
	f, e := os.Open(ruleset)
	if e != nil {
		return nil
	}

	dec := json.NewDecoder(f)
	var adb Authdb
	e = dec.Decode(&adb)
	if e != nil {
		log.Print(e)
		return nil
	}
	for _, r := range adb.Rulelist {
		r.path = strings.Split(r.Path, "/")
		if r.path[0] == "" {
			r.path = r.path[1:] //strip leading '/'
		}
	}
	if debug {
		adb.debug = true
		log.Printf("%v\n", adb)
		for _, r := range adb.Rulelist {
			log.Printf("%v\n", r)
		}
	}
	return &adb
}

func authorize(adb *Authdb, aaaif *aaa.AAA, areq *Auth) {
	areq.Resp <- newAuthResp(adb.authorize(aaaif, areq.Uid, areq.Groups, areq.P, areq.PAttrs, areq.Run))
}

func getperms(adb *Authdb, preq *PermReq) {
	result := make(map[string]string)
	var defaultperm AuthPerm
	if adb.Default == AUTH_ALLOW {
		defaultperm = P_EXECUTE
	}
	for i, rule := range adb.Rulelist {
		if adb.matchUid(preq.Uid, preq.Groups, rule.Groups) {
			perm := defaultperm
			if rule.Action == AUTH_DENY {
				perm = perm & ^rule.Perm
			} else {
				perm = perm | rule.Perm
			}
			key := strconv.Itoa(i) + ": " + rule.Path
			result[key] = strconv.Itoa(int(perm))
		}
	}
	result["10000: DEFAULT"] = strconv.Itoa(int(defaultperm))
	preq.Resp <- result
}

func auth(ruleset string, achan chan *Auth, pchan chan *PermReq,
	acctChan chan *AcctReq, sig chan os.Signal, debug bool) {
	adb := loadauth(ruleset, debug)
	if adb == nil {
		adb = &Authdb{}
	}
	aaaif, err := aaa.LoadAAA()
	if err != nil {
		log.Printf("Could not load AAA subystem: %s", err)
		aaaif = &aaa.AAA{}
	}
	if aaaif == nil {
		aaaif = &aaa.AAA{}
	}
	for {
		select {
		case areq := <-achan:
			go authorize(adb, aaaif, areq)
		case preq := <-pchan:
			go getperms(adb, preq)
		case acctReq := <-acctChan:
			go account(adb, aaaif, acctReq)
		case <-sig:
			adbt := loadauth(ruleset, debug)
			if adbt != nil {
				adb = adbt
			}
			aaat, err := aaa.LoadAAA()
			if err != nil {
				log.Printf("Could not reload AAA subystem: %s", err)
			} else if aaat != nil {
				aaaif = aaat
			}
		}
	}
}
