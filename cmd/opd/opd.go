// Copyright (c) 2018-2019, AT&T Intellectual Property.
// All rights reserved.
//
// Copyright (c) 2013, 2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
Opd is a daemon that authorizes and runs commands from the Vyatta operational template tree.

Usage:
	-debug
		Enable debug logging

	-adebug
		Enable authorization debug logging

	-cpuprofile=<filename>
		Defines a file which to write a cpu profile that can be parsed with go pprof.
		When defined, the daemon will begin recording cpu profile information when it
		receives a SIGUSR1 signal. Then on a subsequent SIGUSR1 it will write the profile
		information to the defined file.

	-memprofile=<filename>
		Defines a file which to write a memory profile that can be parsed with go pprof.
		When defined, a heap profile will be written when the daemon receives the
		SIGUSR2 signal.

	-ruleset=<filename>
		Default: "/opt/vyatta/etc/opruleset.txt"
		When defined the default path to the operational ruleset is overridden by the
		provided filename.

	-tmplpath=<path>
		Default: "/opt/vyatta/share/vyatta-op/templates"
		When defined the default path to the operational templates is overridden by
		the provided path.
	-pidfile=<filename>
		When defined opd will write its pid to the defined file.
	-logfile=<filename>
		When defined opd will redirect its stdout and stderr to the defined file.
	-user=<user>
		When defined opd will set its loginuid to the uid of this user.
	-group=<group>
		When defined opd will make its main socket owned by and writeble by this group.

	SIGHUP
		Issuing SIGHUP to the daemon will trigger a reread of the operational templates
		and the authorization ruleset from their defined paths. In the case of the
		authorization ruleset if an invalid file is found the ruleset will remain unchanged.
*/
package main

import (
	"flag"
	"fmt"
	"github.com/coreos/go-systemd/activation"
	"log"
	"net"
	"os"
	"os/signal"
	"path"
	"runtime/pprof"
	"syscall"

	"github.com/danos/op/tmpl/tree"
	"github.com/danos/op/yang"
)

var runningprof bool
var cpuproffile os.File

var srv *Server

/*Flags*/
var debug *bool = flag.Bool("debug",
	false,
	"Enable debugging.")

var adebug *bool = flag.Bool("adebug",
	false,
	"Enable auth debugging.")

var cpuprofile *string = flag.String("cpuprofile",
	"",
	"Write cpu profile to supplied file on SIGUSR1.")

var memprofile *string = flag.String("memprofile",
	"",
	"Write mem profile to supplied file on SIGUSR2.")

var ruleset *string = flag.String("authorization",
	"/opt/vyatta/etc/opruleset.txt",
	"Read authorization ruleset from supplied file.")

var vyattaOpTmplPath *string = flag.String("tmplpath",
	"/opt/vyatta/share/vyatta-op/templates",
	"Read operational templates from the supplied path.")

var pidfile *string = flag.String("pidfile",
	"",
	"Write pid to supplied file.")

var logfile *string = flag.String("logfile",
	"",
	"Redirect std{out,err} to supplied file.")

var usr *string = flag.String("user",
	"",
	"Set loginuid to this user's id")

var grp *string = flag.String("group",
	"",
	"Set socket group ownership to this group")

func sigdumpmem() {
	sigch := make(chan os.Signal)
	signal.Notify(sigch, syscall.SIGUSR2)
	for {
		<-sigch
		if *memprofile != "" {
			f, err := os.Create(*memprofile)
			if err != nil {
				log.Fatal(err)
			}
			pprof.WriteHeapProfile(f)
			f.Close()
		}
	}
}

func sigstartprof() {
	sigch := make(chan os.Signal)
	signal.Notify(sigch, syscall.SIGUSR1)
	for {
		<-sigch
		if *cpuprofile != "" {
			if !runningprof {
				cpuproffile, err := os.Create(*cpuprofile)
				if err != nil {
					log.Fatal(err)
				}
				pprof.StartCPUProfile(cpuproffile)
				runningprof = true
			} else {
				pprof.StopCPUProfile()
				cpuproffile.Close()
				runningprof = false
			}
		}
	}
}

func sigloadtree(asig chan os.Signal) {
	sigch := make(chan os.Signal)
	signal.Notify(sigch, syscall.SIGHUP)
	for {
		sig := <-sigch
		if srv == nil {
			continue
		}
		var t *tree.OpTree
		var err error
		t, err = tree.BuildOpTree(*vyattaOpTmplPath)
		if err != nil {
			log.Print(err)
			continue
		}
		srv.T = t
		asig <- sig
	}

}

func openLogfile() {
	if logfile == nil {
		return
	}
	dir := path.Dir(*logfile)
	os.MkdirAll(dir, os.ModePerm)
	f, e := os.OpenFile(*logfile, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0640)
	if e != nil {
		fmt.Fprintf(os.Stderr, "%s\n", e)
		return
	}
	defer f.Close()
	syscall.Dup2(int(f.Fd()), 1)
	syscall.Dup2(int(f.Fd()), 2)
}

func writePid() {
	if pidfile == nil {
		return
	}
	f, e := os.OpenFile(*pidfile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if e != nil {
		fmt.Fprintf(os.Stderr, "%s\n", e)
		return
	}
	defer f.Close()
	pid := os.Getpid()
	fmt.Fprintf(f, "%d\n", pid)
}

func main() {
	var exit int = 0
	var err error

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	var socket string = "/var/run/vyatta/opd/main.sock"

	defer func() { os.Exit(exit) }()

	openLogfile()

	asig := make(chan os.Signal)
	go sigloadtree(asig)

	go sigstartprof()
	go sigdumpmem()

	var t *tree.OpTree
	t, err = tree.BuildOpTree(*vyattaOpTmplPath)
	if err != nil {
		log.Print(err)
		exit = 1
		return
	}

	yang := yang.NewYang()

	listeners, err := activation.Listeners(true)
	if err != nil {
		log.Print(err)
		exit = 1
		return
	}
	if len(listeners) == 0 {
		os.Remove(socket)
		ua, err := net.ResolveUnixAddr("unix", socket)
		if err != nil {
			log.Print(err)
			exit = 1
			return
		}

		l, err := net.ListenUnix("unix", ua)
		if err != nil {
			log.Print(err)
			exit = 1
			return
		}
		defer l.Close()
		os.Chmod(socket, 0777)
		listeners = append(listeners, l)
	}
	l := listeners[0]

	achan := make(chan *Auth)
	pchan := make(chan *PermReq)
	acctChan := make(chan *AcctReq)
	go auth(*ruleset, achan, pchan, acctChan, asig, *adebug)

	srv = NewServer(l.(*net.UnixListener), t, yang, achan, pchan, acctChan, *debug)

	writePid()

	err = srv.Serve()
	if err != nil {
		log.Print(err)
		exit = 1
		return
	}
}
