// Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2013-2017 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
)

type Cmd struct {
	Path     string
	Args     []string
	Env      []string
	Dir      string
	Uid      uint32
	Setuid   bool
	Istty    bool
	Termpath string
	Stdin    io.ReadCloser
	Stdout   io.WriteCloser
	Stderr   io.WriteCloser
}

func getExecCommand(cmd *Cmd) (*exec.Cmd, error) {
	/*prepare command for exec*/
	c := exec.Command(cmd.Path, cmd.Args...)
	if cmd.Env != nil {
		var dir string
		for _, v := range cmd.Env {
			ev := strings.Split(v, "=")
			if len(ev) < 2 {
				continue
			}
			switch ev[0] {
			case "PWD":
				dir = ev[1]
			}
		}
		c.Env = cmd.Env
		c.Env = append(c.Env, fmt.Sprintf("OPD_PTY=%t", cmd.Istty))
		if !cmd.Istty {
			c.Env = append(c.Env, "TERM=dumb")
		}
		c.Dir = dir
	}

	c.Stdout = cmd.Stdout
	c.Stdin = cmd.Stdin
	c.Stderr = cmd.Stderr
	c.SysProcAttr = &syscall.SysProcAttr{
		Setctty: cmd.Istty,
		// Set session ID to true for all processes, to
		// ensure it dies when the parent process dies
		Setsid: true,
	}

	return c, nil
}

func Run(cmd *Cmd) (int, error) {
	var err error
	var term *os.File
	var rc int = 1

	term, err = os.OpenFile(cmd.Termpath, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return rc, err
	}

	defer term.Close()

	cmd.Stdin = term
	cmd.Stdout = term
	cmd.Stderr = term

	c, err := getExecCommand(cmd)
	if err != nil {
		return rc, err
	}

	err = c.Start()
	if err != nil {
		return rc, err
	}

	if err = c.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				rc = status.ExitStatus()
			}
		}
	} else {
		rc = 0
	}

	return rc, nil
}
