// Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

package client

import (
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/danos/opd/pty"
)

func setPtySize(watch, f *os.File) error {
	h, w, err := pty.Getsize(watch)
	if err != nil {
		return err
	}
	return pty.Setsize(f, h, w)
}

func startSigWinch(watch io.Writer, f *os.File, done chan struct{}) {
	watchf, ok := watch.(*os.File)
	if !ok {
		return
	}
	err := setPtySize(watchf, f)
	if err != nil {
		return
	}
	go func() {
		sigwinch := make(chan os.Signal)
		signal.Notify(sigwinch, syscall.SIGWINCH)
		for {
			select {
			case <-sigwinch:
				err = setPtySize(watchf, f)
				if err != nil {
					return
				}
			case <-done:
				return
			}
		}
	}()
}

func startCopiers(inf io.Reader, outf io.Writer, term *os.File, done chan struct{}) {
	outdone := make(chan struct{})
	indone := make(chan struct{})
	go func() {
		select {
		case <-outdone:
		case <-indone:
		}
		close(done)
		term.Close()
	}()

	if inf != nil {
		go func() {
			io.Copy(term, inf)
			close(indone)
		}()
	}

	go func() {
		io.Copy(outf, term)
		close(outdone)
	}()
}

func OpenPtyMaster() (*os.File, string, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, "", err
	}
	pty.Unlockpt(master)
	ptsname, err := pty.Ptsname(master)
	if err != nil {
		return nil, "", err
	}
	return master, ptsname, nil
}

func OpenTerminal(input io.Reader, output io.Writer, istty bool) (string, chan struct{}, error) {
	var term *os.File
	var termname string
	var err error
	done := make(chan struct{})
	term, termname, err = OpenPtyMaster()
	if err != nil {
		return "", nil, err
	}
	if istty {
		startSigWinch(output, term, done)
	} else {
		pty.Makefilelike(term)
	}
	startCopiers(input, output, term, done)
	return termname, done, nil
}
