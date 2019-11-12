// Copyright (c) 2019 by AT&T Intellectual Property.
// All rights reserved.

// Copyright (c) 2013-2017 by Brocade Communications, Inc.
// All rights reserved.

// SPDX-License-Identifier: MPL-2.0

package pty

import (
	"os"
	"os/signal"
	"syscall"
	"time"
	"unsafe"
)

func Makefilelike(f *os.File) (*State, error) {
	var oldState State
	if _, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TCGETS,
		uintptr(unsafe.Pointer(&oldState.termios)), 0, 0, 0); err != 0 {
		return nil, err
	}

	newState := oldState.termios
	newState.Oflag &^= syscall.ONLCR
	if _, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TCSETS,
		uintptr(unsafe.Pointer(&newState)), 0, 0, 0); err != 0 {
		return nil, err
	}

	return &oldState, nil
}

func IsForeground(f *os.File) bool {
	var mypid = syscall.Getpgrp()
	//var termios syscall.Termios
	var tpid int
	_, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TIOCGPGRP,
		uintptr(unsafe.Pointer(&tpid)), 0, 0, 0)
	if err != 0 {
		return false
	}
	return tpid == mypid

}

func Setsize(f *os.File, rows, cols uint16) error {
	/*The C struct for this is equiv to the below*/
	var ws winsize
	ws.ws_row = rows
	ws.ws_col = cols

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, f.Fd(),
		uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(&ws)))
	if errno != 0 {
		return syscall.Errno(errno)
	}
	return nil
}

func Resizer(parent, child *os.File) {
	sigwinch := make(chan os.Signal)
	signal.Notify(sigwinch, syscall.SIGWINCH)

	for {
		select {
		case <-sigwinch:
			// pause because of race when maximizing window
			time.Sleep(10 * time.Millisecond)
			h, w, _ := Getsize(parent)
			Setsize(child, h, w)
		}
	}
}
