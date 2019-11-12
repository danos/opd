/* Copyright (c) 2011 Keith Rarick

Permission is hereby granted, free of charge, to any person
obtaining a copy of this software and associated
documentation files (the "Software"), to deal in the
Software without restriction, including without limitation
the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall
be included in all copies or substantial portions of the
Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY
KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE
WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS
OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE. */

// SPDX-License-Identifier: MIT

package pty

import (
	"os"
	"strconv"
	"syscall"
	"unsafe"
)

const (
	sys_TIOCGPTN   = 0x80045430
	sys_TIOCSPTLCK = 0x40045431
)

func open() (pty, tty *os.File, err error) {
	p, err := os.OpenFile("/dev/ptmx", os.O_RDWR, 0)
	if err != nil {
		return nil, nil, err
	}

	sname, err := ptsname(p)
	if err != nil {
		return nil, nil, err
	}

	err = unlockpt(p)
	if err != nil {
		return nil, nil, err
	}

	t, err := os.OpenFile(sname, os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	return p, t, nil
}

func ptsname(f *os.File) (string, error) {
	var n int
	err := ioctl(f.Fd(), sys_TIOCGPTN, &n)
	if err != nil {
		return "", err
	}
	return "/dev/pts/" + strconv.Itoa(n), nil
}

func unlockpt(f *os.File) error {
	var u int
	return ioctl(f.Fd(), sys_TIOCSPTLCK, &u)
}

func ioctl(fd uintptr, cmd uintptr, data *int) error {
	_, _, e := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		cmd,
		uintptr(unsafe.Pointer(data)),
	)
	if e != 0 {
		return syscall.ENOTTY
	}
	return nil
}
