/* Copyright (c) 2009 The Go Authors. All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are
met:

   * Redistributions of source code must retain the above copyright
notice, this list of conditions and the following disclaimer.
   * Redistributions in binary form must reproduce the above
copyright notice, this list of conditions and the following disclaimer
in the documentation and/or other materials provided with the
distribution.
   * Neither the name of Google Inc. nor the names of its
contributors may be used to endorse or promote products derived from
this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
"AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE. */

// SPDX-License-Identifier: BSD-3-Clause

package pty

import (
	"os"
	"syscall"
	"unsafe"
)

// State, IsTerminal, MakeRaw, and Restore are copied from go.crypto/ssh/terminal
// but use os.File instead of an int fd as the arg

// State is the terminos struct
type State struct {
	termios syscall.Termios
}

// IsTerminal returns true if the given file descriptor is a terminal.
func IsTerminal(f *os.File) bool {
	var termios syscall.Termios
	_, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TCGETS,
		uintptr(unsafe.Pointer(&termios)), 0, 0, 0)
	return err == 0
}

// MakeRaw puts a tty into raw mode and returns the previous state
func MakeRaw(f *os.File) (*State, error) {
	var oldState State
	if _, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TCGETS,
		uintptr(unsafe.Pointer(&oldState.termios)), 0, 0, 0); err != 0 {
		return nil, err
	}

	newState := oldState.termios
	newState.Iflag &^= syscall.ISTRIP | syscall.INLCR | syscall.ICRNL | syscall.IGNCR | syscall.IXON | syscall.IXOFF
	newState.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG
	if _, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TCSETS,
		uintptr(unsafe.Pointer(&newState)), 0, 0, 0); err != 0 {
		return nil, err
	}

	return &oldState, nil
}

// Restore sets a terminal back to a previously saved state
func Restore(f *os.File, state *State) error {
	_, _, err := syscall.Syscall6(
		syscall.SYS_IOCTL,
		f.Fd(),
		syscall.TCSETS,
		uintptr(unsafe.Pointer(&state.termios)), 0, 0, 0)
	return err
}
