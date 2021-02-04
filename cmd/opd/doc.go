// Copyright (c) 2019, 2021, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2013-2016 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
	runner fork/exec's the requested child process connected to a
    pty passed in from the client. If the pty doesn't exist the
    process will fail.  The cmdclient package creates a pty.  The pty
    file descriptor is passed to the cmdrunner via an SCM_RIGHTS
    ancilliary message passed via main.sock. This is done through the opd
    Run RPC. Run now blocks until the process exits and returns the exit
    code from the opd child.


	A diagram of how process spawning  works is included below:

       +---------------+    main.sock      +----------------------+
       |               +------------------>+                      |
       |      opc      +<------------------+         opd          |
       |               |                   |                      |
       |.+-----------+.|                   |.+------------------+.|
       ++             ++                   ++                    ++
       ||    cmdc     ||                   ||     cmdrunner      ||
       ++             ++                   ++                    ++
       |'+-----------+'|                   |'+------------------+'|
       +^-+--------+-^-+                   +----------------------+
        | |        | |                                    |fork/exec
        | |        | |                                    V
      in/out       | |                              .+-----------+.
        | |        | |                              +  requested  +
        | |       in/out                            +   process   +
      +-+-v--+     | |                              '+---^-+-----+'
      | tty  |     | |                                   | |
      +------+     | |                                  in/out
      +------+     | |                                   | |
      | user | +---v-+-----------------------------------+-V--------+
      +------+ |                       PTY                          |
               +----------------------------------------------------+



*/
package main
