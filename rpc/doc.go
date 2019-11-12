// Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
//
// Copyright (c) 2013-2014 by Brocade Communications Systems, Inc.
// All rights reserved.
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
	Package rpc provides access to the Vyatta operational mode RPC implementation.
	This library allows access to the operational template tree, as well as executes
	programs on the user's behalf and allowing for the user to connect back to the spawned pty.

	Access to the operational mode template tree is provided by to facilitate the implementaion
	of user interfaces in the Vyatta system. These RPC stub functions are described as part of
	their implementation. This library is currently synchronous, use of concurrent requests from
	the same client is unsupported, but concurrent requests from multiple clients is possible.

	A server implemntation invokes the RPC service in the following way:
		t, err := tree.BuildOpTree(OpTmplPath)
		l, err := net.ListenUnix("unix", ua)
		achan := make(chan rpc.Auth)

		srv := rpc.NewServer(l, t, achan, debug)
		err = srv.Serve()
		if err != nil {
			log.Fatal(err)
		}

	A simple client implementation could work this way:
		c, err := rpc.Connect("server.sock", debug)
		result, err := c.Complete(argv)
*/
package rpc
