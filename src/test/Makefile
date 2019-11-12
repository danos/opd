# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2013 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

INCDIR := /usr/include
LIBDIR := /usr/lib

CFLAGS += -I/usr/include/vyatta-cfg -g -O2 -fPIC -Wall -Werror
LDFLAGS += -L../src/client -lopdclient -lvyatta-config -ljansson

BIN := opdtest
OBJ := opdtest.o

all: $(BIN)

$(BIN): $(OBJ) ../src/client/libopdclient.a
	$(CC) -o $@ $< $(LDFLAGS)

opdtest.o: opdtest.c ../src/client/opd_client.h

clean:
	$(RM) $(BIN) $(OBJ)
