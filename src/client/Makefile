# Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
#
# Copyright (c) 2013 by Brocade Communications Systems, Inc.
# All rights reserved.
#
# SPDX-License-Identifier: LGPL-2.1-only

INCDIR := /usr/include
LIBDIR := /usr/lib

CFLAGS += -I/usr/include/vyatta-util -g -O2 -fPIC -Wall -Werror

OBJS := opd_client.o
LIB := libopdclient.a

all: lib

lib: $(OBJS)
	$(AR) rs $(LIB) $(OBJS)

install: $(LIB)
	install -D opd_client.h $(DESTDIR)$(INCDIR)/opd_client.h
	install -D $(LIB) $(DESTDIR)$(LIBDIR)/$(LIB)

clean:
	$(RM) $(LIB) $(OBJS)
