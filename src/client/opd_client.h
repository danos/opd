/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
  Copyright (c) 2013 by Brocade Communications Systems, Inc.

   All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
*/

#ifndef OPD_CLIENT_H_
#define OPD_CLIENT_H_

#ifdef __cplusplus
extern "C" {
#endif

struct map;
struct vector;

struct opd_connection {
	int fd;              ///< Socket fd
	FILE *fp;            ///< Stream for socket
	unsigned int req_id; ///< Previously used request id
};

int opd_open(struct opd_connection *);
void opd_close(struct opd_connection *);

char *opd_run(struct opd_connection *, const char *, char **);
struct vector *opd_complete(struct opd_connection *, const char *, char **);
struct map *opd_help(struct opd_connection *, const char *, char **);
struct vector *opd_expand(struct opd_connection *, const char *, char **);
struct map *opd_tmpl(struct opd_connection *, const char *, char **);
struct vector *opd_children(struct opd_connection *, const char *, char **);
struct vector *opd_allowed(struct opd_connection *, const char *, char **);
struct map *opd_getperms(struct opd_connection *, char **);

#ifdef __cplusplus
}
#endif

#endif
