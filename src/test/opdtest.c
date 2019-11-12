/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
  Copyright (c) 2013 by Brocade Communications Systems, Inc.

   All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
*/

#include <stdarg.h>
#include <stdio.h>
#include <stdio_ext.h>
#include <stdlib.h>
#include <string.h>
#include <jansson.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>

#include <errno.h>
#include <string.h>
#include <syslog.h>

#include <client/map.h>
#include <client/vector.h>

#include "../src/client/opd_client.h"

static int debug;

enum {
	OPD_RUN,
	OPD_COMPLETE,
	OPD_HELP,
	OPD_EXPAND,
	OPD_TMPL,
	OPD_CHILDREN,
	OPD_ALLOWED
};

static struct cmd {
	const char *cmd_name;
	int cmd_id;
} cmd_table[] = {
	{ "run", OPD_RUN },
	{ "complete", OPD_COMPLETE },
	{ "help", OPD_HELP },
	{ "expand", OPD_EXPAND },
	{ "tmpl", OPD_TMPL },
	{ "children", OPD_CHILDREN },
	{ "allowed", OPD_ALLOWED },
	{ NULL, 0 }
};

int dispatch(struct opd_connection *conn, int cmd_id, const char *arg)
{
	char *err;
	char *buf;
	struct vector *v;
	struct map *m;
	const char *str = NULL;

	switch (cmd_id) {
	case OPD_RUN:
		buf = opd_run(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR executing: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Output for '%s' is:\n", arg);
		fprintf(stdout, "%s\n", buf);
		free(buf);
		break;
	case OPD_COMPLETE:
		v = opd_complete(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR getting completion: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Completion for '%s' is:\n", arg);
		while ((str = vector_next(v, str)))
			fprintf(stdout, "\t%s\n", str);
		vector_free(v);
		break;
	case OPD_HELP:
		m = opd_help(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR getting help: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Help for '%s' is:\n", arg);
		while ((str = map_next(m, str)))
			fprintf(stdout, "\t%s\n", str);
		map_free(m);
		break;
	case OPD_EXPAND:
		v = opd_expand(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR getting expand: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Expand for '%s' is:\n", arg);
		while ((str = vector_next(v, str)))
			fprintf(stdout, "\t%s\n", str);
		vector_free(v);
		break;
	case OPD_TMPL:
		m = opd_tmpl(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR getting template: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Template '%s' is:\n", arg);
		while ((str = map_next(m, str)))
			fprintf(stdout, "\t%s\n", str);
		map_free(m);
		break;
	case OPD_CHILDREN:
		v = opd_children(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR getting children: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Children for '%s' is:\n", arg);
		while ((str = vector_next(v, str)))
			fprintf(stdout, "\t%s\n", str);
		vector_free(v);
		break;
	case OPD_ALLOWED:
		v = opd_allowed(conn, arg, &err);
		if (err) {
			fprintf(stdout, "ERROR getting allowed: %s\n", err);
			free(err);
			return -1;
		}
		fprintf(stdout, "Allowed for '%s' is:\n", arg);
		while ((str = vector_next(v, str)))
			fprintf(stdout, "\t%s\n", str);
		vector_free(v);
		break;
	default:
		fprintf(stdout, "Unknown command %d\n", cmd_id);
		return -1;
	}
	return 0;
}


int main (int argc, char **argv) {
	int result = EXIT_SUCCESS;
	struct opd_connection conn;
	int opt;
	const char *cmd = NULL;
	const char *arg = NULL;

	while ((opt = getopt(argc, argv, ":a:c:d")) != -1) {
		switch (opt) {
		case 'a':
			arg = optarg;
			break;

		case 'c':
			cmd = optarg;
			break;

		case 'd':
			++debug;
			break;

		case ':':
			fprintf(stderr, "Option %c is missing a parameter; ignoring\n", optopt);
			break;

		case '?':
		default:
			fprintf(stderr, "Unknown option %c; ignoring\n", optopt);
			break;
		}
	}

	if (opd_open(&conn) == -1) {
		fprintf(stderr, "Unable to open connection: %s\n", strerror(errno));
		goto done;
	}

	if (cmd) {
		for (opt = 0; cmd_table[opt].cmd_name; ++opt) {
			if (strcasecmp(cmd_table[opt].cmd_name, cmd) == 0)
				break;
		}
		if (!cmd_table[opt].cmd_name) {
			printf("Invalid command name: %s\n", cmd);
			printf("Supported commands:\n");
			for (opt = 0; cmd_table[opt].cmd_name; ++opt) {
				printf("\t%s\n", cmd_table[opt].cmd_name);
			}
			result = EXIT_FAILURE;
			goto done_session;
		}
		result = dispatch(&conn, cmd_table[opt].cmd_id, arg) ? EXIT_FAILURE : EXIT_SUCCESS;
	}

done_session:
	fprintf(stdout, "Done\n");
	opd_close(&conn);
done:
	exit(result);
}
