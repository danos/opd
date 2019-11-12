/*
 * Copyright (c) 2019, AT&T Intellectual Property. All rights reserved.
 *
  Copyright (c) 2013 by Brocade Communications Systems, Inc.

  All rights reserved.
 *
 * SPDX-License-Identifier: LGPL-2.1-only
*/

#include <argz.h>
#include <envz.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <syslog.h>
#include <unistd.h>

#include <vyatta-util/map.h>
#include <vyatta-util/vector.h>
#include <jansson.h>

#include "opd_client.h"

static void msg_(FILE *, int, const char *fmt, ...) __attribute__ ((format (printf, 3, 4)));

#define DEBUG 1
#undef DEBUG

enum {
	FnRun,       ///< Execute template's run block
	FnComplete,  ///< Return list of possible completions
	FnHelp,      ///< Return help string
	FnExpand,    ///< Return fully expanded path
	FnTmpl,      ///< Gets the template
	FnChildren,  ///< Return list of template's children
	FnAllowed,    ///< Return template's allowed values
	FnGetPerms    ///< Return user's permissions
};

struct opd_request {
	int func_id;         ///< function id
	json_t *args;        ///< arguments in JSON array
};

struct opd_response {
	json_t *result;  ///< Response from opd
	char *err;       ///< Error string
	unsigned int id; ///< Request id that response is for
};


/* Set if the message functions also generate output to stdout/stderr */
#ifdef DEBUG
static int use_console_ = 1;
#else
static int use_console_;
#endif

static void msg_(FILE *stream, int severity, const char *fmt, ...)
{
	va_list ap;
	if (use_console_) {
		va_start(ap, fmt);
		vfprintf(stream, fmt, ap);
		va_end(ap);
	}
	va_start(ap, fmt);
	vsyslog(severity, fmt, ap);
	va_end(ap);
}

#define msg_out(f, ...) msg_(stdout, LOG_NOTICE, f , ##__VA_ARGS__)
#define msg_err(f, ...) msg_(stderr, LOG_ERR, f , ##__VA_ARGS__)
#define msg_dbg(f, ...) msg_(stderr, LOG_NOTICE, f , ##__VA_ARGS__)

#ifdef DEBUG
static void msg_json(const json_t *jobj, const char *pfx)
{
	char *jstr = json_dumps(jobj, 0);
	if (jstr) {
		msg_out("%s: %s\n", pfx, jstr);
		free(jstr);
	}
}
#else
#define msg_json(...)
#endif

#define set_err(e,s) do { if (e) *e = s; else free(s); } while (0)

static struct vector *jarray_to_vector(json_t *jobj)
{
	int local_errno = 0;
	struct vector *v = NULL;
	size_t arr_len, i;
	size_t argz_len = 0;
	char *argz = NULL;

	if (!jobj || json_is_null(jobj))
		return NULL;

	arr_len = json_array_size(jobj);
	for (i = 0; i < arr_len; ++i) {
		json_t *jval;
		const char *vstr;

		jval = json_array_get(jobj, i);
		vstr = json_string_value(jval);
		if (!vstr) {
			local_errno = EINVAL;
			goto error;
		}

		if (argz_add(&argz, &argz_len, vstr)) {
			local_errno = ENOMEM;
			goto error;
		}
	}

	v = vector_new(argz, argz_len);
	if (!v) {
		local_errno = ENOMEM;
		goto error;
	}
	goto done;

error:
	free(argz);
done:
	errno = local_errno;
	return v;
}

static struct map *jobj_to_map(json_t *jobj)
{
	int local_errno = 0;
	struct map *m = NULL;
	size_t argz_len = 0;
	char *argz = NULL;

	const char *key;
	json_t *jval;

	if (!jobj || json_is_null(jobj))
		return NULL;

	json_object_foreach(jobj, key, jval) {
		const char *vstr;

		vstr = json_string_value(jval);
		if (!vstr) {
			local_errno = EINVAL;
			goto error;
		}

		if (envz_add(&argz, &argz_len, key, vstr)) {
			local_errno = errno;
			goto error;
		}
	}

	m = map_new(argz, argz_len);
	if (!m) {
		local_errno = ENOMEM;
		goto error;
	}
	goto done;

error:
	free(argz);
done:
	errno = local_errno;
	return m;
}

/* There are no communication timeouts as some operations
 * (e.g., commit) can take an unbounded amount of time.
 */
int opd_open(struct opd_connection *conn)
{
	socklen_t len;
	int local_errno;
	struct sockaddr_un configd = { .sun_family = AF_UNIX, .sun_path = "/var/run/vyatta/opd/main.sock" };

	if (!conn) {
		errno = EFAULT;
		return -1;
	}

	memset(conn, 0, sizeof(*conn));
	conn->fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (conn->fd == -1)
		return -1;

	len = SUN_LEN(&configd);
	if (connect(conn->fd, (struct sockaddr *)&configd, len) == -1) {
		local_errno = errno;
		goto error;
	}

	conn->fp = fdopen(conn->fd, "r+");
	if (!conn->fp) {
		local_errno = errno;
		msg_err("%s: Unable to open socket stream\n", __func__);
		goto error;
	}
	return 0;

error:
	opd_close(conn);
	errno = local_errno;
	return -1;
}

void opd_close(struct opd_connection *conn)
{
	if (conn->fp)
		fclose(conn->fp);
	if (conn->fd != -1)
		close(conn->fd);
}


static int send_request(struct opd_connection *conn, const struct opd_request *req)
{
	json_t *jreq;
	json_error_t jerr;
	int result = -1;
	char *jstr;

	if (!conn || !req || !json_is_array(req->args)) {
		errno = EFAULT;
		return -1;
	}

	jreq = json_pack_ex(&jerr, 0, "{s:i, s:o, s:i}",
			    "method", req->func_id,
			    "args", req->args,
			    "id", ++(conn->req_id));
	if (!jreq || json_is_null(jreq)) {
		msg_err("Unable to pack JSON request: %s\n", jerr.text);
		return -1;
	}

	msg_json(jreq, __func__); /* debugging */
	jstr = json_dumps(jreq, JSON_COMPACT);
	if (jstr) {
		result = write(conn->fd, jstr, strlen(jstr));
		free(jstr);
	}

	json_decref(jreq);
	return result;
}

static int receive_response(struct opd_connection *conn, struct opd_response *resp)
{
	json_t *jresp = NULL;
	json_t *jobj;
	const char *str;
	int ret = -1;
	json_error_t jerr;

	if (!conn || !resp) {
		errno = EFAULT;
		return -1;
	}

	memset(resp, 0, sizeof(*resp));
	while (jresp == NULL && !feof(conn->fp))
		jresp = json_loadf(conn->fp, JSON_DISABLE_EOF_CHECK, &jerr);

	if (!jresp || json_is_null(jresp)) {
		msg_err("%s: %s\n", __func__, jerr.text);
		return -1;
	}

	msg_json(jresp, __func__); /* debugging */

	/* If we have an error, there are no results */
	jobj = json_object_get(jresp, "error");
	str = json_string_value(jobj);
	if (str && strlen(str))
		resp->err = strdup(str);
	else {
		jobj = json_object_get(jresp, "result");
		if (!json_is_null(jobj))
			resp->result = json_incref(jobj);

	}

	jobj = json_object_get(jresp, "id");
	resp->id = json_integer_value(jobj);

	ret = (conn->req_id == resp->id) ? 0 : -1;
	json_decref(jresp);
	return ret;
}

char *opd_run(struct opd_connection *conn, const char *opath, char **errstr)
{
	struct opd_request req = { .func_id = FnRun };
	struct opd_response resp;
	const char *v;
	char *r = NULL;

	req.args = json_pack("[s]", opath);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	v = json_string_value(resp.result);
	if (v && strlen(v))
		r = strdup(v);
	json_decref(resp.result);
	return r;
}

struct vector *opd_complete(struct opd_connection *conn, const char *opath, char **errstr)
{
	struct opd_request req = { .func_id = FnComplete };
	struct opd_response resp;
	struct vector *v;

	req.args = json_pack("[s]", opath);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	v = jarray_to_vector(resp.result);
	json_decref(resp.result);
	return v;
}

struct map *opd_help(struct opd_connection *conn, const char *opath, char **errstr)
{
	struct opd_request req = { .func_id = FnHelp };
	struct opd_response resp;
	struct map *m;

	req.args = json_pack("[s]", opath);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	m = jobj_to_map(resp.result);
	json_decref(resp.result);
	return m;
}

struct vector *opd_expand(struct opd_connection *conn, const char *cmd, char **errstr)
{
	struct opd_request req = { .func_id = FnExpand };
	struct opd_response resp;
	struct vector *v;

	req.args = json_pack("[s]", cmd);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	v = jarray_to_vector(resp.result);
	json_decref(resp.result);
	return v;
}

struct map *opd_tmpl(struct opd_connection *conn, const char *opath, char **errstr)
{
	struct opd_request req = { .func_id = FnTmpl };
	struct opd_response resp;
	struct map *m;

	req.args = json_pack("[s]", opath);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	m = jobj_to_map(resp.result);
	json_decref(resp.result);
	return m;
}

struct vector *opd_children(struct opd_connection *conn, const char *opath, char **errstr)
{
	struct opd_request req = { .func_id = FnChildren };
	struct opd_response resp;
	struct vector *v;

	req.args = json_pack("[s]", opath);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	v = jarray_to_vector(resp.result);
	json_decref(resp.result);
	return v;
}

struct vector *opd_allowed(struct opd_connection *conn, const char *opath, char **errstr)
{
	struct opd_request req = { .func_id = FnAllowed };
	struct opd_response resp;
	struct vector *v;

	req.args = json_pack("[s]", opath);
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	v = jarray_to_vector(resp.result);
	json_decref(resp.result);
	return v;
}

struct map *opd_getperms(struct opd_connection *conn, char **errstr)
{
	struct opd_request req = { .func_id = FnGetPerms };
	struct opd_response resp;
	struct map *m;

	req.args = json_pack("[s]", "/");
	if (send_request(conn, &req) == -1)
		return NULL;
	if (receive_response(conn, &resp) == -1)
		return NULL;
	set_err(errstr, resp.err);
	m = jobj_to_map(resp.result);
	json_decref(resp.result);
	return m;
}
