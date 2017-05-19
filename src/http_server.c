/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/* $Id$ */
/** @file http_server.c
  @brief 
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
  */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <sys/stat.h>
#include <sys/socket.h>
#include <signal.h>
#include <fcntl.h>
#include <unistd.h>
#include <dirent.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>

#include <syslog.h>

#include "http_server.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "wd_util.h"
#include "util.h"
#include "firewall.h"
#include "safe.h"

static const struct table_entry {
	const char *extension;
	const char *content_type;
} content_type_table[] = {
	{ "html", "text/html" },
	{ "htm", "text/html" },
	{ "shtml", "text/html" },
	{ "xhtml", "text/html" },
	{ "dhtml", "text/html" },
	{ "jsp", "text/html" },
	{ "asp", "text/html" },
	{ "php", "text/html" },
	{ "css", "text/css" },
	{ "js", "application/javascript"},
	{ "gif", "image/gif" },
	{ "jpg", "image/jpeg" },
	{ "jpeg", "image/jpeg" },
	{ "png", "image/png" },
	{ NULL, NULL },
};

static const char *
get_content_extension(const char *path)
{
	const char *last_period, *extension;
	last_period = strrchr(path, '.');
	if (!last_period || strchr(last_period, '/'))
		return NULL; /* no exension */
	extension = last_period + 1;
	return extension;
}

/* Try to guess a good content-type for 'path' */
static const char *
guess_content_type(const char *extension)
{
	const struct table_entry *ent;
	if (extension == NULL)
		goto not_found;

	for (ent = &content_type_table[0]; ent->extension; ++ent) {
		if (!evutil_ascii_strcasecmp(ent->extension, extension))
			return ent->content_type;
	}

not_found:
	return "text/html";
}

static void
http_403_callback(struct evhttp_request *req, void *arg) {
	struct evbuffer *evb = NULL;
	const char *docroot = arg;
	const char *uri = evhttp_request_get_uri(req);
	struct evhttp_uri *decoded = NULL;
	const char *path;
	char *decoded_path;
	char *whole_path = NULL;
	size_t len;
	int fd = -1;
	struct stat st;


	if (evhttp_request_get_command(req) != EVHTTP_REQ_GET) {
		// only support HTTP GET
		return;
	}

	/* Decode the URI */
	decoded = evhttp_uri_parse(uri);
	if (!decoded) {
		evhttp_send_error(req, HTTP_BADREQUEST, 0);
		return;
	}

	/* Let's see what path the user asked for. */
	path = evhttp_uri_get_path(decoded);
	if (!path) path = "/";

	/* We need to decode it, to see what path the user really wanted. */
	decoded_path = evhttp_uridecode(path, 0, NULL);
	if (decoded_path == NULL)
		goto err;	

	const char *extension = get_content_extension(decoded_path);
	if ((extension != NULL) && (strncmp(extension,"jpg",3) == 0)) {
		len = strlen("img/limited.jpg")+strlen(docroot)+2;
		if (!(whole_path = malloc(len))) {
			goto err;
		}
		evutil_snprintf(whole_path, len, "%s%s", docroot, "img/limited.jpg");
	} else {	
		len = strlen("403.html")+strlen(docroot)+2;
		if (!(whole_path = malloc(len))) {
			goto err;
		}
		evutil_snprintf(whole_path, len, "%s403.html", docroot);
	}

	if (stat(whole_path, &st)<0) {
		goto err;
	}

	evb = evbuffer_new();

	if (S_ISREG(st.st_mode)) {
		/* Otherwise it's a file; add it to the buffer to get
		 * sent via sendfile */
		
		const char *type = guess_content_type(extension);
		if ((fd = open(whole_path, O_RDONLY)) < 0) {
			goto err;
		}

		if (fstat(fd, &st)<0) {
			/* Make sure the length still matches, now that we
			 * opened the file :/ */
			goto err;
		}

		evhttp_add_header(evhttp_request_get_output_headers(req),
		    "Content-Type", type);
		evbuffer_add_file(evb, fd, 0, st.st_size);
	}

	evhttp_send_reply(req, 200, "OK", evb);
	goto done;

err:
	evhttp_send_error(req, 404, "Document was not found");
	if (fd >= 0)
		close(fd);
done:
	if (decoded)
		evhttp_uri_free(decoded);
	if (decoded_path)
		free(decoded_path);
	if (whole_path)
		free(whole_path);
	if (evb)
		evbuffer_free(evb);	
}

static void serve_403_http(const char *address, const t_http_server *http_server) {
	struct event_base *base;
	struct evhttp *http;
	struct evhttp_bound_socket *handle = NULL;

	base = event_base_new();
	if (!base) {
		return;
	}

	/* Create a new evhttp object to handle requests. */
	http = evhttp_new(base);
	if (!http) {
		goto end_loop;
	}

	evhttp_set_gencb(http, http_403_callback, http_server->base_path);

	handle = evhttp_bind_socket_with_handle(http, address, http_server->gw_http_port);
	if (!handle) {
		goto end_loop;
	}

	event_base_dispatch(base);

end_loop:
	if (handle)
		evhttp_del_accept_socket(http, handle);

	if (http)
		evhttp_free(http);

	if (base)
		event_base_free(base);
}

void thread_http_server(void *args) {
	s_config *config = config_get_config();
   	serve_403_http (config->gw_address, config->http_server);
}
