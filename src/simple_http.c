/* vim: set sw=4 ts=4 sts=4 et : */
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

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <syslog.h>

#include <zlib.h>
#include <event2/bufferevent_ssl.h>
#include <event2/bufferevent.h>
#include <event2/buffer.h>
#include <event2/listener.h>
#include <event2/util.h>
#include <event2/http.h>

#include "common.h"
#include "debug.h"
#include "pstring.h"
#include "centralserver.h"
#include "simple_http.h"
#include "openssl_hostname_validation.h"
#include "conf.h"
#include "version.h"

static int ignore_cert = 0;

void http_process_user_data(struct evhttp_request *req, struct http_request_get *http_req_get)
{
	struct evbuffer* buf = evhttp_request_get_input_buffer(req);
	size_t len = evbuffer_get_length(buf);
	char	*encoding = evhttp_find_header(evhttp_request_get_input_headers(req), "Content-Encoding");
	unsigned char *tmp = malloc(len+1);
	memset(tmp, 0, len+1);
	memcpy(tmp, evbuffer_pullup(buf, -1), len);
	
	int final_len = len;
	if (encoding && strcmp(encoding, "deflate") == 0) {
		char *uncompressed = NULL;
		int ret = inflate_read(tmp, len, &uncompressed, &final_len, 1);
		if (ret != Z_OK) {
			debug(LOG_INFO, "http_process_user_data  inflate_read failed ");
			if (uncompressed) free(uncompressed);
			goto err;
		}
		free(tmp);
		tmp = uncompressed;
	} 

	if (http_req_get->user_cb)
		http_req_get->user_cb(tmp, final_len);
err:
	event_base_loopbreak(http_req_get->base);
	free(tmp);
}

void http_request_post_cb(struct evhttp_request *req, void *arg)
{
    struct http_request_post *http_req_post = (struct http_request_post *)arg;
	if (req == NULL) {
		debug (LOG_INFO, "http_request_post_cb req is NULL ");
		return;
	}
	
    switch(req->response_code)
    {
        case HTTP_OK:
        {
            http_process_user_data(req, (struct http_request_get *)arg);
            break;
        }
        case HTTP_MOVEPERM:
            break;
        case HTTP_MOVETEMP:
        {
            const char *new_location = evhttp_find_header(req->input_headers, "Location");
            struct evhttp_uri *new_uri = evhttp_uri_parse(new_location);
            evhttp_uri_free(http_req_post->uri);
            http_req_post->uri = new_uri;
            start_url_request((struct http_request_get *)http_req_post, REQUEST_POST_FLAG);
            return;
        }
            
        default: 
            break;
    }
	
	 event_base_loopbreak(http_req_post->base);
}

void http_request_get_cb(struct evhttp_request *req, void *arg)
{	
    struct http_request_get *http_req_get = (struct http_request_get *)arg;
	if (req == NULL) {
		debug (LOG_INFO, "http_request_get_cb req is NULL ");
		return;
	}
	
    switch(req->response_code)
    {
        case HTTP_OK:
        {
           	http_process_user_data(req, (struct http_request_get *)arg);
            break;
        }
        case HTTP_MOVEPERM:
            break;
        case HTTP_MOVETEMP:
        {
            const char *new_location = evhttp_find_header(req->input_headers, "Location");
            struct evhttp_uri *new_uri = evhttp_uri_parse(new_location);
            evhttp_uri_free(http_req_get->uri);
            http_req_get->uri = new_uri;
            start_url_request(http_req_get, REQUEST_GET_FLAG);
            return;
        }
            
        default:   
            break;
    }

	 event_base_loopbreak(http_req_get->base);
}

int start_url_request(struct http_request_get *http_req, int req_get_flag)
{
    if (http_req->cn)
        evhttp_connection_free(http_req->cn);
    
    int port = evhttp_uri_get_port(http_req->uri);
    http_req->cn = evhttp_connection_base_new(http_req->base,
							   NULL,
							   evhttp_uri_get_host(http_req->uri),
							   (port == -1 ? 80 : port));
    
    /**
     * Request will be released by evhttp connection
     * See info of evhttp_make_request()
     */
    if (req_get_flag == REQUEST_POST_FLAG) {
        http_req->req = evhttp_request_new(http_request_post_cb, http_req);
    } else if (req_get_flag ==  REQUEST_GET_FLAG) {
        http_req->req = evhttp_request_new(http_request_get_cb, http_req);
    }
    
	/** Set the header properties */
    evhttp_add_header(http_req->req->output_headers, "Host", evhttp_uri_get_host(http_req->uri));
	
    if (req_get_flag == REQUEST_POST_FLAG) {
        const char *path = evhttp_uri_get_path(http_req->uri);
        evhttp_make_request(http_req->cn, http_req->req, EVHTTP_REQ_POST,
                            path ? path : "/");
        /** Set the post data */
        struct http_request_post *http_req_post = (struct http_request_post *)http_req;
        evbuffer_add(http_req_post->req->output_buffer, http_req_post->post_data, strlen(http_req_post->post_data));
        evhttp_add_header(http_req_post->req->output_headers, "Content-Type", http_req_post->content_type);
    } else if (req_get_flag == REQUEST_GET_FLAG) {
        const char *query = evhttp_uri_get_query(http_req->uri);
        const char *path = evhttp_uri_get_path(http_req->uri);
        size_t len = (query ? strlen(query) : 0) + (path ? strlen(path) : 0) + 1;
        char *path_query = NULL;
        if (len > 1) {
            path_query = calloc(len, sizeof(char));
			if (query)
            	snprintf(path_query, len, "%s?%s", path, query);
			else	
            	snprintf(path_query, len, "%s", path);
        }    
        evhttp_make_request(http_req->cn, http_req->req, EVHTTP_REQ_GET,
                             path_query ? path_query: "/");
    }  
	
    return 0;
}

void *http_request_new(struct event_base* base, const char *url, int req_get_flag, 
                       const char *content_type, const char* data)
{
    int len = 0;
    if (req_get_flag == REQUEST_GET_FLAG) {
        len = sizeof(struct http_request_get);
    } else if(req_get_flag == REQUEST_POST_FLAG) {
        len = sizeof(struct http_request_post);
    }
    
    struct http_request_get *http_req_get = calloc(1, len);
    http_req_get->uri = evhttp_uri_parse(url);
    
    http_req_get->base = base;
    
    if (req_get_flag == REQUEST_POST_FLAG) {
        struct http_request_post *http_req_post = (struct http_request_post *)http_req_get;
        if (content_type == NULL) {
            content_type = HTTP_CONTENT_TYPE_URL_ENCODED;
        }
        http_req_post->content_type = strdup(content_type);
        
        if (data == NULL) {
            http_req_post->post_data = NULL;
        } else {
            http_req_post->post_data = strdup(data);
        }
    }
    
    return http_req_get;
}

void http_request_free(struct http_request_get *http_req_get, int req_get_flag)
{
    evhttp_connection_free(http_req_get->cn);
    evhttp_uri_free(http_req_get->uri);
    if (req_get_flag == REQUEST_GET_FLAG) {
        free(http_req_get);
    } else if(req_get_flag == REQUEST_POST_FLAG) {
        struct http_request_post *http_req_post = (struct http_request_post*)http_req_get;
        if (http_req_post->content_type) {
            free(http_req_post->content_type);
        }
        if (http_req_post->post_data) {
            free(http_req_post->post_data);
        }
        free(http_req_post);
    }
    http_req_get = NULL;
}

void start_http_request(const char *url, int req_get_flag, 
					const char *content_type, const char* data,
					user_process_data_cb	user_cb)
{
	struct event_base* base = event_base_new();
    struct http_request_get *http_req_get = http_request_new(base, url, req_get_flag, content_type, data);
	
	http_req_get->user_cb = user_cb;
	start_url_request(http_req_get, req_get_flag);
    
	event_base_dispatch(base);

    http_request_free(http_req_get, req_get_flag);
    event_base_free(base);
}

int
deflate_write(char *source, int len, char **dest, int *wlen, int gzip)
{
	int ret;  
	unsigned have;  
	z_stream strm;  
	unsigned char out[CHUNK] = {0};  
	int totalsize = 0;  

	/* allocate inflate state */  
	strm.zalloc = Z_NULL;  
	strm.zfree = Z_NULL;  
	strm.opaque = Z_NULL;  
	strm.avail_in = 0;  
	strm.next_in = Z_NULL;  

	if(gzip)  
		ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
					  windowBits | GZIP_ENCODING,
					  8,
					  Z_DEFAULT_STRATEGY);  
	else  
		ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);  
	
	if (ret != Z_OK)  
		return ret;  

	strm.avail_in = len;  
	strm.next_in = source;  
  
	do {  
		strm.avail_out = CHUNK;  
		strm.next_out = out;  
		ret = deflate(&strm, Z_FINISH);
		switch (ret) {  
		case Z_NEED_DICT:  
			ret = Z_DATA_ERROR; /* and fall through */  
		case Z_DATA_ERROR:  
		case Z_MEM_ERROR:  
			deflateEnd(&strm);  
			return ret;  
		}  

		have = CHUNK - strm.avail_out;  
		totalsize += have;  
		*dest = realloc(*dest, totalsize);  
		memcpy(*dest + totalsize - have, out, have);
	} while (strm.avail_out == 0);  

	/* clean up and return */  
	(void)deflateEnd(&strm);
	*wlen = totalsize;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

int 
inflate_read(char *source, int len, char **dest, int *rlen, int gzip)
{  
	int ret;  
	unsigned have;  
	z_stream strm;  
	unsigned char out[CHUNK] = {0};  
	int totalsize = 0;  

	/* allocate inflate state */  
	strm.zalloc = Z_NULL;  
	strm.zfree = Z_NULL;  
	strm.opaque = Z_NULL;  
	strm.avail_in = 0;  
	strm.next_in = Z_NULL;  

	if(gzip)  
		ret = inflateInit2(&strm, -MAX_WBITS);  
	else  
		ret = inflateInit(&strm);  

	if (ret != Z_OK)  
		return ret;  

	strm.avail_in = len;  
	strm.next_in = source;  

	/* run inflate() on input until output buffer not full */  
	do {  
		strm.avail_out = CHUNK;  
		strm.next_out = out;  
		ret = inflate(&strm, Z_NO_FLUSH);   
		switch (ret) {  
		case Z_NEED_DICT:  
			ret = Z_DATA_ERROR; /* and fall through */  
		case Z_DATA_ERROR:  
		case Z_MEM_ERROR:  
			inflateEnd(&strm);  
			return ret;  
		}  
		have = CHUNK - strm.avail_out;  
		totalsize += have;  
		*dest = realloc(*dest, totalsize);  
		memcpy(*dest + totalsize - have, out, have);  
	} while (strm.avail_out == 0);  

	/* clean up and return */  
	(void)inflateEnd(&strm);  
	*rlen = totalsize;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;  
}

char *
http_get(const int sockfd, const char *req)
{
	return http_get_ex(sockfd, req, 30);
}

/**
 * Perform an HTTP request, caller frees both request and response,
 * NULL returned on error.
 * @param sockfd Socket to use, already connected
 * @param req Request to send, fully formatted.
 * @param wait 
 * @return char Response as a string
 */
char *
http_get_ex(const int sockfd, const char *req, int wait)
{
	int done, nfds; 
    ssize_t numbytes; 
    size_t reqlen = strlen(req);
    char readbuf[MAX_BUF];
    char *retval;
    pstr_t *response = pstr_new();

    if (sockfd == -1) {
        /* Could not connect to server */
        debug(LOG_ERR, "Could not open socket to server!");
        goto error;
    }

    debug(LOG_DEBUG, "Sending HTTP request to auth server: [%s]\n", req);
    numbytes = send(sockfd, req, reqlen, 0);
    if (numbytes <= 0) {
        debug(LOG_ERR, "send failed: %s", strerror(errno));
        goto error;
    } else if ((size_t) numbytes != reqlen) {
        debug(LOG_ERR, "send failed: only %d bytes out of %d bytes sent!", numbytes, reqlen);
        goto error;
    }

    debug(LOG_DEBUG, "Reading response timeout [%d]", wait);
    done = 0;
    do {		
#ifdef	SELECT
		fd_set readfds;
		struct timeval timeout;
        FD_ZERO(&readfds);
        FD_SET(sockfd, &readfds);
        timeout.tv_sec = wait;    
        timeout.tv_usec = 0;
        nfds = sockfd + 1;

        nfds = select(nfds, &readfds, NULL, NULL, &timeout);
#else
		struct pollfd fds;
        memset(&fds, 0, sizeof(fds));
        fds.fd      = sockfd;
        fds.events   = POLLIN;
        nfds = poll(&fds, 1, wait*1000);
#endif
        if (nfds > 0) {
            /** We don't have to use FD_ISSET() because there
			 *  was only one fd. */
            memset(readbuf, 0, MAX_BUF);
            numbytes = read(sockfd, readbuf, MAX_BUF - 1);
            if (numbytes < 0) {
                debug(LOG_ERR, "An error occurred while reading from server: %s", strerror(errno));
                goto error;
            } else if (numbytes == 0) {
				debug(LOG_INFO, "Server close connection: %s", strerror(errno));
				close_auth_server();
                done = 1;
            } else {
                readbuf[numbytes] = '\0';
                pstr_cat(response, readbuf);
                debug(LOG_DEBUG, "Read %d bytes", numbytes);
				if(numbytes < MAX_BUF - 1)
					done = 1;
            }
        } else if (nfds == 0) {
            debug(LOG_ERR, "Timed out reading data via select() from auth server");
            goto error;
        } else if (nfds < 0) {
            debug(LOG_ERR, "Error reading data via select() from auth server: %s", strerror(errno));
            goto error;
        }
    } while (!done);

    retval = pstr_to_string(response);
    debug(LOG_DEBUG, "HTTP Response from Server: [%s]", retval);
    return retval;

 error:
    retval = pstr_to_string(response);
    free(retval);
    return NULL;
}

static int 
cert_verify_callback(X509_STORE_CTX *x509_ctx, void *arg)
{
	char cert_str[256] = {0};
	const char *host = (const char *) arg;
	const char *res_str = "X509_verify_cert failed";
	HostnameValidationResult res = Error;

	/* This is the function that OpenSSL would call if we hadn't called
	 * SSL_CTX_set_cert_verify_callback().  Therefore, we are "wrapping"
	 * the default functionality, rather than replacing it. */
	int ok_so_far = 0;

	X509 *server_cert = NULL;

	if (ignore_cert) {
		return 1;
	}

	ok_so_far = X509_verify_cert(x509_ctx);

	server_cert = X509_STORE_CTX_get_current_cert(x509_ctx);

	if (ok_so_far) {
		res = validate_hostname(host, server_cert);

		switch (res) {
		case MatchFound:
			res_str = "MatchFound";
			break;
		case MatchNotFound:
			res_str = "MatchNotFound";
			break;
		case NoSANPresent:
			res_str = "NoSANPresent";
			break;
		case MalformedCertificate:
			res_str = "MalformedCertificate";
			break;
		case Error:
			res_str = "Error";
			break;
		default:
			res_str = "WTF!";
			break;
		}
	}

	X509_NAME_oneline(X509_get_subject_name (server_cert),
			  cert_str, sizeof (cert_str));

	if (res == MatchFound) {
		debug(LOG_INFO, "https server '%s' has this certificate, "
		       "which looks good to me:\n%s\n",
		       host, cert_str);
		return 1;
	} else {
		debug(LOG_INFO, "Got '%s' for hostname '%s' and certificate:\n%s\n",
		       res_str, host, cert_str);
		return 0;
	}
}

struct evhttps_request_context *
evhttps_context_init(void)
{
	struct evhttps_request_context *context = NULL;
	SSL_CTX *ssl_ctx = NULL;
	struct event_base 	*base = NULL;

	context = (struct evhttps_request_context *) malloc(sizeof(struct evhttps_request_context));
	if (context == NULL)
		goto cleanup;

	/* This isn't strictly necessary... OpenSSL performs RAND_poll
	 * automatically on first use of random number generator. */
	if (RAND_poll() == 0) {
		debug(LOG_ERR, "RAND_poll failed");
		goto cleanup;
	}

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) {
		debug(LOG_ERR, "SSL_CTX_new failed");
		goto cleanup;
	}

#ifdef	VERIFY_PEER
	if (1 != SSL_CTX_load_verify_locations(ssl_ctx, crt, NULL)) {
		debug(LOG_ERR, "SSL_CTX_load_verify_locations failed");
		goto cleanup;
	}
	
	SSL_CTX_set_verify(ssl_ctx, SSL_VERIFY_PEER, NULL);
	
	SSL_CTX_set_cert_verify_callback(ssl_ctx, cert_verify_callback,
					  (void *) auth_server->authserv_hostname);
#endif
	// Create event base
	base = event_base_new();
	if (!base) {
		debug(LOG_ERR, "event_base_new() failed");
		goto cleanup;
	}

	context->base 		= base;
	context->ssl_ctx 	= ssl_ctx;
	return context;

cleanup:
	if (context)
		free(context);

	if (ssl_ctx)
		SSL_CTX_free(ssl_ctx);	

	if (base)
		 event_base_free(base);

	return NULL;
}

void 
evhttps_context_exit(struct evhttps_request_context *context)
{
	if (!context)
		return;

	if (context->base)
		event_base_free(context->base);

	if (context->ssl_ctx)
		SSL_CTX_free(context->ssl_ctx);
}

void 
evhttp_set_request_header(struct evhttp_request *req)
{
	char user_agent[128] = {0};
	snprintf(user_agent, 128, "ApFree WiFiDog %s", VERSION);
	struct evkeyvalq *output_headers = evhttp_request_get_output_headers(req);
	evhttp_add_header(output_headers, "Host", get_auth_server()->authserv_hostname);
	evhttp_add_header(output_headers, "User-Agent", user_agent);
	evhttp_add_header(output_headers, "Connection", "keep-alive");
}

void
evhttps_request(struct evhttps_request_context *context, const char *uri, int timeout, request_done_cb process_request_done, void *data)
{
	t_auth_serv *auth_server = get_auth_server();
#ifdef	VERIFY_PEER
	const char *crt = "/etc/ssl/certs/ca-certificates.crt";
#endif
	SSL_CTX *ssl_ctx = context->ssl_ctx;
	SSL *ssl = NULL;
	
	struct event_base 	*base = context->base;
	struct bufferevent 	*bev = NULL;
	struct evhttp_connection *evcon = NULL;
	struct evhttp_request *req;
	
	int ret = 0;
		
	
	// Create OpenSSL bufferevent and stack evhttp on top of it
	ssl = SSL_new(ssl_ctx);
	if (ssl == NULL) {
		debug(LOG_ERR, "SSL_new() failed");
		goto cleanup;
	}
	
#ifdef SSL_CTRL_SET_TLSEXT_HOSTNAME
	// Set hostname for SNI extension
	SSL_set_tlsext_host_name(ssl, auth_server->authserv_hostname);
#endif

	bev = bufferevent_openssl_socket_new(base, -1, ssl,
			BUFFEREVENT_SSL_CONNECTING,
			BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if (bev == NULL) {
		debug(LOG_ERR, "bufferevent_openssl_socket_new() failed");
		goto cleanup;
	}
	
	bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);

	evcon = evhttp_connection_base_bufferevent_new(base, NULL, bev,
		auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	if (evcon == NULL) {
		debug(LOG_ERR, "evhttp_connection_base_bufferevent_new() failed");
		goto cleanup;
	}
	
	evhttp_connection_set_timeout(evcon, timeout);
	context->data = data;
	req = evhttp_request_new(process_request_done, context);
	if (req == NULL) {
		debug(LOG_ERR, "evhttp_request_new() failed");
		goto cleanup;
	}
	
	evhttp_set_request_header(req);
	
	ret = evhttp_make_request(evcon, req, EVHTTP_REQ_GET, uri);
	if (ret != 0) {
		debug(LOG_ERR, "evhttp_make_request() failed");
		goto cleanup;
	}

	event_base_dispatch(base);

cleanup:
	if (evcon)
		evhttp_connection_free(evcon);
}
