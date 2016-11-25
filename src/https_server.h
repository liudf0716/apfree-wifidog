#ifndef	_HTTPS_SERVER_H_
#define	_HTTPS_SERVER_H_
void thread_https_server(void *args);

char*get_full_redir_url(const char *mac, const char *ip, const char *orig_url);
void evhttpd_gw_reply(struct evhttp_request *req, enum reply_type type);
char *evhttp_get_request_url(struct evhttp_request *req);

#endif
