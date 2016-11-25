#ifndef	_HTTPS_SERVER_H_
#define	_HTTPS_SERVER_H_
void thread_https_server(void *args);

struct evbuffer *get_full_redir_url(const char *mac, const char *ip, const char *orig_url);
#endif
