
#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "https_server.h"

uv_loop_t *loop;

static void https_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    
}


static void uvhttp_ssl_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf){
   
}

static void https_connection_cb(uv_stream_t *server, int status) {
    if (status == -1) {
        return;
    }

    uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client);
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
        uv_read_start((uv_stream_t*) client, https_alloc_cb, https_read_cb);
    } else {
        uv_close((uv_handle_t*) client, NULL);
    }
}

static void https_init() {
}

void thread_https_server(void *args) {
    loop = uv_default_loop();

    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    struct sockaddr_in bind_addr = uv_ip4_addr("0.0.0.0", 8443);
    uv_tcp_bind(&server, bind_addr);
    int r = uv_listen((uv_stream_t*) &server, 128, https_connection_cb);
    if (r) {
        fprintf(stderr, "Listen error!\n");
        return 1;
    }
    return uv_run(loop, UV_RUN_DEFAULT);
}
