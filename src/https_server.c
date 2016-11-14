
#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "https_server.h"

uv_loop_t *loop;

static void https_read_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    struct uvhttp_ssl_session* ssl = (struct uvhttp_ssl_session*)stream;
    if ( nread <= 0) {
        goto cleanup;
    }
    
    if ( ssl->is_closing) {
        int ret = mbedtls_ssl_close_notify( &ssl->ssl);
        if ( uv_is_closing( (uv_handle_t*)ssl) == 0) {
            uv_close( (uv_handle_t*)stream, uvhttp_ssl_session_close_cb);
        }
    } else if ( ssl->ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
        int ret = 0;
        ssl->ssl_read_buffer_len = nread;
        ssl->ssl_read_buffer_offset = 0;
        while ( (ret = mbedtls_ssl_handshake_step( &ssl->ssl )) == 0) {
            if ( ssl->ssl.state == MBEDTLS_SSL_HANDSHAKE_OVER){
                break;
            }
        }
        if ( ssl->ssl_read_buffer_offset != nread) {
            nread = -1;
            goto cleanup;
        }
        ssl->ssl_read_buffer_len = 0;
        ssl->ssl_read_buffer_offset = 0;
        if ( ret != 0 && ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            nread = -1;
            goto cleanup;
        }
    } else {
        int ret = 0;
        int read_len = 0;
        ssl->ssl_read_buffer_len = nread;
        ssl->ssl_read_buffer_offset = 0;

        //可能本次由于没有读取到一个完整的块，导致一点数据也不返回。
        while((read_len = mbedtls_ssl_read( &ssl->ssl, 
            (unsigned char *)ssl->user_read_buf.base,  ssl->user_read_buf.len)) > 0) {
            ssl->user_read_cb( stream, read_len, &ssl->user_read_buf);
        }
        if ( read_len !=0 && read_len != MBEDTLS_ERR_SSL_WANT_READ) {
            if ( MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == read_len) {
                nread = UV_ECONNABORTED;
                goto cleanup;
            }
            else {
                nread = -1;
                goto cleanup;
            }
        }
    }
cleanup:
    if ( nread <= 0) {
        ssl->user_read_cb( stream, nread, 0);
    }
}


static void uvhttp_ssl_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf){
    /*
    struct uvhttp_ssl_session* ssl = (struct uvhttp_ssl_session*)handle;
    ssl->user_read_buf.base = 0;
    ssl->user_read_buf.len = 0;
    ssl->user_alloc_cb( handle, suggested_size, &ssl->user_read_buf);
    buf->base = ssl->ssl_read_buffer;
    buf->len = sizeof( ssl->ssl_read_buffer);
    */
}

void on_new_connection(uv_stream_t *server, int status) {
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


void thread_https_server(void *args) {
    loop = uv_default_loop();

    uv_tcp_t server;
    uv_tcp_init(loop, &server);

    struct sockaddr_in bind_addr = uv_ip4_addr("0.0.0.0", 8443);
    uv_tcp_bind(&server, bind_addr);
    int r = uv_listen((uv_stream_t*) &server, 128, on_new_connection);
    if (r) {
        fprintf(stderr, "Listen error!\n");
        return 1;
    }
    return uv_run(loop, UV_RUN_DEFAULT);
}
