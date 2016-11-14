
#include <netinet/in.h>  /* INET6_ADDRSTRLEN */
#include <stdlib.h>
#include <string.h>
#include <uv.h>

#include "https_server.h"

uv_loop_t *loop;

static void *https_session_new() {
    int ret = 0;
    ssl_context *ssl;
    entropy_context entropy;
    ctr_drbg_context ctr_drbg;
    
    ssl = calloc(1, sizeof(ssl_context));
    if (!ssl)
        return NULL;

    ret = ssl_int(ssl);
    if (ret != 0) {
        free(ssl);
        return NULL
    }
    
    ret = ctr_drbg_init(&ctr_drbg, entropy_func, &entropy, (const unsigned char *) pers, strlen(pers));
    if (ret != 0) {
        free(ssl);
        return NULL;
    }
    
    ssl_set_endpoint(ssl, SSL_IS_SERVER );
    ssl_set_authmode(ssl, SSL_VERIFY_NONE );

    /* SSLv3 is deprecated, set minimum to TLS 1.0 */
    ssl_set_min_version(ssl, SSL_MAJOR_VERSION_3, SSL_MINOR_VERSION_1 );
    /* RC4 is deprecated, disable it */
    ssl_set_arc4_support(ssl, SSL_ARC4_DISABLED );
    
    ssl_set_rng(ssl, ctr_drbg_random, &ctr_drbg);
    
    ssl_session_reset(ssl);
    
    return ssl;
}

static void https_connection_cb(uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf) {
    
}


static void https_alloc_cb(uv_handle_t* handle, size_t suggested_size, uv_buf_t* buf){
   
}

static void https_connection_cb(uv_stream_t *server, int status) {
    if (status == -1) {
        return;
    }

    uv_tcp_t *client = (uv_tcp_t*) malloc(sizeof(uv_tcp_t));
    uv_tcp_init(loop, client);
    if (uv_accept(server, (uv_stream_t*) client) == 0) {
        uv_read_start((uv_stream_t*) client, https_alloc_cb, https_connection_cb);
    } else {
        uv_close((uv_handle_t*) client, NULL);
    }
}

static void https_init() {
    int ret = 0;
    x509_crt *srvcert;
    pk_context *pkey;

    x509_crt_init( srvcert );
    pk_init( pkey );
    
    ret = x509_crt_parse_file(srvcert, config->ssl_ctx->crt_file);
    if (ret != 0) {
        
    }
    
    ret = pk_parse_keyfile(pkey, config->ssl_ctx->key_file, NULL);
    if (ret != 0) {
    }
    

}

static void https_exit() {
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
