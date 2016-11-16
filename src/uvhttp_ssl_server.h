#ifndef UVHTTP_SSL_SERVER_H__
#define UVHTTP_SSL_SERVER_H__
#include <stdlib.h>
#if defined(_MSC_VER) || defined(__MINGW64_VERSION_MAJOR)
#include <crtdbg.h>
#endif
#include <uv.h>
#ifdef  _MBEDTLS_
#include <mbedtls/config.h>
#include <mbedtls/platform.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ssl.h>
#else
#include <polarssl/entropy.h>
#include <polarssl/ctr_drbg.h>
#include <polarssl/certs.h>
#include <polarssl/x509.h>
#include <polarssl/ssl.h>
#include <polarssl/error.h>
#include <polarssl/debug.h>
#endif
#include "uvhttp_internal.h"
#include "uvhttp_util.h"

#ifndef _MBEDTLS_
typedef pk_context mbedtls_pk_context;
typedef entropy_context mbedtls_entropy_context;
typedef ctr_drbg_context mbedtls_ctr_drbg_context;
typedef x509_crt mbedtls_x509_crt;
typedef ssl_context mbedtls_ssl_context;

#define mbedtls_ssl_close_notify    ssl_close_notify
#define mbedtls_ssl_handshake_step  ssl_handshake_step
#define mbedtls_ssl_read            ssl_read
#define mbedtls_ssl_write           ssl_write
#define mbedtls_fprintf             polarssl_fprintf
#define mbedtls_x509_crt_init       x509_crt_init
#define mbedtls_ctr_drbg_seed       ctr_drbg_init
#define mbedtls_entropy_init        entropy_init
#define mbedtls_pk_init             pk_init
#define mbedtls_x509_crt_parse      x509_crt_parse
#define mbedtls_pk_parse_key        pk_parse_key
#define mbedtls_ssl_init            ssl_init
#define mbedtls_ssl_free            ssl_free
#define mbedtls_x509_crt_free       x509_crt_free
#define mbedtls_pk_free             pk_free
#define mbedtls_ctr_drbg_free       ctr_drbg_free
#define mbedtls_entropy_free        entropy_free

#define MBEDTLS_ERR_SSL_WANT_WRITE          POLARSSL_ERR_NET_WANT_WRITE
#define MBEDTLS_ERR_SSL_WANT_READ           POLARSSL_ERR_NET_WANT_READ
#define MBEDTLS_SSL_HANDSHAKE_OVER          SSL_HANDSHAKE_OVER
#define MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY   POLARSSL_ERR_SSL_PEER_CLOSE_NOTIFY
#endif

#define MIN(a,b) (((a)<(b))?(a):(b))
#define MAX(a,b) (((a)>(b))?(a):(b))

struct uvhttp_ssl_session {
    uv_tcp_t tcp;
    uv_buf_t user_read_buf;
    uv_close_cb user_close_cb;
    uv_read_cb user_read_cb;
    uv_write_cb user_write_cb;
    uv_alloc_cb user_alloc_cb;
    uv_write_t* user_write_req;
    char ssl_read_buffer[UVHTTP_NET_BUFFER_SIZE];
    unsigned int ssl_read_buffer_len;
    unsigned int ssl_read_buffer_offset;
    unsigned int ssl_write_offset;
    unsigned int ssl_write_buffer_len;
    char* ssl_write_buffer;
    char is_async_writing;
    char is_writing;
    char is_write_error;
    char is_closing;
    uv_buf_t write_buffer;
    mbedtls_ssl_context ssl;
};

struct uvhttp_ssl_server {
    uv_tcp_t tcp;
    uv_close_cb user_close_cb;
    mbedtls_pk_context key;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
#ifdef _MBEDTLS_
    mbedtls_ssl_config conf;
#endif
    mbedtls_x509_crt srvcert;
};

int uvhttp_ssl_server_init(
    uv_loop_t* loop,
    uv_tcp_t* handle
    );

int uvhttp_ssl_session_init(
    uv_loop_t* loop,
    uv_tcp_t* handle,
    uv_tcp_t* server
    );

int uvhttp_ssl_read_session_start(
    uv_stream_t* stream,
    uv_alloc_cb alloc_cb,
    uv_read_cb read_cb
    );

int uvhttp_ssl_session_write(
    uv_write_t* req,
    uv_stream_t* handle,
    char* buffer,
    unsigned int buffer_len,
    uv_write_cb cb
    );

void uvhttp_ssl_session_close(
    uv_handle_t* handle, 
    uv_close_cb close_cb
    );

void uvhttp_ssl_server_close(
    uv_handle_t* handle, 
    uv_close_cb close_cb
    );
#endif // UVHTTP_SSL_SERVER_H__
