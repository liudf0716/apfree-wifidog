#include "uvhttp_server.h"
#include "uvhttp_base.h"
#include "uvhttp_server_internal.h"
#include "uvhttp_ssl_server.h"
#include "http_parser.h"
#include <stdarg.h>
#include <syslog.h>
#include "debug.h"

static void server_session_connected(
    uv_stream_t* stream,
    int status
    );

static void session_data_alloc( 
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf
    );

static void session_close( 
    struct uvhttp_session_obj* session_obj
    );

static void session_data_read(
    uv_stream_t* stream,
    ssize_t nread,
    const uv_buf_t* buf
    );

static void session_delete( 
    struct uvhttp_session_obj* session_obj
    );

static void session_reset( 
    struct uvhttp_session_obj* session_obj
    );
    
static void session_error(
    struct uvhttp_session_obj* session_obj
    );

int uvhttp_server_set_option( 
    uvhttp_server server,
    uvhttp_server_option option,
    ...
    )
{
    int ret = 0;
    struct uvhttp_server_obj* server_obj = (struct uvhttp_server_obj*)server;
    va_list ap;
    va_start(ap, option);
    switch( option)
    {
    case UVHTTP_SRV_OPT_USER_DATA:
        server_obj->user_data = va_arg(ap, void*);
        break;
    case UVHTTP_SRV_OPT_SESSION_NEW_CB:
        server_obj->session_new_callback = va_arg(ap, uvhttp_server_session_new_callback);
        break;
    case UVHTTP_SRV_OPT_END_CB:
        server_obj->end_callback = va_arg(ap, uvhttp_server_end_callback);
        break;
    case UVHTTP_SRV_OPT_SSL:
        server_obj->ssl = va_arg( ap, unsigned char);
    default:
        ret = UVHTTP_ERROR_NOOPTIONS;
        break;
    }
    va_end(ap);
    return ret;
}

int uvhttp_session_set_option( 
    uvhttp_session session,
    uvhttp_session_option option,
    ...
    )
{
    int ret = 0;
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)session;
    va_list ap;
    va_start(ap, option);
    switch( option)
    {
    case UVHTTP_SESSION_OPT_USER_DATA:
        session_obj->user_data = va_arg(ap, void*);
        break;
    case UVHTTP_SESSION_OPT_REQUEST_CB:
        session_obj->request_callback = va_arg(ap, uvhttp_session_request_callback);
        break;
    case UVHTTP_SESSION_OPT_REQUEST_BODY_CB:
        session_obj->body_read_callback = va_arg(ap, uvhttp_session_body_read_callback);
        break;
    case UVHTTP_SESSION_OPT_REQUEST_END_CB:
        session_obj->request_end_callback = va_arg(ap, uvhttp_session_request_end_callback);
        break;
    case UVHTTP_SESSION_OPT_END_CB:
        session_obj->end_callback = va_arg(ap, uvhttp_session_end_callback);
        break;
    default:
        ret = UVHTTP_ERROR_NOOPTIONS;
        break;
    }
    va_end(ap);
    return ret;
}

int uvhttp_server_get_info( 
    uvhttp_server server,
    uvhttp_server_info info,
    ...
    )
{
    int ret = 0;
    struct uvhttp_server_obj* server_obj = (struct uvhttp_server_obj*)server;
    va_list ap;
    va_start(ap, info);
    switch( info)
    {
    case UVHTTP_SRV_INFO_USER_DATA:
        {
            *va_arg(ap, void**) = server_obj->user_data;
        }
        break;
    case UVHTTP_SRV_INFO_UVTCP:
        {
            *va_arg(ap, uv_tcp_t**) = (uvhttp_loop)server_obj->tcp;
        }
        break;
    case UVHTTP_SRV_INFO_LOOP:
        {
            *va_arg(ap, uvhttp_loop*) = (uvhttp_loop)server_obj->loop;
        }
        break;
    default:
        ret = UVHTTP_ERROR_NOOPTIONS;
        break;
    }
    va_end(ap);
    return ret;
}

int uvhttp_session_get_info( 
    uvhttp_session session,
    uvhttp_session_info info,
    ...
    )
{
    int ret = 0;
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)session;
    va_list ap;
    va_start(ap, info);
    switch( info)
    {
    case UVHTTP_SESSION_INFO_USER_DATA:
        {
            *va_arg(ap, void**) = session_obj->user_data;
        }
        break;
    case UVHTTP_SESSION_INFO_UVTCP:
        {
            *va_arg(ap, uv_tcp_t**) = (uvhttp_loop)session_obj->tcp;
        }
        break;
    case UVHTTP_SESSION_INFO_LOOP:
        {
            *va_arg(ap, uvhttp_loop*) = (uvhttp_loop)session_obj->loop;
        }
        break;
    case UVHTTP_SESSION_INFO_MESSAGE:
        {
            *va_arg(ap, struct uvhttp_message**) = (struct uvhttp_message*)&session_obj->request;
        }
        break;
    default:
        ret = UVHTTP_ERROR_NOOPTIONS;
        break;
    }
    va_end(ap);
    return ret;
}

uvhttp_server uvhttp_server_new(
    uvhttp_loop loop
    )
{
    struct uvhttp_server_obj* server_obj = (struct uvhttp_server_obj*)malloc( 
        sizeof(struct uvhttp_server_obj) );

    memset( server_obj, 0, sizeof(struct uvhttp_server_obj));
    server_obj->loop = (uv_loop_t*)loop;

    return server_obj;
}

int uvhttp_server_ip4_listen(
    uvhttp_server server,
    const char* ip,
    int port
    )
{
    struct sockaddr_in addr;
    struct uvhttp_server_obj* server_obj = (struct uvhttp_server_obj*)server;
    int ret = 0;
    if ( server_obj->ssl) {
        if ( !server_obj->tcp) {
            server_obj->tcp = (uv_tcp_t*)malloc( sizeof(struct uvhttp_ssl_server) );
            memset( server_obj->tcp, 0, sizeof(struct uvhttp_ssl_server));
        }
        server_obj->tcp->data = server_obj;
        ret = uvhttp_ssl_server_init( server_obj->loop, server_obj->tcp);
    }
    else {
        if ( !server_obj->tcp) {
            server_obj->tcp = (uv_tcp_t*)malloc( sizeof(uv_tcp_t) );
            memset( server_obj->tcp, 0, sizeof(uv_tcp_t));
        }
        server_obj->tcp->data = server_obj;
        ret = uv_tcp_init( server_obj->loop, server_obj->tcp );
    }
    if ( ret != 0)
        goto cleanup;
    server_obj->status = UVHTTP_SRV_STATUS_RUNNING;
    ret = uv_ip4_addr( ip, port, &addr);
    if ( ret != 0)
        goto cleanup;
    ret = uv_tcp_bind( server_obj->tcp, (const struct sockaddr*)&addr, 0);
    if ( ret != 0)
        goto cleanup;
    ret = uv_tcp_nodelay( server_obj->tcp, 1);
    if ( ret != 0)
        goto cleanup;
    ret = uv_listen((uv_stream_t*)server_obj->tcp, 1024, server_session_connected);
    if ( ret != 0)
        goto cleanup;
cleanup:
    return ret;
}

static void server_session_connected(
    uv_stream_t* stream,
    int status
    ) 
{
    int ret = 0;
    struct uvhttp_server_obj* server_obj = 0;
    struct uvhttp_session_obj* session_obj = 0;

    if ( status != 0) {
		debug(LOG_ERR, "server_session_connected failed!");
        ret = UVHTTP_ERROR_FAILED;
        goto cleanup;
    }

    server_obj = (struct uvhttp_server_obj*)stream->data;
    session_obj = (struct uvhttp_session_obj*)malloc( sizeof(struct uvhttp_session_obj));
    memset( session_obj, 0, sizeof(struct uvhttp_session_obj));

    http_parser_init( &session_obj->parser, HTTP_REQUEST);
    session_obj->server_obj = server_obj;
    session_obj->loop = server_obj->loop;

    if ( server_obj->ssl ) {
        session_obj->tcp = (uv_tcp_t*)malloc( sizeof(struct uvhttp_ssl_session) );
        memset( session_obj->tcp, 0, sizeof(struct uvhttp_ssl_session)); 
        session_obj->tcp->data = session_obj;
        ret = uvhttp_ssl_session_init( session_obj->loop, session_obj->tcp, server_obj->tcp);
        if ( ret != 0) {
			debug(LOG_ERR, "uvhttp_ssl_session_init failed!!!");	
            session_delete( session_obj);
            return;
        }
    }
    else {
        session_obj->tcp = (uv_tcp_t*)malloc( sizeof(uv_tcp_t) );
        memset( session_obj->tcp, 0, sizeof(uv_tcp_t)); 
        session_obj->tcp->data = session_obj;
        ret = uv_tcp_init( session_obj->loop, session_obj->tcp);
        if ( ret != 0) {
            session_delete( session_obj);
            return;
        }
    }
    ret = uv_tcp_nodelay( session_obj->tcp, 1);
    if ( ret != 0)
        goto cleanup;
    ret = uv_accept( stream, (uv_stream_t*)session_obj->tcp);
    if ( ret != 0)
        goto cleanup;
    if ( server_obj->ssl ) {
        ret = uvhttp_ssl_read_session_start((uv_stream_t*)session_obj->tcp, session_data_alloc, session_data_read);
        if ( ret != 0)
            goto cleanup;
    }
    else {
        ret = uv_read_start((uv_stream_t*)session_obj->tcp, session_data_alloc, session_data_read);
        if ( ret != 0)
            goto cleanup;
    }

    if ( server_obj->session_new_callback) {
        server_obj->session_new_callback( server_obj, session_obj);
    }
cleanup:
    if ( ret != 0) {
        if ( session_obj)
            session_close( session_obj);
    }
}

static void session_data_alloc( 
    uv_handle_t* handle,
    size_t suggested_size,
    uv_buf_t* buf
    )
{
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)handle->data;
    *buf = uv_buf_init(
        session_obj->net_buffer_in,
        UVHTTP_NET_BUFFER_SIZE
        );
}


static int http_parser_on_srv_message_begin(
    http_parser* parser
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    session_reset( session_obj);
    return 0;
}

static int http_parser_on_srv_url(
    http_parser* parser,
    const char *at,
    size_t length
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    session_obj->request.uri = new_string_buffer( session_obj->request.uri, at, length);
    return 0;
}

static int http_parser_on_srv_header_field(
    http_parser* parser,
    const char *at,
    size_t length
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    if ( session_obj->temp_header_value) {
        session_obj->request.headers = uvhttp_headers_append( session_obj->request.headers, 
            session_obj->temp_header_field, session_obj->temp_header_value);
        session_obj->temp_header_field = 0;
        session_obj->temp_header_value = 0;
    }
    session_obj->temp_header_field = new_string_buffer( session_obj->temp_header_field, at, length);
    return 0;
}

static int http_parser_on_srv_header_value(
    http_parser* parser,
    const char *at,
    size_t length
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    session_obj->temp_header_value = new_string_buffer( session_obj->temp_header_value, at, length);
    return 0;
}

static int http_parser_on_srv_headers_complete(
    http_parser* parser
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    if ( session_obj->temp_header_value) {
        session_obj->request.headers = uvhttp_headers_append( session_obj->request.headers, 
            session_obj->temp_header_field, session_obj->temp_header_value);
        session_obj->temp_header_field = 0;
        session_obj->temp_header_value = 0;
    }
    session_obj->request.http_major = parser->http_major;
    session_obj->request.http_minor = parser->http_minor;
    session_obj->request.keep_alive = http_should_keep_alive(parser);
    if ( session_obj->request_callback) {
        session_obj->request_callback(
            session_obj,
            &session_obj->request
            );
    }
    return 0;
}

static int http_parser_on_srv_body(
    http_parser* parser,
    const char *at,
    size_t length
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    struct uvhttp_chunk chunk;
    chunk.base = (char*)at;
    chunk.len = length;
    session_obj->body_read_callback(
        session_obj,
        chunk
        );
    return 0;
}

static int http_parser_on_srv_message_complete(
    http_parser* parser
    )
{
    struct uvhttp_session_obj* session_obj = UVHTTP_CONTAINER_PTR( struct uvhttp_session_obj, parser, parser );
    if ( session_obj->request_end_callback) {
        session_obj->request_end_callback( UVHTTP_OK, session_obj);
    }
    session_obj->request_finished = 1;
    return 0;
}

static int http_parser_on_srv_chunk_header(
    http_parser* parser
    )
{
    return 0;
}

static int http_parser_on_srv_chunk_complete(
    http_parser* parser
    )
{
    return 0;
}

static http_parser_settings session_parser_settings = {
    http_parser_on_srv_message_begin,
    http_parser_on_srv_url,
    0,
    http_parser_on_srv_header_field,
    http_parser_on_srv_header_value,
    http_parser_on_srv_headers_complete,
    http_parser_on_srv_body,
    http_parser_on_srv_message_complete,
    http_parser_on_srv_chunk_header,
    http_parser_on_srv_chunk_complete
};

static void session_shutdown(
    uv_shutdown_t* req, 
    int status
    )
{
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)req->data;
    session_close( session_obj);
    free(req);
}

static void session_data_read(
    uv_stream_t* stream,
    ssize_t nread,
    const uv_buf_t* buf
    )
{
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)stream->data;
    size_t nparsed = 0;
	
	debug(LOG_INFO, "debug: session_data_read %d", nread);
    if ( nread > 0) {
        nparsed = http_parser_execute(&session_obj->parser, &session_parser_settings, buf->base, nread);
        if ( session_obj->parser.http_errno != 0) {
            session_obj->last_error = UVHTTP_ERROR_HTTP_PARSER;
            goto error;
        }
        if ( session_obj->parser.upgrade) {
            session_obj->last_error = UVHTTP_ERROR_HTTP_PARSER;
            goto error;
        } else if (nparsed != nread) {
            session_obj->last_error = UVHTTP_ERROR_HTTP_PARSER;
            goto error;
        }
    }
    else if ( nread == 0) {
        goto read_more;
    }
    else if( nread == UV_EOF) {
        uv_shutdown_t* req = (uv_shutdown_t*)malloc(sizeof(uv_shutdown_t));
        req->data = session_obj;
        session_obj->last_error = UVHTTP_ERROR_PEER_CLOSED;
        uv_shutdown(req, (uv_stream_t*)session_obj->tcp, session_shutdown);
        goto error;
    }
    else if (nread == UV_ECONNRESET || nread == UV_ECONNABORTED) {
        session_obj->last_error = UVHTTP_ERROR_PEER_CLOSED;
        session_close( session_obj);
        goto error;
    }
    else if (nread == UV_ENOBUFS) {
        session_obj->last_error = UVHTTP_ERROR_NO_BUFFERS;
        goto error;
    }
read_more:
    ;
    return;
error:
    session_error( session_obj);
}

static void session_error(
    struct uvhttp_session_obj* session_obj
    )
{
    if ( session_obj->request_finished == 0 && session_obj->request_end_callback) {
        if ( session_obj->last_error != UVHTTP_OK) {
            session_obj->request_end_callback(  session_obj->last_error, session_obj);
        }
        else {
            session_obj->request_end_callback(  UVHTTP_ERROR_FAILED, session_obj);
        }
        session_obj->request_finished = 1;
    }
}

static void session_closed( 
    uv_handle_t* handle
    )
{
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)handle->data;
    //如果关闭连接之前有错误导致request_end没有调用，则先通知request_end
    session_error( session_obj);
    //关闭连接回调
    if ( session_obj->end_callback) {
        session_obj->end_callback( session_obj);
    }
    //删除会话数据
    session_delete( session_obj);
}

static void session_close( 
    struct uvhttp_session_obj* session_obj
    )
{
    if ( uv_is_closing( (uv_handle_t*)session_obj->tcp) == 0) {
        //uv_read_stop( (uv_stream_t*)session_obj->tcp);
        if ( session_obj->server_obj->ssl) {
            uvhttp_ssl_session_close( (uv_handle_t*)session_obj->tcp, session_closed);
        }
        else {
            uv_close( (uv_handle_t*)session_obj->tcp, session_closed);
        }
    }
}
    
static void session_reset( 
    struct uvhttp_session_obj* session_obj
    )
{
    struct uvhttp_header* list = session_obj->request.headers;
    struct uvhttp_header* end = 0;
    struct uvhttp_header* iter = 0;

    if ( list) {
        iter = uvhttp_headers_begin( list);
        end = uvhttp_headers_end( list);

        for ( ; iter !=end ; iter = iter->next ) {
            free_string_buffer( iter->field);
            free_string_buffer( iter->value);
        }

        if ( session_obj->request.headers) {
            uvhttp_headers_free( session_obj->request.headers);
            session_obj->request.headers = 0;
        }
    }

    if ( session_obj->temp_header_field) {
        free_string_buffer( session_obj->temp_header_field);
        session_obj->temp_header_field = 0;
    }
    if ( session_obj->temp_header_value) {
        free_string_buffer( session_obj->temp_header_value);
        session_obj->temp_header_value = 0;
    }
    if ( session_obj->request.uri) {
        free_string_buffer( (char*)session_obj->request.uri);
        session_obj->request.uri = 0;
    }

    //是否已经接收完成request请求
    session_obj->request_finished = 0;
    session_obj->last_error = UVHTTP_OK;
}

static void session_delete( 
    struct uvhttp_session_obj* session_obj
    )
{
    session_reset( session_obj);
    UVHTTP_SAFE_FREE( session_obj->tcp);
    free( session_obj);
}
    
void server_delete(
    struct uvhttp_server_obj* server_obj
    )
{
    if ( server_obj->tcp) {
        UVHTTP_SAFE_FREE( server_obj->tcp);
    }
    free( server_obj);
}

void uvhttp_server_delete(
    uvhttp_server server
    )
{
    struct uvhttp_server_obj* server_obj = (struct uvhttp_server_obj*)server;
    if ( server_obj->deleted ) {
        return;
    }
    if ( server_obj->status == UVHTTP_SRV_STATUS_RUNNING ) {
        server_obj->deleted = 1;
        uvhttp_server_abort( server_obj);
    }
    else {
        server_delete( server_obj);
    }
}

int uvhttp_session_abort(
    uvhttp_session session
    )
{
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)session;
    session_close( session_obj);
    return UVHTTP_OK;
}

static void server_closed( 
    uv_handle_t* handle
    )
{
    struct uvhttp_server_obj* server = (struct uvhttp_server_obj*)handle->data;
    server->status = UVHTTP_SRV_STATUS_CLOSED;
    if ( server->end_callback) {
        server->end_callback( UVHTTP_OK, server);
    }
    if ( server->deleted) {
        server_delete( server);
    }
}

static void server_close(
    struct uvhttp_server_obj* server
    )
{
    if ( uv_is_closing( (uv_handle_t*)server->tcp) == 0){
        if ( server->ssl) {
            uvhttp_ssl_server_close( (uv_handle_t*)server->tcp, server_closed);
        }
        else {
            uv_close( (uv_handle_t*)server->tcp, server_closed);
        }
    }
}

int uvhttp_server_abort(
    uvhttp_server server
    )
{
    server_close( (struct uvhttp_server_obj*)server);
    return UVHTTP_OK;
}

static void session_write_callback(
    uv_write_t* req,
    int status
    )
{
    struct uvhttp_session_write_request* write_req = (struct uvhttp_session_write_request*)req;
    write_req->write_callback( status, write_req->session, write_req->user_data );
    free( req);
}

static int uvhttp_write(
    uv_write_t* req,
    uv_stream_t* handle,
    char* buffer,
    unsigned int buffer_len,
    uv_write_cb cb
    )
{
    uv_buf_t buf;
    buf.base = buffer;
    buf.len = buffer_len;
    return uv_write( req, handle, &buf, 1, cb);
}

int uvhttp_session_write(
    uvhttp_session session,
    struct uvhttp_chunk* buffer,
    void* user_data,
    uvhttp_session_write_callback write_callback 
    )
{
    int ret = UVHTTP_OK;
    struct uvhttp_session_obj* session_obj = (struct uvhttp_session_obj*)session;
    struct uvhttp_session_write_request* write_req = 0;
    if ( uv_is_writable( (uv_stream_t*)session_obj->tcp) == 0) {
        return UVHTTP_ERROR_FAILED;
    }
    write_req = (struct uvhttp_session_write_request*)malloc( sizeof(struct uvhttp_session_write_request));
    memset( write_req, 0, sizeof(struct uvhttp_session_write_request));
    write_req->user_data = user_data;
    write_req->session = session;
    write_req->write_callback = write_callback;
    if( !session_obj->server_obj->ssl ) {
        ret = uvhttp_write( &write_req->write_req, (uv_stream_t*)session_obj->tcp, buffer->base, buffer->len, session_write_callback);
        if ( ret != UVHTTP_OK) {
            free( write_req);
        }
    }
    else {
        ret = uvhttp_ssl_session_write( &write_req->write_req, (uv_stream_t*)session_obj->tcp, buffer->base, buffer->len, session_write_callback);
        if ( ret != UVHTTP_OK) {
            free( write_req);
        }
    }
    return ret;
}
