#ifndef uvhttp_base_h__
#define uvhttp_base_h__
#include "uvhttp_util.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef void* uvhttp_loop;

typedef enum {
    UVHTTP_OK = 0,
    UVHTTP_ERROR_FAILED = -1,
    UVHTTP_ERROR_NOOPTIONS = -2,
    UVHTTP_ERROR_PARAMS_INVALID = -3,
    UVHTTP_ERROR_HTTP_PARSER = -4,
    UVHTTP_ERROR_PEER_CLOSED = -5,
    UVHTTP_ERROR_NO_BUFFERS = -6,
    UVHTTP_ERROR_WRITE_WAIT = -7,
    UVHTTP_ERROR_URL_PARSE = -8,
    UVHTTP_ERROR_HOSTNAME_TOOLONG = -9,
    UVHTTP_ERROR_REQUEST_NOTEND = -10
} uvhttp_error_code;

struct uvhttp_header {
    char* field;
    char* value;
    struct uvhttp_header* next;
};

typedef enum {
    UVHTTP_METHOD_DELETE,
    UVHTTP_METHOD_GET,
    UVHTTP_METHOD_HEAD,
    UVHTTP_METHOD_POST,
    UVHTTP_METHOD_PUT,
    UVHTTP_METHOD_CONNECT,
    UVHTTP_METHOD_OPTIONS,
    UVHTTP_METHOD_TRACE,
    UVHTTP_METHOD_COPY,
    UVHTTP_METHOD_LOCK,
    UVHTTP_METHOD_MKCOL,
    UVHTTP_METHOD_MOVE,
    UVHTTP_METHOD_PROPFIND,
    UVHTTP_METHOD_PROPPATCH,
    UVHTTP_METHOD_SEARCH,
    UVHTTP_METHOD_UNLOCK,
    UVHTTP_METHOD_BIND,
    UVHTTP_METHOD_REBIND,
    UVHTTP_METHOD_UNBIND,
    UVHTTP_METHOD_ACL,
    UVHTTP_METHOD_REPORT,
    UVHTTP_METHOD_MKACTIVITY,
    UVHTTP_METHOD_CHECKOUT,
    UVHTTP_METHOD_MERGE,
    UVHTTP_METHOD_MSEARCH,
    UVHTTP_METHOD_NOTIFY,
    UVHTTP_METHOD_SUBSCRIBE,
    UVHTTP_METHOD_UNSUBSCRIBE,
    UVHTTP_METHOD_PATCH,
    UVHTTP_METHOD_PURGE,
    UVHTTP_METHOD_MKCALENDAR,
    UVHTTP_METHOD_LINK,
    UVHTTP_METHOD_UNLINK
} uvhttp_method;

struct uvhttp_message {
    unsigned long long content_length;
    unsigned short http_major;
    unsigned short http_minor;
    unsigned char status_code;
    unsigned char method;
    unsigned char keep_alive;
    const char* resp_status;
    const char* uri;
    struct uvhttp_header* headers;
};

const char* uvhttp_error_description(
    int error_no
    );

uvhttp_loop uvhttp_loop_new( );

void uvhttp_loop_delete( 
    uvhttp_loop loop
    );

int uvhttp_run( 
    uvhttp_loop loop
    );

void uvhttp_stop(
    uvhttp_loop loop
    );

struct uvhttp_header* uvhttp_headers_begin( 
    struct uvhttp_header* headers
    );

struct uvhttp_header* uvhttp_headers_end( 
    struct uvhttp_header* headers
    );

int uvhttp_headers_size(
    struct uvhttp_header* headers
    );

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif // uvhttp_base_h__