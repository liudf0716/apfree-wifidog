#ifndef UVHTTP_SERVER_INTERNAL_H__
#define UVHTTP_SERVER_INTERNAL_H__

#include <uv.h>
#include "uvhttp_internal.h"
#include "uvhttp_util.h"
#include "uvhttp_base.h"
#include "uvhttp_server.h"
#include "http_parser.h"

#if defined(__cplusplus)
extern "C" {
#endif
    
typedef enum
{
    UVHTTP_SRV_STATUS_INITED,
    UVHTTP_SRV_STATUS_RUNNING,
    UVHTTP_SRV_STATUS_CLOSED
} uvhttp_srv_status;

struct uvhttp_server_obj {
    void* user_data;
    uv_loop_t* loop;
    uv_tcp_t* tcp;
    uvhttp_server_session_new_callback session_new_callback;
    uvhttp_server_end_callback end_callback;
    unsigned char deleted:1;
    unsigned char ssl:1;
    unsigned char status:7;
} ;

struct  uvhttp_session_obj {
    void* user_data;
    uv_loop_t* loop;
    uv_tcp_t* tcp;
    uvhttp_session_request_callback request_callback;
    uvhttp_session_body_read_callback body_read_callback;
    uvhttp_session_request_end_callback request_end_callback;
    uvhttp_session_end_callback end_callback;
    struct uvhttp_server_obj* server_obj;

    struct uvhttp_message request;
    http_parser parser;
    char net_buffer_in[UVHTTP_NET_BUFFER_SIZE];
    struct uvhttp_buffer user_buffer_out;
    struct uvhttp_buffer net_buffer_out;
    char* temp_header_field;
    char* temp_header_value;
    int last_error;
    unsigned short request_finished;
};

struct uvhttp_session_write_request {
    uv_write_t write_req;
    uvhttp_session session;
    void* user_data;
    uvhttp_session_write_callback write_callback;
};

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif // UVHTTP_SERVER_INTERNAL_H__