#ifndef UVHTTP_SERVER_H__
#define UVHTTP_SERVER_H__
#include "uvhttp_util.h"
#include "uvhttp_base.h"

#if defined(__cplusplus)
extern "C" {
#endif

typedef void* uvhttp_server;
typedef void* uvhttp_session;

typedef enum {
    UVHTTP_SRV_OPT_USER_DATA,
    UVHTTP_SRV_OPT_SSL,
    UVHTTP_SRV_OPT_SESSION_NEW_CB,
    UVHTTP_SRV_OPT_END_CB
} uvhttp_server_option;

typedef enum {
    UVHTTP_SESSION_OPT_USER_DATA,
    UVHTTP_SESSION_OPT_REQUEST_CB,
    UVHTTP_SESSION_OPT_REQUEST_BODY_CB,
    UVHTTP_SESSION_OPT_REQUEST_END_CB,
    UVHTTP_SESSION_OPT_END_CB
} uvhttp_session_option;

typedef enum {
    UVHTTP_SRV_INFO_USER_DATA,
    UVHTTP_SRV_INFO_UVTCP,
    UVHTTP_SRV_INFO_LOOP
} uvhttp_server_info;

typedef enum {
    UVHTTP_SESSION_INFO_USER_DATA,
    UVHTTP_SESSION_INFO_UVTCP,
    UVHTTP_SESSION_INFO_LOOP,
    UVHTTP_SESSION_INFO_MESSAGE
} uvhttp_session_info;

typedef void (*uvhttp_server_session_new_callback)(
    uvhttp_server server,
    uvhttp_session session
    );

typedef void (*uvhttp_session_request_callback)(
    uvhttp_session session,
    struct uvhttp_message* request
    );

typedef void (*uvhttp_session_body_read_callback)(
    uvhttp_session session,
    struct uvhttp_chunk data
    );
    
typedef void (*uvhttp_session_request_end_callback)(
    int status,
    uvhttp_session session
    );

typedef void (*uvhttp_session_end_callback)(
    uvhttp_session session
    );

typedef void (*uvhttp_session_write_callback)(
    int status,
    uvhttp_session session,
    void* user_data
    );

typedef void (*uvhttp_server_end_callback)(
    int status,
    uvhttp_server server
    );

int uvhttp_session_set_option( 
    uvhttp_session session,
    uvhttp_session_option option,
    ...
    );

int uvhttp_session_get_info( 
    uvhttp_session session,
    uvhttp_session_info info,
    ...
    );

int uvhttp_session_write(
    uvhttp_session session,
    struct uvhttp_chunk* buffer,
    void* user_data,
    uvhttp_session_write_callback write_callback 
    );

	//需要修改为调用uv_shutdown
int uvhttp_session_abort(
    uvhttp_session session
    );

int uvhttp_server_set_option( 
    uvhttp_server server,
    uvhttp_server_option option,
    ...
    );

int uvhttp_server_get_info( 
    uvhttp_server server,
    uvhttp_server_info info,
    ...
    );

uvhttp_server uvhttp_server_new(
    uvhttp_loop loop
    );

int uvhttp_server_ip4_listen(
    uvhttp_server server,
    const char* ip,
    int port
    );

void uvhttp_server_delete(
    uvhttp_server server
    );

int uvhttp_server_abort(
    uvhttp_server server
    );

#if defined(__cplusplus)
}
#endif /* __cplusplus */
#endif // UVHTTP_SERVER_H__
