#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <uv.h>
#include <syslog.h>
#include "uvhttp.h"
#include "https_server.h"
#include "debug.h"

void thread_https_server(void *args) {
    uvhttp_loop loop = uvhttp_loop_new();
    if ( loop) {
        uvhttp_server server_ssl = uvhttp_server_new( loop);
        if ( server_ssl) {
            const s_config *config = config_get_config();
            uvhttp_server_set_option( server_ssl, UVHTTP_SRV_OPT_SSL, 1);
            if ( uvhttp_server_ip4_listen( server_ssl, config->gw_address, config->https_server->gw_https_port) == UVHTTP_OK) {
                debug(LOG_INFO, "https on %d success", config->https_server->gw_https_port);
            }
        }
        uvhttp_run( loop);
        uvhttp_server_delete( server_ssl);
        uvhttp_loop_delete( loop);
    }
}
