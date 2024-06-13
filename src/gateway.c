/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free:Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
 \********************************************************************/

/** @internal
  @file gateway.c
  @brief Main loop
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@miniguru.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "gateway.h"
#include "firewall.h"
#include "commandline.h"
#include "auth.h"
#include "http.h"
#include "client_list.h"
#include "wdctl_thread.h"
#include "ping_thread.h"
#include "util.h"
#include "ssl_redir.h"
#include "mqtt_thread.h"
#include "wd_util.h"
#include "wd_client.h"
#include "dhcp_cpi.h"
#include "ws_thread.h"
#include "dns_forward.h"


struct evbuffer *evb_internet_offline_page, *evb_authserver_offline_page;
struct redir_file_buffer *wifidog_redir_html;
time_t started_time;

/** XXX Ugly hack 
 * We need to remember the thread IDs of threads that simulate wait with pthread_cond_timedwait
 * so we can explicitly kill them in the termination handler
 */
static pthread_t tid_fw_counter;
static pthread_t tid_ping;
static pthread_t tid_wdctl;
static pthread_t tid_ssl_redirect;
#ifdef _MQTT_SUPPORT_
static pthread_t tid_mqtt_server;
#endif
static pthread_t tid_ws;
static pthread_t tid_dns_forward;

static int signals[] = { SIGTERM, SIGQUIT, SIGHUP, SIGINT, SIGPIPE, SIGCHLD, SIGUSR1 };
static struct event *sev[sizeof(signals)/sizeof(int)];

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
static void *
wd_zeroing_malloc(size_t howmuch) {
	return calloc(1, howmuch);
}
#endif

static void 
openssl_init(void)
{ 
    if (!RAND_poll()) return;

#if (OPENSSL_VERSION_NUMBER < 0x10100000L) || \
	(defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER < 0x20700000L)
	// Initialize OpenSSL
    CRYPTO_set_mem_functions (wd_zeroing_malloc, realloc, free);
	SSL_library_init();
	ERR_load_crypto_strings();
	SSL_load_error_strings();
	OpenSSL_add_all_algorithms();
	debug (LOG_DEBUG, "Using OpenSSL version \"%s\"\nand libevent version \"%s\"\n",
		  SSLeay_version (SSLEAY_VERSION),
		  event_get_version ());
#else
	debug (LOG_DEBUG, "Using OpenSSL version \"%s\"\nand libevent version \"%s\"\n",
		  OpenSSL_version (OPENSSL_VERSION),
		  event_get_version ());
#endif
}

static void
wd_msg_init()
{
	s_config *config = config_get_config();	
	
	evb_internet_offline_page 	= evbuffer_new();
	evb_authserver_offline_page	= evbuffer_new();
	if (!evb_internet_offline_page || !evb_authserver_offline_page)
		exit(EXIT_FAILURE);
	
	if ( !ev_http_read_html_file(config->internet_offline_file, evb_internet_offline_page) || 
		 !ev_http_read_html_file(config->authserver_offline_file, evb_authserver_offline_page)) {
		debug(LOG_ERR, "wd_msg_init failed, exiting...");
		exit(EXIT_FAILURE);
	}
}

static void
wd_redir_file_init(void)
{
	s_config *config = config_get_config();
	char	front_file[128] = {0};
	char	rear_file[128] = {0};
	
	
	wifidog_redir_html = (struct redir_file_buffer *)safe_malloc(sizeof(struct redir_file_buffer));
	
	struct evbuffer *evb_front 	= evbuffer_new();
	struct evbuffer *evb_rear	= evbuffer_new();
	if (evb_front == NULL || evb_rear == NULL)  {
		exit(EXIT_FAILURE);
	}
	
	snprintf(front_file, 128, "%s.front", config->htmlredirfile);
	snprintf(rear_file, 128, "%s.rear", config->htmlredirfile);
	if (!ev_http_read_html_file(front_file, evb_front) || 
		!ev_http_read_html_file(rear_file, evb_rear)) {
		exit(EXIT_FAILURE);
	}
	
	int len = 0;
	wifidog_redir_html->front 		= evb_2_string(evb_front, &len);
	wifidog_redir_html->front_len	= len;
	wifidog_redir_html->rear		= evb_2_string(evb_rear, &len);
	wifidog_redir_html->rear_len	= len;
	
	if (evb_front) evbuffer_free(evb_front);	
	if (evb_rear) evbuffer_free(evb_rear);
}

/* Appends -x, the current PID, and NULL to restartargv
 * see parse_commandline in commandline.c for details
 *
 * Why is restartargv global? Shouldn't it be at most static to commandline.c
 * and this function static there? -Alex @ 8oct2006
 */
void
append_x_restartargv(void)
{
	int i;
    for (i = 0; restartargv[i]; i++) ;

    restartargv[i++] = safe_strdup("-x");
    safe_asprintf(&(restartargv[i++]), "%d", getpid());
}

/**@internal
 * @brief Handles SIGCHLD signals to avoid zombie processes
 *
 * When a child process exits, it causes a SIGCHLD to be sent to the
 * process. This handler catches it and reaps the child process so it
 * can exit. Otherwise we'd get zombie processes.
 */
void
sigchld_handler(int s)
{
    int status;
    pid_t rc;

    debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");
	do {
    	rc = waitpid(-1, &status, WNOHANG);
	} while(rc != (pid_t)0 && rc != (pid_t)-1);
}

/** Exits cleanly after cleaning up the firewall.  
 *  Use this function anytime you need to exit after firewall initialization.
 *  @param s Integer that is really a boolean, true means voluntary exit, 0 means error.
 */
void
termination_handler(int s)
{
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t self = pthread_self();

    debug(LOG_INFO, "Handler for termination caught signal %d", s);

    /* Makes sure we only call fw_destroy() once. */
    if (pthread_mutex_trylock(&sigterm_mutex)) {
        debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
        pthread_exit(NULL);
    } 

    debug(LOG_INFO, "Flushing firewall rules...");
    fw_destroy();

    /* XXX Hack
     * Aparently pthread_cond_timedwait under openwrt prevents signals (and therefore
     * termination handler) from happening so we need to explicitly kill the threads 
     * that use that
     */
    if (tid_fw_counter && self != tid_fw_counter) {
        debug(LOG_INFO, "Explicitly killing the fw_counter thread");
        pthread_kill(tid_fw_counter, SIGKILL);
    }
    if (tid_ping && self != tid_ping) {
        debug(LOG_INFO, "Explicitly killing the ping thread");
        pthread_kill(tid_ping, SIGKILL);
    }
	if (tid_wdctl && self != tid_wdctl) {
        debug(LOG_INFO, "Explicitly killing the wdctl thread");
		pthread_kill(tid_wdctl, SIGKILL);
	}
	if (tid_ssl_redirect && self != tid_ssl_redirect) {
		debug(LOG_INFO, "Explicitly killing the https_server thread");
		pthread_kill(tid_ssl_redirect, SIGKILL);
	}
#ifdef _MQTT_SUPPORT_
    if (tid_mqtt_server && self != tid_mqtt_server) {
        debug(LOG_INFO, "Explicitly killing the mqtt_server thread");
        pthread_kill(tid_mqtt_server, SIGKILL);
    }
#endif
    if (tid_ws && self != tid_ws) {
        debug(LOG_INFO, "Explicitly killing the websocket thread");
        pthread_kill(tid_ws, SIGKILL);
    }
    if (tid_dns_forward && self != tid_dns_forward) {
        debug(LOG_INFO, "Explicitly killing the dns_forward thread");
        pthread_kill(tid_dns_forward, SIGKILL);
    }
    debug(LOG_NOTICE, "Exiting...");
    exit(s == 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}

/*
 * Signal handler for SIGTERM, SIGQUIT, SIGINT, SIGHUP, SIGPIPE and SIGUSR1.
 */
static void
wd_signal_cb(evutil_socket_t fd, short what, void *arg)
{
	struct event_base *evbase = arg;
	
	switch(fd) {
	case SIGTERM:
	case SIGQUIT:
	case SIGINT:
	case SIGHUP:
		event_base_loopbreak(evbase);
		termination_handler(1);
		break;
	case SIGCHLD:
		sigchld_handler(0);
		break;
	case SIGUSR1:
		debug(LOG_INFO, "Received SIGUSER1; ignore.");
		break;
	case SIGPIPE:
		debug(LOG_INFO, "Warning: Received SIGPIPE; ignoring.\n");
		break;
	default:
		debug(LOG_INFO, "Warning: Received unexpected signal %i\n", fd);
		break;
	}
}

static void
wd_signals_init(struct event_base *evbase)
{
	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++) {
		sev[i] = evsignal_new(evbase, signals[i], wd_signal_cb, evbase);
		if (sev[i])
			evsignal_add(sev[i], NULL);
	}
}


/**
 * @brief wifidog init
 */
static void
wd_init(s_config *config)
{
    // read wifidog msg file to memory
    wd_msg_init();    
    wd_redir_file_init();
    openssl_init();              /* Initialize OpenSSL */
	
    /* Set the time when wifidog started */
    if (!started_time) {
        started_time = time(NULL);
    } else if (started_time < MINIMUM_STARTED_TIME) {
        started_time = time(NULL);
    }  

    /* save the pid file if needed */
    if (config->pidfile)
        save_pid_file(config->pidfile);

    /* If we don't have the Gateway IP address, get it. Can't fail. */
    if (!config->gw_address) {
        if ((config->gw_address = get_iface_ip(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get IP address information of %s, exiting...", config->gw_interface);
            exit(EXIT_FAILURE);
        }
        
    }
    
    /* If we don't have the Gateway ID, construct it from the internal MAC address.
     * "Can't fail" so exit() if the impossible happens. */
    if (!config->gw_id) {
        if ((config->gw_id = get_iface_mac(config->gw_interface)) == NULL) {
            debug(LOG_ERR, "Could not get MAC address information of %s, exiting...", config->gw_interface);
            exit(EXIT_FAILURE);
        }
    } 

    debug(LOG_DEBUG, "gw_id [%s] %s = %s ", 
        config->gw_id, config->gw_interface, config->gw_address);

    /*
     * If needed, increase rlimits to allow as many connections
     * as needed.
     */
    struct rlimit rlim;
    memset(&rlim, 0, sizeof(struct rlimit));
    if (getrlimit(RLIMIT_NOFILE, &rlim) != 0) {
        debug(LOG_ERR, "Failed to getrlimit number of files");
        exit(EXIT_FAILURE);
    } else {
        rlim.rlim_cur = 1024*1024;
        rlim.rlim_max = 1024*1024;
        if (setrlimit(RLIMIT_NOFILE, &rlim) != 0) {
            debug(LOG_ERR, "Failed to set rlimit for open files. Try starting as root or requesting smaller maxconns value.");
            exit(EXIT_FAILURE);
        }
    }

     /* Reset the firewall (if WiFiDog crashed) */
    fw_destroy();
    /* Then initialize it */
    if (!fw_init()) {
        debug(LOG_ERR, "FATAL: Failed to initialize firewall");
        exit(EXIT_FAILURE);
    }
}

static void
threads_init(s_config *config)
{
    int result;

    // add ssl redirect server    
    result = pthread_create(&tid_ssl_redirect, NULL, (void *)thread_ssl_redirect, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (https_server) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_ssl_redirect);

    /* Start heartbeat thread */
    result = pthread_create(&tid_ping, NULL, (void *)thread_ping, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (ping) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_ping);
    

    /* Start client clean up thread */
    result = pthread_create(&tid_fw_counter, NULL, (void *)thread_client_timeout_check, NULL);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (fw_counter) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_fw_counter);

    if (config->enable_dhcp_cpi) {
        result = pthread_create(&tid_fw_counter, NULL, (void *)thread_dhcp_cpi, NULL);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (dhcp_cpi) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid_fw_counter);
    }

#ifdef	_MQTT_SUPPORT_
    // start mqtt subscript thread
    result = pthread_create(&tid_mqtt_server, NULL, (void *)thread_mqtt, config);
    if (result != 0) {
        debug(LOG_INFO, "Failed to create a new thread (thread_mqtt)");
    }
    pthread_detach(tid_mqtt_server);
#endif
	
	 /* Start control thread */
    result = pthread_create(&tid_wdctl, NULL, (void *)thread_wdctl, (void *)safe_strdup(config->wdctl_sock));
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create a new thread (wdctl) - exiting");
        termination_handler(0);
    }
    pthread_detach(tid_wdctl);

    if (config->enable_ws) {
        result = pthread_create(&tid_ws, NULL, (void *)start_ws_thread, NULL);
        if (result != 0) {
            debug(LOG_INFO, "Failed to create a new thread (ws)");
            termination_handler(0);
        }
        pthread_detach(tid_ws);
    }

    if (config->enable_dns_forward) {
        result = pthread_create(&tid_dns_forward, NULL, (void *)dns_forward_thread, NULL);
        if (result != 0) {
            debug(LOG_ERR, "FATAL: Failed to create a new thread (dns_forward) - exiting");
            termination_handler(0);
        }
        pthread_detach(tid_dns_forward);
    }
}

static void
wd_debug_base(const struct event_base *ev_base)
{
	debug(LOG_DEBUG, "Using libevent backend '%s'\n",
	               event_base_get_method(ev_base));

	enum event_method_feature f;
	f = event_base_get_features(ev_base);
	debug(LOG_DEBUG, "Event base supports: edge %s, O(1) %s, anyfd %s\n",
	               ((f & EV_FEATURE_ET) ? "yes" : "no"),
	               ((f & EV_FEATURE_O1) ? "yes" : "no"),
	               ((f & EV_FEATURE_FDS) ? "yes" : "no"));
}

static void
http_redir_loop(s_config *config)
{
    struct event_base *base;
	struct evhttp *http;

    SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) termination_handler(0);

    SSL *ssl = SSL_new(ssl_ctx);
	if (!ssl) termination_handler(0);

    base = event_base_new();
    if (!base) termination_handler(0);

    wd_debug_base(base);

    http = evhttp_new(base);
    if (!http) termination_handler(0);

	evhttp_set_allowed_methods(http,
            EVHTTP_REQ_GET |
            EVHTTP_REQ_POST |
            EVHTTP_REQ_OPTIONS);
	
	struct wd_request_context *request_ctx = wd_request_context_new(
        base, ssl, get_auth_server()->authserv_use_ssl);
	if (!request_ctx) termination_handler(0);
	
	wd_signals_init(base);
	
    evhttp_set_cb(http, "/wifidog", ev_http_callback_wifidog, NULL);
    //evhttp_set_cb(http, "/wifidog/status", ev_http_callback_status, NULL);
    evhttp_set_cb(http, "/wifidog/auth", ev_http_callback_auth, request_ctx);
    //evhttp_set_cb(http, "/wifidog/disconnect", ev_http_callback_disconnect, request_ctx);
    evhttp_set_cb(http, "/wifidog/temporary_pass", ev_http_callback_temporary_pass, NULL);

    evhttp_set_gencb(http, ev_http_callback_404, NULL);

    evhttp_bind_socket_with_handle(http, config->gw_address, config->gw_port);

    event_base_dispatch(base);
}

/**@internal
 * Main execution loop 
 */
static void
main_loop(void)
{
    s_config *config = config_get_config();
	
    wd_init(config);
	threads_init(config);

    http_redir_loop(config);
}

/** Reads the configuration file and then starts the main loop */
int
gw_main(int argc, char **argv)
{
    config_init();

    parse_commandline(argc, argv);

    /* Initialize the config */
    config_read();
    config_validate();

    /* Initializes the linked list of connected clients */
    client_list_init();

    if (config_get_config()->daemon) {
        debug(LOG_INFO, "Forking into background");

        switch (safe_fork()) {
        case 0:                /* child */
            setsid();
            append_x_restartargv();
            main_loop();
            break;

        default:               /* parent */
            exit(0);
            break;
        }
    } else {
        append_x_restartargv();
        main_loop();
    }

    return (0);                 /* never reached */
}
