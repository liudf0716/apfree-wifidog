
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
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
#include "wdctlx_thread.h"
#include "ping_thread.h"
#include "util.h"
#include "tls_thread.h"
#include "mqtt_thread.h"
#include "wd_util.h"
#include "wd_client.h"
#include "ws_thread.h"
#include "dns_monitor.h"
#include "client_snapshot.h"

/* Global mutexes and buffers */
pthread_mutex_t g_resource_lock = PTHREAD_MUTEX_INITIALIZER;
struct evbuffer *evb_internet_offline_page = NULL;
struct evbuffer *evb_authserver_offline_page = NULL;
redir_file_buffer_t *wifidog_redir_html = NULL;
time_t started_time = 0;
static struct wd_request_context *s_auth_request_ctx = NULL;

/* Thread identifiers for various services */
static pthread_t tid_fw_counter = 0;    /* Firewall counter thread */
static pthread_t tid_ping = 0;          /* Ping thread */
static pthread_t tid_wdctl = 0;         /* Control interface thread */
static pthread_t tid_tls_server = 0;   /* TLS redirect thread */
static pthread_t tid_mqtt_server = 0;    /* MQTT server thread */
static pthread_t tid_ws = 0;            /* WebSocket thread */
static pthread_t tid_dns_monitor = 0;    /* DNS monitor thread */
static pthread_t tid_resilience = 0;     /* Firewall resilience thread */

/* Signal handling */
static const int signals[] = { 
    SIGTERM,    /* Termination */
    SIGQUIT,    /* Quit */
    SIGHUP,     /* Hangup */
    SIGINT,     /* Interrupt */
    SIGPIPE,    /* Broken pipe */
    SIGCHLD,    /* Child status changed */
    SIGUSR1     /* User-defined signal 1 */
};
static struct event *sev[sizeof(signals)/sizeof(int)];


/**
 * @brief This is the start of a static function definition in the gateway source file
 * 
 * Note: Without seeing the full function signature and implementation, 
 * a more detailed description cannot be provided.
 */
static void 
openssl_init(void)
{ 
    if (!RAND_poll()) {
        debug(LOG_ERR, "Could not seed the PRNG");
        exit(EXIT_FAILURE);
    }

    debug(LOG_DEBUG, "Using OpenSSL version \"%s\"\n"
                    "and libevent version \"%s\"",
          OpenSSL_version(OPENSSL_VERSION),
          event_get_version());
}

/**
 * @brief Gateway function that will be defined (static scope)
 * 
 * This function represents a static gateway operation.
 * The specific implementation details and parameters should be defined
 * in the function body.
 * 
 * @note This is a static function and can only be used within the same file
 */
static void
wd_msg_init(void)
{
    s_config *config = config_get_config();

    // Create evbuffers
    evb_internet_offline_page = evbuffer_new();
    evb_authserver_offline_page = evbuffer_new();
    
    // Check evbuffer creation
    if (!evb_internet_offline_page || !evb_authserver_offline_page) {
        debug(LOG_ERR, "Failed to create evbuffers");
        goto cleanup;
    }

    // Read offline message files
    if (!ev_http_read_html_file(config->internet_offline_file, evb_internet_offline_page)) {
        debug(LOG_ERR, "Failed to read internet offline file");
        goto cleanup;
    }

    if (!ev_http_read_html_file(config->authserver_offline_file, evb_authserver_offline_page)) {
        debug(LOG_ERR, "Failed to read auth server offline file");
        goto cleanup;
    }

    return;

cleanup:
    if (evb_internet_offline_page) {
        evbuffer_free(evb_internet_offline_page);
        evb_internet_offline_page = NULL;
    }
    if (evb_authserver_offline_page) {
        evbuffer_free(evb_authserver_offline_page);
        evb_authserver_offline_page = NULL;
    }
    debug(LOG_ERR, "Failed to initialize message system");
    exit(EXIT_FAILURE);
}

/**
 * @brief This function is static and void, indicating it's a private helper function
 *        with no return value. Additional context about the function's purpose and
 *        parameters would be needed for more specific documentation.
 * 
 * @return void
 */
static void
wd_redir_file_init(void)
{
    s_config *config = config_get_config();
    struct evbuffer *evb_front = NULL;
    struct evbuffer *evb_rear = NULL;
    char front_file[128] = {0};
    char rear_file[128] = {0};

    // Initialize redirect HTML buffer
    wifidog_redir_html = safe_malloc(sizeof(redir_file_buffer_t));
    if (!wifidog_redir_html) {
        debug(LOG_ERR, "Failed to allocate memory for redirect HTML buffer");
        goto cleanup;
    }

    // Create evbuffers
    evb_front = evbuffer_new();
    evb_rear = evbuffer_new();
    if (!evb_front || !evb_rear) {
        debug(LOG_ERR, "Failed to create evbuffers");
        goto cleanup;
    }

    // Generate file paths
    if (snprintf(front_file, sizeof(front_file), "%s.front", config->htmlredirfile) < 0 ||
        snprintf(rear_file, sizeof(rear_file), "%s.rear", config->htmlredirfile) < 0) {
        debug(LOG_ERR, "Failed to generate file paths");
        goto cleanup;
    }

    // Read HTML files
    if (!ev_http_read_html_file(front_file, evb_front) || 
        !ev_http_read_html_file(rear_file, evb_rear)) {
        debug(LOG_ERR, "Failed to read HTML files");
        goto cleanup;
    }

    // Convert evbuffers to strings and store lengths
    int len = 0;
    wifidog_redir_html->front = evb_2_string(evb_front, &len);
    wifidog_redir_html->front_len = len;
    wifidog_redir_html->rear = evb_2_string(evb_rear, &len);
    wifidog_redir_html->rear_len = len;

    if (!wifidog_redir_html->front || !wifidog_redir_html->rear) {
        debug(LOG_ERR, "Failed to convert evbuffers to strings");
        goto cleanup;
    }

    // Normal cleanup
    evbuffer_free(evb_front);
    evbuffer_free(evb_rear);
    return;

cleanup:
    // Error cleanup
    if (evb_front) evbuffer_free(evb_front);
    if (evb_rear) evbuffer_free(evb_rear);
    if (wifidog_redir_html) {
        free(wifidog_redir_html->front);
        free(wifidog_redir_html->rear);
        free(wifidog_redir_html);
    }
    exit(EXIT_FAILURE);
}


/**
 * @brief Appends process restart arguments to the restart argument array
 * 
 * This function adds two arguments to the restartargv array:
 * 1. The "-x" flag
 * 2. The current process ID as a string
 * 
 * These arguments are used when the process needs to be restarted
 * while maintaining state information.
 */
void
append_x_restartargv(void)
{
    int i;
    // Find the end of the existing arguments
    for (i = 0; restartargv[i]; i++);

    // Append "-x" flag
    restartargv[i++] = safe_strdup("-x");
    
    // Append current process ID
    safe_asprintf(&(restartargv[i++]), "%d", getpid());
}

/**
 * @brief Handler for SIGCHLD signals to reap zombie child processes
 * 
 * This function is called when a child process terminates. It performs
 * non-blocking waits to collect the exit status of any terminated
 * child processes, preventing them from becoming zombies.
 * 
 * @param s Signal number (unused but required by signal handler signature)
 */
void
sigchld_handler(int s)
{
    pid_t rc;
    int status;

    debug(LOG_DEBUG, "Handler for SIGCHLD called. Trying to reap a child");

    // Keep reaping children until there are no more to reap
    do {
        rc = waitpid(-1, &status, WNOHANG);
    } while (rc > 0);
}

/* Thread termination information */
static const struct {
    pthread_t *tid;
    const char *name;
} cleanup_threads[] = {
    {&tid_fw_counter, "fw_counter"},
    {&tid_ping, "ping"},
    {&tid_wdctl, "wdctl"},
    {&tid_tls_server, "https_server"},
    {&tid_mqtt_server, "mqtt_server"},
    {&tid_ws, "websocket"},
    {&tid_dns_monitor, "dns_monitor"},
    {&tid_resilience, "resilience"}
};

/**
 * @brief Safely terminates all service threads
 * 
 * @param self Current thread ID to avoid self-termination
 */
static void 
terminate_threads(pthread_t self) {
    for (size_t i = 0; i < sizeof(cleanup_threads)/sizeof(cleanup_threads[0]); i++) {
        if (*cleanup_threads[i].tid && !pthread_equal(self, *cleanup_threads[i].tid)) {
            debug(LOG_INFO, "Explicitly killing the %s thread", cleanup_threads[i].name);
            
            // First try graceful termination
            int result = pthread_cancel(*cleanup_threads[i].tid);
            if (result != 0) {
                debug(LOG_WARNING, "Failed to cancel thread %s: %s", 
                      cleanup_threads[i].name, strerror(result));
            }
            
            // Give thread time to cleanup
            struct timespec timeout = {0, 100000000}; // 100ms
            nanosleep(&timeout, NULL);
            
            // Force kill if still running (last resort)
            pthread_kill(*cleanup_threads[i].tid, SIGKILL);
        }
    }
}

/**
 * @brief Handles process termination signals with proper cleanup
 * 
 * @param s Signal number that triggered termination
 */
void 
termination_handler(int s) {
    static pthread_mutex_t sigterm_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_t self = pthread_self();

    debug(LOG_INFO, "Handler for termination caught signal %d", s);

    /* Ensure cleanup only happens once */
    if (pthread_mutex_trylock(&sigterm_mutex) != 0) {
        debug(LOG_INFO, "Another thread already began global termination handler. I'm exiting");
        pthread_exit(NULL);
        return; // This won't be reached but good for clarity
    }

    /* Cleanup firewall rules */
    debug(LOG_INFO, "Flushing firewall rules...");
    
    /* Save client snapshot before exit */
    client_snapshot_save();

    fw_destroy();

    /* Stop DNS monitor */
    dns_monitor_stop();

    /* Clean up threads */
    terminate_threads(self);

    debug(LOG_NOTICE, "Exiting...");
    
    // Unlock mutex before exit (good practice even though process is ending)
    pthread_mutex_unlock(&sigterm_mutex);
    
    exit(s == 0 ? EXIT_FAILURE : EXIT_SUCCESS);
}


/**
 * @brief The prefix "static void" indicates this is a private function within the source file
 * that doesn't return a value.
 * 
 * @note This function is declared in gateway.c which appears to handle gateway-related
 * functionality for the wifidogx/apfree-wifidog project.
 */
static void
handle_termination(struct event_base *evbase)
{
    debug(LOG_INFO, "Received termination signal; exiting...");
    event_base_loopbreak(evbase);
    termination_handler(1);
}

static void
handle_child(struct event_base *evbase)
{
    sigchld_handler(0);
}

static void
handle_usr1(struct event_base *evbase) 
{
    debug(LOG_ERR, "Received SIGUSR1; reload fw.");
    fw_destroy();
    restart_orig_pid = 1;
    fw_init();
    restart_orig_pid = 0;
}

static void
handle_pipe(struct event_base *evbase)
{
    debug(LOG_WARNING, "Received SIGPIPE: Client disconnected while writing data. This is usually harmless.");
}

static void
handle_hup(struct event_base *evbase)
{
    debug(LOG_INFO, "Received SIGHUP; ignoring...");
}

/**
 * @brief Creates a static function definition
 * 
 * This section is meant to be completed with a function name and parameters.
 * Static functions in C have internal linkage and are only visible within
 * the source file where they are defined.
 */
static void
wd_signal_cb(evutil_socket_t fd, short what, void *arg)
{
    struct event_base *evbase = arg;

    // Common signal handling
    static const struct {
        int signal;
        void (*handler)(struct event_base *);
    } signal_handlers[] = {
        {SIGTERM, handle_termination},
        {SIGQUIT, handle_termination},
        {SIGINT,  handle_termination},
        {SIGHUP,  handle_hup},
        {SIGCHLD, handle_child},
        {SIGUSR1, handle_usr1},
        {SIGPIPE, handle_pipe}
    };

    // Find and execute appropriate handler
    for (size_t i = 0; i < sizeof(signal_handlers)/sizeof(signal_handlers[0]); i++) {
        if (fd == signal_handlers[i].signal) {
            signal_handlers[i].handler(evbase);
            return;
        }
    }

    debug(LOG_INFO, "Warning: Received unexpected signal %i\n", fd);
}

/**
 * @brief Initializes signal handlers for the event base
 *
 * @param evbase Event base for signal handling
 */
static void
wd_signals_init(struct event_base *evbase)
{
    if (!evbase) {
        debug(LOG_ERR, "Invalid event base for signal initialization");
        return;
    }
    
	for (size_t i = 0; i < (sizeof(signals) / sizeof(int)); i++) {
		sev[i] = evsignal_new(evbase, signals[i], wd_signal_cb, evbase);
		if (sev[i]) {
		    if (evsignal_add(sev[i], NULL) != 0) {
		        debug(LOG_WARNING, "Failed to add signal handler for signal %d", signals[i]);
		        event_free(sev[i]);
		        sev[i] = NULL;
		    }
		} else {
		    debug(LOG_WARNING, "Failed to create signal event for signal %d", signals[i]);
		}
	}
}

/**
 * @brief Initialize gateway settings for network interfaces
 * 
 * This function initializes the settings for each configured gateway interface:
 * - Validates required interface and channel settings
 * - Retrieves IPv4 address if not configured
 * - Retrieves IPv6 address if not configured
 * - Retrieves MAC address if gateway ID not configured
 * 
 * The function exits with failure if critical settings cannot be initialized.
 */
static void
gateway_setting_init(void)
{
    t_gateway_setting *gateway_settings = get_gateway_settings();
    
    while (gateway_settings) {
        // Validate required settings
        if (!gateway_settings->gw_interface || !gateway_settings->gw_channel) {
            debug(LOG_ERR, "Gateway settings are not complete");
            exit(EXIT_FAILURE);
        }

        debug(LOG_DEBUG, "Initializing gateway interface '%s' on channel '%s'", 
              gateway_settings->gw_interface, gateway_settings->gw_channel);

        // Get IPv4 address if not configured
        if (!gateway_settings->gw_address_v4) {
            gateway_settings->gw_address_v4 = get_iface_ip(gateway_settings->gw_interface);
            if (!gateway_settings->gw_address_v4) {
                debug(LOG_ERR, "Could not get IPv4 address for interface %s", 
                      gateway_settings->gw_interface);
                exit(EXIT_FAILURE);
            }
        }

        // Get IPv6 address if not configured
        if (!gateway_settings->gw_address_v6) {
            gateway_settings->gw_address_v6 = get_iface_ip6(gateway_settings->gw_interface);
            if (!gateway_settings->gw_address_v6) {
                debug(LOG_ERR, "Could not get IPv6 address for interface %s", 
                      gateway_settings->gw_interface);
            }
        }

        // Get MAC address for gateway ID if not configured
        if (!gateway_settings->gw_id) {
            gateway_settings->gw_id = get_iface_mac(gateway_settings->gw_interface);
            if (!gateway_settings->gw_id) {
                debug(LOG_ERR, "Could not get MAC address for interface %s", 
                      gateway_settings->gw_interface);
                exit(EXIT_FAILURE);
            }
        }

        debug(LOG_DEBUG, "Gateway [ID: %s] IPv4: %s IPv6: %s", 
              gateway_settings->gw_id,
              gateway_settings->gw_address_v4,
              gateway_settings->gw_address_v6 ? gateway_settings->gw_address_v6 : "none");

        gateway_settings = gateway_settings->next;
    }
}

/**
 * @brief Initializes system resource limits for file descriptors
 * 
 * Sets both soft and hard limits for number of open file descriptors
 * to support high concurrent connections. Validates current limits
 * and sets reasonable maximums based on system capabilities.
 * 
 * @note Requires root privileges to increase limits beyond system defaults
 * 
 * @throws Exits with failure if unable to get or set resource limits
 */
static void 
init_resource_limits(void)
{
    struct rlimit file_limits;

    // Get current file descriptor limits
    if (getrlimit(RLIMIT_NOFILE, &file_limits) != 0) {
        debug(LOG_ERR, "Failed to get file descriptor limits: %s", strerror(errno));
        exit(EXIT_FAILURE);
    }
    
    debug(LOG_DEBUG, "Current file descriptor limits: soft=%ld hard=%ld", 
          (long)file_limits.rlim_cur, (long)file_limits.rlim_max);
    
    // Calculate reasonable limit based on system max or a safe default
    rlim_t target_limit = file_limits.rlim_max;
    const rlim_t DEFAULT_MAX_FD = 65536;  // 64K file descriptors (reasonable default)
    const rlim_t ABSOLUTE_MAX_FD = 1024 * 1024;  // 1M absolute maximum
    
    // Use system maximum if available, otherwise use default
    if (target_limit == RLIM_INFINITY || target_limit > ABSOLUTE_MAX_FD) {
        target_limit = DEFAULT_MAX_FD;
    }
    
    // Only increase limits if current soft limit is lower
    if (file_limits.rlim_cur < target_limit) {
        file_limits.rlim_cur = target_limit;
        
        if (setrlimit(RLIMIT_NOFILE, &file_limits) != 0) {
            debug(LOG_WARNING, "Failed to set file descriptor limits to %ld: %s", 
                  (long)target_limit, strerror(errno));
            debug(LOG_INFO, "Continuing with current limits: %ld", (long)file_limits.rlim_cur);
        } else {
            debug(LOG_DEBUG, "Successfully set file descriptor limits to %ld", (long)target_limit);
        }
    } else {
        debug(LOG_DEBUG, "Current file descriptor limits are sufficient: %ld", 
              (long)file_limits.rlim_cur);
    }
}

/**
 * @brief Initializes or validates the gateway start time
 * 
 * Ensures the gateway has a valid start timestamp that is at least
 * equal to MINIMUM_STARTED_TIME. Sets current time if no valid
 * timestamp exists.
 * 
 * This timestamp is used for various timing and scheduling operations
 * throughout the gateway's operation.
 */
static void 
init_started_time(void) 
{
    if (!started_time || started_time < MINIMUM_STARTED_TIME) {
        started_time = time(NULL);
        debug(LOG_DEBUG, "Gateway start time initialized to: %ld", (long)started_time);
    }
}

/**
 * @brief Initializes firewall rules and network security
 * 
 * This function:
 * 1. Flushes the connection tracking table
 * 2. Removes existing firewall rules
 * 3. Initializes new firewall rules
 * 
 * @throws Exits with failure if firewall initialization fails
 */
static void 
init_firewall(void)
{
    // Clear existing network state
    // conntrack_flush(NULL);
    fw_destroy();

    // Initialize new firewall rules
    if (!fw_init()) {
        debug(LOG_ERR, "FATAL: Failed to initialize firewall");
        exit(EXIT_FAILURE);
    }
}

/**
 * @brief Main initialization function for the WiFiDog gateway
 * 
 * Performs complete initialization of all gateway components:
 * - Message system and redirect files
 * - SSL/TLS security
 * - System resources and limits
 * - Process management
 * - Network security
 *
 * @param config Pointer to the global configuration structure
 * @throws Exits with failure if critical initialization fails
 */
static void 
wd_init(s_config *config)
{
    // Initialize user interface components
    wd_msg_init();    // Setup message system
    wd_redir_file_init();  // Setup redirect pages
    
    // Initialize security components
    openssl_init();  // Setup SSL/TLS
    
    // Initialize system components
    init_started_time();  // Set gateway start time
    init_resource_limits();  // Configure system limits
    
    // Process management
    if (config->pidfile) {
        save_pid_file(config->pidfile);
    }

    // Network security
    init_firewall();

    // Load client snapshot if exists
    if (!is_portal_auth_disabled() && !is_bypass_mode()) {
        client_snapshot_load();
    } else {
        debug(LOG_INFO, "Portal auth disabled or bypass mode, skip snapshot load");
    }
}

/**
 * @brief Creates a detached thread with proper error handling
 * 
 * @param tid Pointer to thread ID storage
 * @param routine Thread function to execute
 * @param arg Argument to pass to thread function
 * @param name Thread name for debugging
 * @return 1 on success, 0 on failure
 */
static int 
create_detached_thread(pthread_t *tid, void *(*routine)(void*), void *arg, const char *name) 
{
    if (!tid || !routine || !name) {
        debug(LOG_ERR, "Invalid parameters for thread creation");
        return 0;
    }
    
    int result = pthread_create(tid, NULL, routine, arg);
    if (result != 0) {
        debug(LOG_ERR, "FATAL: Failed to create thread '%s': %s", name, strerror(result));
        termination_handler(0);
        return 0;
    }
    
    result = pthread_detach(*tid);
    if (result != 0) {
        debug(LOG_WARNING, "Failed to detach thread '%s': %s", name, strerror(result));
        // Continue anyway as the thread was created successfully
    }
    
    debug(LOG_DEBUG, "Successfully created and detached thread '%s'", name);
    return 1;
}

/**
 * @brief Initializes all service threads with proper error handling
 *
 * @param config Pointer to global configuration
 */
static void
threads_init(s_config *config)
{
    if (!config) {
        debug(LOG_ERR, "Invalid config parameter for thread initialization");
        return;
    }
    
    // Core service threads - these are always required
    // Skip HTTPS server thread if portal auth is disabled
    if (!is_portal_auth_disabled()) {
        if (!create_detached_thread(&tid_tls_server, (void *)thread_tls_server, NULL, "https_server")) {
            debug(LOG_ERR, "Failed to create HTTPS server thread");
            return;
        }
    } else {
        debug(LOG_INFO, "Portal auth is disabled, skipping HTTPS server thread");
    }
    
    char *wdctl_sock_copy = NULL;
    if (config->wdctl_sock) {
        wdctl_sock_copy = safe_strdup(config->wdctl_sock);
        if (!wdctl_sock_copy) {
            debug(LOG_ERR, "Failed to duplicate wdctl socket path");
            return;
        }
    }
    
    if (!create_detached_thread(&tid_wdctl, (void *)thread_wdctl, 
                               (void *)wdctl_sock_copy, "wdctl")) {
        debug(LOG_ERR, "Failed to create wdctl thread");
        if (wdctl_sock_copy) free(wdctl_sock_copy);
        return;
    }

    if (!create_detached_thread(&tid_dns_monitor, (void *)thread_dns_monitor, NULL, "dns_monitor")) {
        debug(LOG_ERR, "Failed to create DNS monitor thread");
        return;
    }

    if (!create_detached_thread(&tid_ping, (void *)thread_ping, NULL, "ping")) {
        debug(LOG_ERR, "Failed to create ping thread");
        return;
    }

    // Auth server dependent threads
    if (is_local_auth_mode()) {
        debug(LOG_INFO, "Auth mode is local, no need to start auth server related threads");
        return;
    }

    // Start auth server dependent threads
    if (!create_detached_thread(&tid_fw_counter, (void *)thread_client_timeout_check, NULL, "fw_counter")) {
        debug(LOG_ERR, "Failed to create firewall counter thread");
        return;
    }

    // Optional websocket thread
    if (get_ws_server()) {
        if (!create_detached_thread(&tid_ws, (void *)thread_websocket, NULL, "websocket")) {
            debug(LOG_WARNING, "Failed to create WebSocket thread (optional)");
        }
    }

    // Optional MQTT thread
    if (get_mqtt_server()) {
        if (!create_detached_thread(&tid_mqtt_server, (void *)thread_mqtt, config, "mqtt")) {
            debug(LOG_WARNING, "Failed to create MQTT thread (optional)");
        }
    }

    // Resilience thread - monitor firewall and periodic snapshots
    if (is_portal_auth_disabled() || is_bypass_mode()) {
        debug(LOG_INFO, "Portal auth disabled or bypass mode, skip resilience thread");
    } else if (!create_detached_thread(&tid_resilience, (void *)thread_resilience, NULL, "resilience")) {
        debug(LOG_ERR, "Failed to create resilience thread");
        return;
    }
}

/**
 * @brief Static function declaration
 * 
 * This placeholder documentation is generic since no function name, parameters,
 * or implementation details are provided in the selection. To generate more
 * specific documentation, please include the complete function signature and
 * context.
 */
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

/**
 * @brief Internal function declaration prefix
 * @details Defines a static function with return type int, indicating the function
 *          is only visible within the current source file (gateway.c)
 * @return integer value indicating success/failure status
 */
static int
setup_http_server(struct evhttp *http, struct event_base *base)
{
    s_config *config = config_get_config();
    int is_ssl = 0;
    
    if (!http || !base) {
        debug(LOG_ERR, "Invalid parameters for HTTP server setup");
        return 0;
    }
    
    if (config->auth_server_mode == AUTH_MODE_CLOUD) {
        t_auth_serv *auth_server = get_auth_server();
        if (!auth_server || !auth_server->authserv_hostname) {
            debug(LOG_ERR, "Invalid auth server configuration");
            return 0;
        }
        
        SSL_CTX *ssl_ctx = SSL_CTX_new(SSLv23_method());
        if (!ssl_ctx) {
            debug(LOG_ERR, "Failed to create SSL context");
            return 0;
        }

        SSL *ssl = SSL_new(ssl_ctx);
        if (!ssl) {
            debug(LOG_ERR, "Failed to create SSL object");
            SSL_CTX_free(ssl_ctx);
            return 0;
        }

        if (!SSL_set_tlsext_host_name(ssl, auth_server->authserv_hostname)) {
            debug(LOG_ERR, "SSL_set_tlsext_host_name failed");
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            return 0;
        }
    
        // Assign to the static pointer after successful creation
        s_auth_request_ctx = wd_request_context_new(
            base, ssl, auth_server->authserv_use_ssl);
        if (!s_auth_request_ctx) {
            debug(LOG_ERR, "Failed to create auth request context");
            SSL_free(ssl);
            SSL_CTX_free(ssl_ctx);
            return 0;
        }

        evhttp_set_cb(http, "/wifidog", ev_http_callback_wifidog, NULL);
        evhttp_set_cb(http, "/wifidog/auth", ev_http_callback_auth, s_auth_request_ctx);
        evhttp_set_cb(http, "/wifidog/temporary_pass", ev_http_callback_temporary_pass, NULL);
    } else if (config->auth_server_mode == AUTH_MODE_LOCAL) {
        evhttp_set_cb(http, "/wifidog/local_auth", ev_http_callback_local_auth, NULL);
        evhttp_set_cb(http, "/cgi-bin/cgi-device", ev_http_callback_device, NULL);
    }
    evhttp_set_gencb(http, ev_http_callback_404, &is_ssl);
    return 1;
}

/**
 * @brief Global HTTP server instance for handling web requests
 * 
 * This pointer holds the libevent HTTP server instance that handles
 * all incoming HTTP requests for the gateway. It is used for processing
 * authentication, portal pages, and other web-based interactions.
 * 
 * @return struct evhttp* Pointer to the HTTP server instance
 */
static struct evhttp* 
init_http_server(struct event_base *base)
{
    struct evhttp *http = evhttp_new(base);
    if (!http) return NULL;

    evhttp_set_allowed_methods(http,
        EVHTTP_REQ_GET |
        EVHTTP_REQ_POST |
        EVHTTP_REQ_OPTIONS);

    return http;
}

/**
 * @brief Function prototype declaration for an internal helper function
 * 
 * This static function is defined within the gateway.c file and is only accessible
 * within this translation unit. The function serves as a helper function for the
 * gateway functionality.
 * 
 * @return Returns an integer status code indicating success or failure
 */
static int
bind_http_server(struct evhttp *http, struct event_base *base, int port)
{
    struct evconnlistener *listener;
    struct sockaddr_in6 sin_ipv6;

    memset(&sin_ipv6, 0, sizeof(sin_ipv6));
    sin_ipv6.sin6_family = AF_INET6;
    sin_ipv6.sin6_port = htons(port);
    sin_ipv6.sin6_addr = in6addr_any;

    listener = evconnlistener_new_bind(base, NULL, NULL,
        LEV_OPT_CLOSE_ON_FREE | LEV_OPT_REUSEABLE, -1,
        (struct sockaddr*)&sin_ipv6, sizeof(sin_ipv6));
    if (!listener) {
        debug(LOG_ERR, "Failed to bind ipv6 address to port %d", port);
        return 0;
    }

    if (!evhttp_bind_listener(http, listener)) {
        debug(LOG_ERR, "Failed to bind listener to port %d", port);
        return 0;
    }

    return 1;
}

/**
 * @brief Gateway level static function that requires documentation
 * 
 * Note: Without more context about the function's purpose and parameters,
 * this is a generic documentation template. Please provide the full 
 * function signature and implementation details for more specific
 * documentation.
 */
static void
http_redir_loop(s_config *config)
{
    struct event_base *base = event_base_new();
    if (!base) termination_handler(0);

    wd_debug_base(base);

    struct evhttp *http = init_http_server(base);
    if (!http) termination_handler(0);
    
    wd_signals_init(base);
    
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    if (!setup_http_server(http, base)) 
        termination_handler(0);

    if (!bind_http_server(http, base, config->gw_port))
        termination_handler(0);
    
    debug(LOG_INFO, "HTTP server started on port %d", config->gw_port);
    event_base_dispatch(base);

    if (s_auth_request_ctx) {
        wd_request_context_destroy(s_auth_request_ctx);
        s_auth_request_ctx = NULL;
    }
    evhttp_free(http);
    event_base_free(base);
}

/**
 * @brief Cleanup function called before process exit
 * 
 * Properly releases all allocated resources including:
 * - Global configuration
 * - Event buffers for offline pages
 * - Redirect HTML buffers
 * - Client lists
 * - Firewall rules
 */
static void
aw_clean_before_exit(void)
{
    debug(LOG_DEBUG, "Starting cleanup before exit");
    
    // Clean up global configuration resources
    config_cleanup(); 

    // Clean up event buffers
    if (evb_internet_offline_page) {
        evbuffer_free(evb_internet_offline_page);
        evb_internet_offline_page = NULL;
    }
    if (evb_authserver_offline_page) {
        evbuffer_free(evb_authserver_offline_page);
        evb_authserver_offline_page = NULL;
    }
    
    // Clean up redirect HTML buffer
    if (wifidog_redir_html) {
        if (wifidog_redir_html->front) {
            free(wifidog_redir_html->front);
            wifidog_redir_html->front = NULL;
        }
        if (wifidog_redir_html->rear) {
            free(wifidog_redir_html->rear);
            wifidog_redir_html->rear = NULL;
        }
        free(wifidog_redir_html);
        wifidog_redir_html = NULL;
    }

    // Clean up client lists
    t_client *first_client = client_get_first_client();
    if (first_client) {
        client_list_destroy(first_client);
    }
    
    t_offline_client *first_offline_client = client_get_first_offline_client();
    if (first_offline_client) {
        offline_client_list_destroy(first_offline_client);
    }

    // Clean up firewall
    fw_destroy();
    
    debug(LOG_DEBUG, "Cleanup before exit completed");
}

/**
 * @brief Main loop for the gateway
 * 
 * This function initializes the gateway components and starts the main loop
 * for the gateway operation. It includes initialization of SSL, threads, and
 * the HTTP server for handling web requests.
 */
static void
main_loop(void)
{
    s_config *config = config_get_config();
    
    safe_set_cleanup_func(aw_clean_before_exit);
    wd_init(config);
    threads_init(config);
    
    // Skip HTTP service if portal auth is disabled
    if (!is_portal_auth_disabled()) {
        http_redir_loop(config);
    } else {
        debug(LOG_INFO, "Portal auth is disabled, skipping HTTP redirect service");
        
        // Create event base for signal handling when HTTP service is disabled
        struct event_base *base = event_base_new();
        if (!base) {
            debug(LOG_ERR, "Failed to create event base for signal handling");
            termination_handler(0);
        }
        
        // Initialize signal handlers
        wd_signals_init(base);
        
        debug(LOG_INFO, "Starting minimal event loop for signal handling");
        // Run event loop to handle signals gracefully
        event_base_dispatch(base);
        
        // Cleanup
        event_base_free(base);
    }
}

/**
 * @brief Gateway main function
 * 
 * This is the main entry point for the gateway application. It initializes
 * the configuration, command line arguments, and gateway settings before
 * starting the main loop for the gateway operation.
 * 
 * @param argc Number of command line arguments
 * @param argv Array of command line arguments
 * @return Integer status code
 */
int
gw_main(int argc, char **argv)
{
    config_init();
    parse_commandline(argc, argv);
    config_read();
    config_validate();
    gateway_setting_init();
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
