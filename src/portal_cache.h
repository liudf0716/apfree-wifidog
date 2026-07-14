// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2024 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Portal page resource cache for apfree-wifidog.
 */

#ifndef _PORTAL_CACHE_H_
#define _PORTAL_CACHE_H_

#include <event2/http.h>
#include <json-c/json.h>

#define PORTAL_CACHE_DIR         "/tmp/portal_cache"
#define PORTAL_CACHE_MAX_SIZE    (20 * 1024 * 1024)
#define PORTAL_CACHE_MAX_FILES   64
#define PORTAL_CACHE_DEFAULT_TTL 86400
#define PORTAL_CACHE_KEY_LEN     65

typedef enum {
    CACHE_EMPTY = 0,
    CACHE_DOWNLOADING,
    CACHE_READY,
    CACHE_EXPIRED,
    CACHE_ERROR
} cache_state_t;

/* Forward declaration for pending client queue */
struct pending_client_s;

typedef struct {
    char            url[512];
    char            cache_key[PORTAL_CACHE_KEY_LEN];
    char            local_path[330];   /* cache_dir(256) + '/' + key(64) + '\0' */
    char            content_type[64];
    unsigned long   file_size;
    time_t          download_time;
    time_t          expire_time;
    cache_state_t   state;
    struct pending_client_s *pending_clients;  /* Queue of waiting clients */
} portal_cache_entry_t;

typedef struct {
    portal_cache_entry_t    entries[PORTAL_CACHE_MAX_FILES];
    int                     count;
    pthread_mutex_t         lock;
    char                    cache_dir[256];
} portal_cache_t;

int     portal_cache_init(void);
void    portal_cache_destroy(void);
int     portal_cache_start_reap_timer(struct event_base *base);
void    portal_cache_make_key(const char *channel, const char *url,
                              char *key, size_t key_size);
portal_cache_entry_t *portal_cache_lookup(const char *cache_key);
int     portal_cache_is_valid(const portal_cache_entry_t *entry);
int     portal_cache_download(const char *channel, const char *url, int ttl);
void    portal_cache_trigger_update(json_object *j_data);
void    portal_cache_cleanup_expired(void);
const char *portal_cache_get_content_type(const char *url);

/* HTTP callback for /wifidog/portal/cache/{key} */
void    ev_http_callback_portal_cache(struct evhttp_request *req, void *arg);

#endif /* _PORTAL_CACHE_H_ */
