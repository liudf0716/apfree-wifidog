// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2024 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Portal page resource cache implementation.
 */

#include "common.h"
#include "portal_cache.h"
#include "debug.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <event2/http.h>
#include <json-c/json.h>

/* Global cache instance */
static portal_cache_t g_cache;
static int g_cache_initialized = 0;
static struct event_base *g_evbase = NULL;  /* Global event base for async downloads */

/* ---- Pending client request for concurrent downloads ---- */
typedef struct pending_client_s {
    struct evhttp_request           *req;
    struct pending_client_s         *next;
} pending_client_t;

/* ---- Async download context ---- */
typedef struct {
    char                        url[512];
    char                        key[PORTAL_CACHE_KEY_LEN];
    char                        tmp_path[330];
    char                        local_path[330];
    char                        content_type[64];
    int                         fd;
    size_t                      bytes_written;
    struct evhttp_request       *client_req;    /* First deferred client request */
    pending_client_t            *pending;       /* Additional pending clients */
    struct evhttp_connection    *evcon;         /* HTTP connection for cleanup */
    portal_cache_entry_t        *entry;
} download_context_t;

/* MIME type table */
static const struct {
    const char *ext;
    const char *type;
} mime_types[] = {
    {".jpg",  "image/jpeg"},
    {".jpeg", "image/jpeg"},
    {".png",  "image/png"},
    {".gif",  "image/gif"},
    {".webp", "image/webp"},
    {".svg",  "image/svg+xml"},
    {".ico",  "image/x-icon"},
    {".css",  "text/css"},
    {".js",   "application/javascript"},
    {".html", "text/html"},
    {NULL,    "application/octet-stream"}
};

/* ---- SHA256 key generation ---- */
void
portal_cache_make_key(const char *channel, const char *url,
                      char *key, size_t key_size)
{
    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hash_len = 0;

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        /* Fallback: fill with zeros */
        memset(key, '0', key_size > 64 ? 64 : key_size);
        if (key_size > 64) key[64] = '\0';
        return;
    }

    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    if (channel && *channel)
        EVP_DigestUpdate(ctx, channel, strlen(channel));
    EVP_DigestUpdate(ctx, url, strlen(url));
    EVP_DigestFinal_ex(ctx, hash, &hash_len);
    EVP_MD_CTX_free(ctx);

    for (unsigned int i = 0; i < hash_len && (i * 2 + 2) < key_size; i++)
        sprintf(key + i * 2, "%02x", hash[i]);
}

/* ---- Content-Type inference ---- */
const char *
portal_cache_get_content_type(const char *url)
{
    if (!url) return "application/octet-stream";

    /* Find the last '.' before any '?' (query string) */
    const char *dot = NULL;
    const char *question = strchr(url, '?');
    const char *p = url + strlen(url);

    while (p > url) {
        p--;
        if (*p == '?' && !question) { question = p; continue; }
        if (*p == '.') { dot = p; break; }
        if (*p == '/') break;
    }

    if (!dot) return "application/octet-stream";

    for (int i = 0; mime_types[i].ext; i++) {
        if (strcasecmp(dot, mime_types[i].ext) == 0)
            return mime_types[i].type;
    }
    return "application/octet-stream";
}

/* ---- Find free entry slot ---- */
static portal_cache_entry_t *
find_free_entry(void)
{
    for (int i = 0; i < PORTAL_CACHE_MAX_FILES; i++) {
        if (g_cache.entries[i].state == CACHE_EMPTY)
            return &g_cache.entries[i];
    }
    return NULL;
}

/* ---- Find entry by key ---- */
static portal_cache_entry_t *
find_entry_by_key(const char *key)
{
    for (int i = 0; i < PORTAL_CACHE_MAX_FILES; i++) {
        if (g_cache.entries[i].state != CACHE_EMPTY &&
            strcmp(g_cache.entries[i].cache_key, key) == 0)
            return &g_cache.entries[i];
    }
    return NULL;
}

/* ---- Initialize ---- */
int
portal_cache_init(void)
{
    if (g_cache_initialized) return 0;

    memset(&g_cache, 0, sizeof(g_cache));
    pthread_mutex_init(&g_cache.lock, NULL);
    strncpy(g_cache.cache_dir, PORTAL_CACHE_DIR, sizeof(g_cache.cache_dir) - 1);

    /* Create cache directory */
    if (mkdir(g_cache.cache_dir, 0755) != 0 && errno != EEXIST) {
        debug(LOG_ERR, "Failed to create portal cache dir %s: %s",
              g_cache.cache_dir, strerror(errno));
        return -1;
    }

    g_cache_initialized = 1;
    debug(LOG_INFO, "Portal cache initialized at %s", g_cache.cache_dir);
    return 0;
}

/* ---- Save event base for async downloads ---- */
int
portal_cache_start_reap_timer(struct event_base *base)
{
    if (!base) return -1;
    g_evbase = base;
    return 0;
}

/* ---- Destroy ---- */
void
portal_cache_destroy(void)
{
    if (!g_cache_initialized) return;

    pthread_mutex_destroy(&g_cache.lock);
    g_cache_initialized = 0;
}

/* ---- Lookup ---- */
portal_cache_entry_t *
portal_cache_lookup(const char *cache_key)
{
    if (!cache_key || !g_cache_initialized) return NULL;
    return find_entry_by_key(cache_key);
}

/* ---- Check validity ---- */
int
portal_cache_is_valid(const portal_cache_entry_t *entry)
{
    if (!entry) return 0;
    if (entry->state != CACHE_READY) return 0;
    if (time(NULL) > entry->expire_time) return 0;
    if (access(entry->local_path, R_OK) != 0) return 0;
    return 1;
}

/* Forward declaration */
static int portal_cache_download_async(const char *url, const char *local_path,
                                       const char *key, const char *content_type,
                                       portal_cache_entry_t *entry,
                                       struct evhttp_request *client_req);

/* ---- Proactive cache download (triggered by bootstrap response) ---- */
int
portal_cache_download(const char *channel, const char *url, int ttl)
{
    if (!channel || !url || !*url || !g_cache_initialized)
        return -1;

    char key[PORTAL_CACHE_KEY_LEN];
    portal_cache_make_key(channel, url, key, sizeof(key));

    pthread_mutex_lock(&g_cache.lock);

    portal_cache_entry_t *entry = find_entry_by_key(key);
    if (entry && (entry->state == CACHE_READY || entry->state == CACHE_DOWNLOADING)) {
        if (portal_cache_is_valid(entry)) {
            pthread_mutex_unlock(&g_cache.lock);
            return 0; /* already cached and valid */
        }
        /* Expired or error: reuse slot */
    }

    if (!entry) {
        entry = find_free_entry();
        if (!entry) {
            debug(LOG_WARNING, "Portal cache full, cannot cache %s", url);
            pthread_mutex_unlock(&g_cache.lock);
            return -1;
        }
    }

    /* Initialize entry */
    memset(entry->url, 0, sizeof(entry->url));
    strncpy(entry->url, url, sizeof(entry->url) - 1);
    strncpy(entry->cache_key, key, sizeof(entry->cache_key) - 1);
    snprintf(entry->local_path, sizeof(entry->local_path),
             "%s/%s", g_cache.cache_dir, key);
    strncpy(entry->content_type, portal_cache_get_content_type(url),
            sizeof(entry->content_type) - 1);

    entry->state = CACHE_DOWNLOADING;

    /* Remove stale file if exists */
    unlink(entry->local_path);

    pthread_mutex_unlock(&g_cache.lock);

    /* Start async download via libevent (no client request to defer) */
    char local_path[330];
    snprintf(local_path, sizeof(local_path), "%s/%s", g_cache.cache_dir, key);

    int ret = portal_cache_download_async(url, local_path, key,
                                          entry->content_type, entry, NULL);
    if (ret != 0) {
        entry->state = CACHE_EMPTY;
        return -1;
    }

    return 0;
}

/* ---- Cleanup expired entries ---- */
void
portal_cache_cleanup_expired(void)
{
    if (!g_cache_initialized) return;

    pthread_mutex_lock(&g_cache.lock);
    time_t now = time(NULL);

    for (int i = 0; i < PORTAL_CACHE_MAX_FILES; i++) {
        portal_cache_entry_t *e = &g_cache.entries[i];
        if (e->state == CACHE_READY && now > e->expire_time) {
            debug(LOG_INFO, "Portal cache expired: %s", e->cache_key);
            unlink(e->local_path);
            /* Free pending clients list */
            pending_client_t *pc = e->pending_clients;
            while (pc) {
                pending_client_t *next = pc->next;
                evhttp_send_error(pc->req, HTTP_NOTFOUND, "Cache Expired");
                free(pc);
                pc = next;
            }
            memset(e, 0, sizeof(*e));
            e->state = CACHE_EMPTY;
        }
        if (e->state == CACHE_ERROR) {
            /* Free pending clients list */
            pending_client_t *pc = e->pending_clients;
            while (pc) {
                pending_client_t *next = pc->next;
                evhttp_send_error(pc->req, HTTP_NOTFOUND, "Download Failed");
                free(pc);
                pc = next;
            }
            memset(e, 0, sizeof(*e));
            e->state = CACHE_EMPTY;
        }
    }
    g_cache.count = 0;
    for (int i = 0; i < PORTAL_CACHE_MAX_FILES; i++) {
        if (g_cache.entries[i].state != CACHE_EMPTY)
            g_cache.count++;
    }
    pthread_mutex_unlock(&g_cache.lock);
}

/* ---- Trigger update from bootstrap response ---- */
void
portal_cache_trigger_update(json_object *j_data)
{
    if (!j_data || !g_cache_initialized) return;

    json_object *j_bg = NULL, *j_p1 = NULL, *j_p2 = NULL, *j_p3 = NULL;
    json_object *j_channel = NULL;

    /* Use _original* fields for download (these are the real URLs) */
    json_object_object_get_ex(j_data, "_originalBackgroundUrl", &j_bg);
    json_object_object_get_ex(j_data, "_originalPoster1Url", &j_p1);
    json_object_object_get_ex(j_data, "_originalPoster2Url", &j_p2);
    json_object_object_get_ex(j_data, "_originalPoster3Url", &j_p3);

    /* Fallback: if _original* fields don't exist, use the regular fields */
    if (!j_bg) json_object_object_get_ex(j_data, "backgroundUrl", &j_bg);
    if (!j_p1) json_object_object_get_ex(j_data, "poster1Url", &j_p1);
    if (!j_p2) json_object_object_get_ex(j_data, "poster2Url", &j_p2);
    if (!j_p3) json_object_object_get_ex(j_data, "poster3Url", &j_p3);

    json_object_object_get_ex(j_data, "gwChannel", &j_channel);

    const char *channel = j_channel ? json_object_get_string(j_channel) : "default";
    if (!channel || !*channel) channel = "default";

    const char *urls[4];
    int count = 0;

    if (j_bg) urls[count++] = json_object_get_string(j_bg);
    if (j_p1) urls[count++] = json_object_get_string(j_p1);
    if (j_p2) urls[count++] = json_object_get_string(j_p2);
    if (j_p3) urls[count++] = json_object_get_string(j_p3);

    debug(LOG_INFO, "Portal cache: triggering update for channel '%s', %d images",
          channel, count);

    for (int i = 0; i < count; i++) {
        if (urls[i] && *urls[i]) {
            portal_cache_download(channel, urls[i], PORTAL_CACHE_DEFAULT_TTL);
        }
    }

    /* Cleanup expired in the background */
    portal_cache_cleanup_expired();
}

/* ---- Base64URL decode helper ---- */
static int
base64url_decode(const char *encoded, char *decoded, size_t decoded_size)
{
    if (!encoded || !decoded || decoded_size == 0) return -1;

    size_t len = strlen(encoded);
    /* Allocate temp buffer for standard base64 */
    char *buf = malloc(len + 4);
    if (!buf) return -1;

    /* Convert base64url to standard base64 */
    memcpy(buf, encoded, len);
    buf[len] = '\0';
    for (size_t i = 0; i < len; i++) {
        if (buf[i] == '-') buf[i] = '+';
        else if (buf[i] == '_') buf[i] = '/';
    }
    /* Add padding */
    while (len % 4 != 0) {
        buf[len++] = '=';
    }
    buf[len] = '\0';

    /* Decode */
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *mem = BIO_new_mem_buf(buf, len);
    BIO_push(b64, mem);
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);

    int decoded_len = BIO_read(b64, decoded, decoded_size - 1);
    BIO_free_all(b64);
    free(buf);

    if (decoded_len < 0) return -1;
    decoded[decoded_len] = '\0';
    return decoded_len;
}

/* Forward declaration */
static void add_cors_headers(struct evhttp_request *req, struct evkeyvalq *headers);

/* ---- Serve cached file to deferred request ---- */
static void
serve_cache_file_deferred(struct evhttp_request *client_req, portal_cache_entry_t *entry)
{
    struct stat st;
    int fd = open(entry->local_path, O_RDONLY);
    if (fd < 0 || stat(entry->local_path, &st) != 0) {
        evhttp_send_error(client_req, HTTP_NOTFOUND, "File Not Found");
        evhttp_request_free(client_req);
        if (fd >= 0) close(fd);
        return;
    }

    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        close(fd);
        evhttp_send_error(client_req, HTTP_SERVUNAVAIL, "No Memory");
        evhttp_request_free(client_req);
        return;
    }

    if (evbuffer_add_file(evb, fd, 0, st.st_size) < 0) {
        close(fd);
        evbuffer_free(evb);
        evhttp_send_error(client_req, HTTP_SERVUNAVAIL, "Internal Error");
        evhttp_request_free(client_req);
        return;
    }

    struct evkeyvalq *headers = evhttp_request_get_output_headers(client_req);
    evhttp_add_header(headers, "Content-Type", entry->content_type);
    evhttp_add_header(headers, "Cache-Control", "public, max-age=3600");
    evhttp_add_header(headers, "Connection", "close");
    add_cors_headers(client_req, headers);

    evhttp_send_reply(client_req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
    evhttp_request_free(client_req);
}

/* ---- Async download: chunk callback ---- */
static void
download_chunk_cb(struct evhttp_request *down_req, void *arg)
{
    download_context_t *ctx = arg;
    struct evbuffer *input = evhttp_request_get_input_buffer(down_req);
    size_t chunk_len = evbuffer_get_length(input);

    if (chunk_len == 0) return;

    /* Enforce file size limit */
    if (ctx->bytes_written + chunk_len > PORTAL_CACHE_MAX_SIZE) {
        debug(LOG_WARNING, "Portal cache download exceeds size limit: %s", ctx->url);
        evhttp_cancel_request(down_req);
        return;
    }

    /* Write chunk to temp file */
    int written = evbuffer_write(input, ctx->fd);
    if (written > 0) {
        ctx->bytes_written += written;
    }
}

/* ---- Async download: complete callback ---- */
static void
download_complete_cb(struct evhttp_request *down_req, void *arg)
{
    download_context_t *ctx = arg;
    int status_code = down_req ? evhttp_request_get_response_code(down_req) : 0;

    close(ctx->fd);
    ctx->fd = -1;

    /* Check if cache was destroyed during download */
    if (!g_cache_initialized) {
        if (ctx->client_req) evhttp_request_free(ctx->client_req);
        /* Pending clients are in entry, but entry may be invalid */
        unlink(ctx->tmp_path);
        if (ctx->evcon) evhttp_connection_free(ctx->evcon);
        free(ctx);
        return;
    }

    pthread_mutex_lock(&g_cache.lock);

    if (status_code == HTTP_OK && ctx->bytes_written > 0) {
        /* Success: rename temp to final */
        if (rename(ctx->tmp_path, ctx->local_path) == 0) {
            ctx->entry->file_size = ctx->bytes_written;
            ctx->entry->download_time = time(NULL);
            ctx->entry->expire_time = ctx->entry->download_time + PORTAL_CACHE_DEFAULT_TTL;
            ctx->entry->state = CACHE_READY;
            debug(LOG_INFO, "Portal cache async download ok: %s (%zu bytes)",
                  ctx->key, ctx->bytes_written);

            /* Serve all pending clients (first request + queued requests) */
            if (ctx->client_req) {
                serve_cache_file_deferred(ctx->client_req, ctx->entry);
                ctx->client_req = NULL;
            }
            /* Serve queued pending clients */
            pending_client_t *pc = ctx->entry->pending_clients;
            ctx->entry->pending_clients = NULL;
            while (pc) {
                pending_client_t *next = pc->next;
                serve_cache_file_deferred(pc->req, ctx->entry);
                free(pc);
                pc = next;
            }
        } else {
            debug(LOG_WARNING, "Portal cache rename failed: %s -> %s: %s",
                  ctx->tmp_path, ctx->local_path, strerror(errno));
            unlink(ctx->tmp_path);
            ctx->entry->state = CACHE_ERROR;
            /* Send error to all pending clients */
            if (ctx->client_req) {
                evhttp_send_error(ctx->client_req, HTTP_SERVUNAVAIL, "Internal Error");
                evhttp_request_free(ctx->client_req);
                ctx->client_req = NULL;
            }
            pending_client_t *pc = ctx->entry->pending_clients;
            ctx->entry->pending_clients = NULL;
            while (pc) {
                pending_client_t *next = pc->next;
                evhttp_send_error(pc->req, HTTP_SERVUNAVAIL, "Internal Error");
                evhttp_request_free(pc->req);
                free(pc);
                pc = next;
            }
        }
    } else {
        /* Failure */
        ctx->entry->state = CACHE_ERROR;
        unlink(ctx->tmp_path);
        debug(LOG_WARNING, "Portal cache async download failed (status=%d): %s",
              status_code, ctx->url);
        /* Send error to all pending clients */
        if (ctx->client_req) {
            evhttp_send_error(ctx->client_req, HTTP_NOTFOUND, "Download Failed");
            evhttp_request_free(ctx->client_req);
            ctx->client_req = NULL;
        }
        pending_client_t *pc = ctx->entry->pending_clients;
        ctx->entry->pending_clients = NULL;
        while (pc) {
            pending_client_t *next = pc->next;
            evhttp_send_error(pc->req, HTTP_NOTFOUND, "Download Failed");
            evhttp_request_free(pc->req);
            free(pc);
            pc = next;
        }
    }

    pthread_mutex_unlock(&g_cache.lock);

    /* Cleanup */
    if (ctx->evcon) evhttp_connection_free(ctx->evcon);
    free(ctx);
}

/* ---- Async download: start ---- */
static int
portal_cache_download_async(const char *url, const char *local_path,
                            const char *key, const char *content_type,
                            portal_cache_entry_t *entry,
                            struct evhttp_request *client_req)
{
    /* Parse URL */
    struct evhttp_uri *parsed_uri = evhttp_uri_parse(url);
    if (!parsed_uri) return -1;

    const char *scheme = evhttp_uri_get_scheme(parsed_uri);
    const char *host = evhttp_uri_get_host(parsed_uri);
    int port = evhttp_uri_get_port(parsed_uri);
    const char *path = evhttp_uri_get_path(parsed_uri);
    const char *query = evhttp_uri_get_query(parsed_uri);

    if (!host) {
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    int is_https = (scheme && strcasecmp(scheme, "https") == 0);
    if (port == -1) port = is_https ? 443 : 80;

    /* Build full path with query */
    char full_path[1024];
    if (query) {
        snprintf(full_path, sizeof(full_path), "%s?%s", path ? path : "/", query);
    } else {
        snprintf(full_path, sizeof(full_path), "%s", path ? path : "/");
    }

    /* Create download context */
    download_context_t *ctx = calloc(1, sizeof(download_context_t));
    if (!ctx) {
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    strncpy(ctx->url, url, sizeof(ctx->url) - 1);
    strncpy(ctx->key, key, sizeof(ctx->key) - 1);
    snprintf(ctx->tmp_path, sizeof(ctx->tmp_path), "%s/.%s.tmp", g_cache.cache_dir, key);
    strncpy(ctx->local_path, local_path, sizeof(ctx->local_path) - 1);
    strncpy(ctx->content_type, content_type, sizeof(ctx->content_type) - 1);
    ctx->client_req = client_req;
    ctx->entry = entry;
    ctx->evcon = NULL;

    /* Open temp file */
    ctx->fd = open(ctx->tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ctx->fd < 0) {
        debug(LOG_ERR, "Portal cache: failed to create temp file %s: %s",
              ctx->tmp_path, strerror(errno));
        free(ctx);
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    /* Use global event base (works for both proactive and lazy downloads) */
    if (!g_evbase) {
        debug(LOG_ERR, "Portal cache: event base not initialized");
        close(ctx->fd);
        unlink(ctx->tmp_path);
        free(ctx);
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    /* Create HTTP connection */
    struct evhttp_connection *evcon = evhttp_connection_base_new(g_evbase, NULL, host, port);

    if (!evcon) {
        close(ctx->fd);
        unlink(ctx->tmp_path);
        free(ctx);
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    evhttp_connection_set_timeout(evcon, 30);
    ctx->evcon = evcon;  /* Save for cleanup in download_complete_cb */

    /* Create request */
    struct evhttp_request *down_req = evhttp_request_new(download_complete_cb, ctx);
    if (!down_req) {
        evhttp_connection_free(evcon);
        close(ctx->fd);
        unlink(ctx->tmp_path);
        free(ctx);
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    /* Set chunk callback for streaming to disk */
    evhttp_request_set_chunked_cb(down_req, download_chunk_cb);

    /* Set headers */
    evhttp_add_header(evhttp_request_get_output_headers(down_req), "Host", host);
    evhttp_add_header(evhttp_request_get_output_headers(down_req), "Connection", "close");

    /* Mark entry as downloading */
    entry->state = CACHE_DOWNLOADING;

    /* Make the request */
    int ret = evhttp_make_request(evcon, down_req, EVHTTP_REQ_GET, full_path);
    if (ret != 0) {
        debug(LOG_ERR, "Portal cache: failed to make request to %s", host);
        evhttp_request_free(down_req);
        evhttp_connection_free(evcon);
        close(ctx->fd);
        unlink(ctx->tmp_path);
        entry->state = CACHE_EMPTY;
        free(ctx);
        evhttp_uri_free(parsed_uri);
        return -1;
    }

    debug(LOG_INFO, "Portal cache async download started: %s", url);
    evhttp_uri_free(parsed_uri);
    return 0;
}

/* ---- CORS header helper: echo Origin dynamically for credentialed requests ---- */
static void
add_cors_headers(struct evhttp_request *req, struct evkeyvalq *headers)
{
    const char *origin = evhttp_find_header(evhttp_request_get_input_headers(req), "Origin");
    if (origin) {
        evhttp_add_header(headers, "Access-Control-Allow-Origin", origin);
        evhttp_add_header(headers, "Access-Control-Allow-Credentials", "true");
    } else {
        evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
    }
    evhttp_add_header(headers, "Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    evhttp_add_header(headers, "Access-Control-Allow-Headers", "*");
}

/* ---- HTTP callback: /wifidog/portal/cache/{key}?orig={base64url} ---- */
void
ev_http_callback_portal_cache(struct evhttp_request *req, void *arg)
{
    (void)arg;

    /* Handle CORS preflight */
    if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
        struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
        add_cors_headers(req, headers);
        evhttp_send_reply(req, HTTP_OK, "OK", NULL);
        return;
    }

    const char *uri = evhttp_request_get_uri(req);
    if (!uri) {
        evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
        return;
    }

    /* Extract cache key: /wifidog/portal/cache/{key} */
    const char *prefix = "/wifidog/portal/cache/";
    const char *key_start = strstr(uri, prefix);
    if (!key_start) {
        evhttp_send_error(req, HTTP_NOTFOUND, "Not Found");
        return;
    }
    key_start += strlen(prefix);

    /* Key must be exactly 64 hex chars */
    char key[PORTAL_CACHE_KEY_LEN];
    int i;
    for (i = 0; i < 64 && key_start[i] && key_start[i] != '?' && key_start[i] != '/'; i++) {
        key[i] = key_start[i];
    }
    if (i != 64) {
        evhttp_send_error(req, HTTP_NOTFOUND, "Invalid Key");
        return;
    }
    key[64] = '\0';

    /* Extract orig query parameter */
    char original_url[512] = {0};
    const char *query_string = strchr(uri, '?');
    if (query_string) {
        struct evkeyvalq params;
        evhttp_parse_query(query_string, &params);
        const char *orig_value = evhttp_find_header(&params, "orig");
        if (orig_value) {
            base64url_decode(orig_value, original_url, sizeof(original_url));
            debug(LOG_DEBUG, "Portal cache: decoded orig URL: %s", original_url);
        }
        evhttp_clear_headers(&params);
    }

    pthread_mutex_lock(&g_cache.lock);
    portal_cache_entry_t *entry = portal_cache_lookup(key);

    if (!entry || !portal_cache_is_valid(entry)) {
        /* Entry is missing, expired, or in error state */
        if (!entry || entry->state == CACHE_EMPTY || entry->state == CACHE_ERROR) {
            /* Start new download if we have original URL */
            if (original_url[0]) {
                debug(LOG_INFO, "Portal cache miss, async downloading: %s", original_url);

                char local_path[330];
                snprintf(local_path, sizeof(local_path), "%s/%s", g_cache.cache_dir, key);
                const char *content_type = portal_cache_get_content_type(original_url);

                /* Find or create cache entry */
                if (!entry) {
                    entry = find_free_entry();
                }
                if (!entry) {
                    pthread_mutex_unlock(&g_cache.lock);
                    evhttp_send_error(req, HTTP_SERVUNAVAIL, "Cache Full");
                    evhttp_request_free(req);
                    return;
                }
                /* Initialize entry for downloading */
                strncpy(entry->url, original_url, sizeof(entry->url) - 1);
                strncpy(entry->cache_key, key, sizeof(entry->cache_key) - 1);
                strncpy(entry->local_path, local_path, sizeof(entry->local_path) - 1);
                strncpy(entry->content_type, content_type, sizeof(entry->content_type) - 1);
                entry->state = CACHE_DOWNLOADING;
                entry->pending_clients = NULL;
                pthread_mutex_unlock(&g_cache.lock);

                /* Defer client response until download completes */
                evhttp_request_own(req);

                /* Start async download */
                if (portal_cache_download_async(original_url, local_path, key,
                                                content_type, entry, req) != 0) {
                    entry->state = CACHE_EMPTY;
                    evhttp_send_error(req, HTTP_NOTFOUND, "Download Failed");
                    evhttp_request_free(req);
                    return;
                }

                /* Response will be sent in download_complete_cb */
                return;
            }

            pthread_mutex_unlock(&g_cache.lock);
            evhttp_send_error(req, HTTP_NOTFOUND, "Cache Miss");
            return;
        }

        /* Entry is currently downloading - add to pending queue */
        if (entry->state == CACHE_DOWNLOADING) {
            debug(LOG_INFO, "Portal cache download in progress, queuing request for: %s", key);

            /* Create pending client node */
            pending_client_t *pc = malloc(sizeof(pending_client_t));
            if (!pc) {
                pthread_mutex_unlock(&g_cache.lock);
                evhttp_send_error(req, HTTP_SERVUNAVAIL, "No Memory");
                return;
            }
            pc->req = req;
            pc->next = entry->pending_clients;
            entry->pending_clients = pc;

            /* Defer client response until download completes */
            evhttp_request_own(req);
            pthread_mutex_unlock(&g_cache.lock);
            return;
        }

        pthread_mutex_unlock(&g_cache.lock);
        evhttp_send_error(req, HTTP_NOTFOUND, "Cache Miss");
        return;
    }

    /* Verify file still exists */
    struct stat st;
    if (stat(entry->local_path, &st) != 0) {
        pthread_mutex_unlock(&g_cache.lock);
        evhttp_send_error(req, HTTP_NOTFOUND, "File Not Found");
        return;
    }

    int fd = open(entry->local_path, O_RDONLY);
    if (fd < 0) {
        pthread_mutex_unlock(&g_cache.lock);
        evhttp_send_error(req, HTTP_SERVUNAVAIL, "Open Failed");
        return;
    }

    /* Copy content_type before unlocking */
    char content_type[64];
    strncpy(content_type, entry->content_type, sizeof(content_type) - 1);
    content_type[sizeof(content_type) - 1] = '\0';

    pthread_mutex_unlock(&g_cache.lock);

    struct evbuffer *evb = evbuffer_new();
    if (!evb) {
        close(fd);
        evhttp_send_error(req, HTTP_SERVUNAVAIL, "No Memory");
        return;
    }

    if (evbuffer_add_file(evb, fd, 0, st.st_size) < 0) {
        close(fd);
        evbuffer_free(evb);
        evhttp_send_error(req, HTTP_SERVUNAVAIL, "Internal Error");
        return;
    }

    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", content_type);
    evhttp_add_header(headers, "Cache-Control", "public, max-age=3600");
    evhttp_add_header(headers, "Connection", "close");
    add_cors_headers(req, headers);

    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
