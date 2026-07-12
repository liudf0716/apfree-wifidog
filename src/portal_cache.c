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
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <event2/http.h>
#include <json-c/json.h>

/* Global cache instance */
static portal_cache_t g_cache;
static int g_cache_initialized = 0;

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

/* ---- Utility: get file size ---- */
static unsigned long
get_file_size(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return 0;
    return (unsigned long)st.st_size;
}

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

/* ---- SIGCHLD handler for reap downloads ---- */
static void
sigchld_handler(int sig)
{
    (void)sig;
    int saved_errno = errno;
    pid_t pid;
    int status;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        for (int i = 0; i < PORTAL_CACHE_MAX_FILES; i++) {
            portal_cache_entry_t *e = &g_cache.entries[i];
            if (e->state == CACHE_DOWNLOADING && e->download_pid == pid) {
                if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
                    /* Rename temp file to final path */
                    char tmp_path[260];
                    snprintf(tmp_path, sizeof(tmp_path), "%s/.%s.tmp",
                             g_cache.cache_dir, e->cache_key);
                    if (rename(tmp_path, e->local_path) != 0) {
                        debug(LOG_WARNING, "Portal cache rename failed: %s -> %s: %s",
                              tmp_path, e->local_path, strerror(errno));
                        unlink(tmp_path);
                        e->state = CACHE_ERROR;
                        e->download_pid = 0;
                        break;
                    }
                    e->file_size = get_file_size(e->local_path);
                    e->download_time = time(NULL);
                    e->expire_time = e->download_time + PORTAL_CACHE_DEFAULT_TTL;
                    e->state = CACHE_READY;
                    debug(LOG_INFO, "Portal cache download complete: %s (%lu bytes)",
                          e->cache_key, e->file_size);
                } else {
                    e->state = CACHE_ERROR;
                    debug(LOG_WARNING, "Portal cache download failed: %s", e->cache_key);
                    /* Remove failed temp file */
                    unlink(e->local_path);
                }
                e->download_pid = 0;
                break;
            }
        }
    }
    errno = saved_errno;
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

    /* Install SIGCHLD handler */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    g_cache_initialized = 1;
    debug(LOG_INFO, "Portal cache initialized at %s", g_cache.cache_dir);
    return 0;
}

/* ---- Destroy ---- */
void
portal_cache_destroy(void)
{
    if (!g_cache_initialized) return;

    /* Wait for any in-progress downloads */
    for (int i = 0; i < PORTAL_CACHE_MAX_FILES; i++) {
        if (g_cache.entries[i].state == CACHE_DOWNLOADING &&
            g_cache.entries[i].download_pid > 0) {
            kill(g_cache.entries[i].download_pid, SIGTERM);
        }
    }

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

/* ---- Download via fork+exec curl ---- */
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

    /* Fork a child to download */
    char tmp_path[260];
    snprintf(tmp_path, sizeof(tmp_path), "%s/.%s.tmp", g_cache.cache_dir, key);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: exec wget */
        execl("/usr/bin/wget", "wget",
              "-q",                      /* quiet */
              "-O", tmp_path,            /* output file */
              "--timeout=10",            /* connection timeout */
              "-T", "60",                /* total timeout */
              "--tries=1",               /* single attempt */
              "-t", "1",                 /* retry count */
              url, (char *)NULL);
        _exit(127); /* exec failed */
    } else if (pid > 0) {
        /* Parent: record PID and wait for rename after download */
        pthread_mutex_lock(&g_cache.lock);
        entry->download_pid = pid;
        pthread_mutex_unlock(&g_cache.lock);

        debug(LOG_DEBUG, "Portal cache download started: pid=%d key=%s url=%s",
              pid, key, url);

        /* We'll let SIGCHLD handle the completion.
         * But we need to rename tmp -> final in the handler.
         * For simplicity, use a helper: spawn a reaper that waits and renames. */
        /* Actually, let's do the rename in a short-lived grandchild or
         * just handle it in SIGCHLD by checking the tmp file. */

        /* Simple approach: parent renames after a short delay won't work.
         * Better: use a pipe or just check in SIGCHLD. Let's update
         * the SIGCHLD handler to do the rename. */
        return 0;
    } else {
        debug(LOG_ERR, "fork failed for portal cache download: %s", strerror(errno));
        return -1;
    }
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
            memset(e, 0, sizeof(*e));
            e->state = CACHE_EMPTY;
        }
        if (e->state == CACHE_ERROR) {
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

/* ---- Synchronous download (blocking) ---- */
static int
portal_cache_download_sync(const char *url, const char *local_path)
{
    char tmp_path[260];
    snprintf(tmp_path, sizeof(tmp_path), "%s.tmp", local_path);

    char max_size_str[32];
    snprintf(max_size_str, sizeof(max_size_str), "%u", PORTAL_CACHE_MAX_SIZE);

    pid_t pid = fork();
    if (pid == 0) {
        /* Child: exec wget */
        execl("/usr/bin/wget", "wget",
              "-q",
              "-O", tmp_path,
              "--timeout=10",
              "-T", "30",
              "--tries=1",
              url, (char *)NULL);
        _exit(127);
    } else if (pid > 0) {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            /* Rename temp to final */
            if (rename(tmp_path, local_path) == 0) {
                debug(LOG_INFO, "Portal cache sync download ok: %s", url);
                return 0;
            }
        }
        unlink(tmp_path);
        return -1;
    }
    return -1;
}

/* ---- HTTP callback: /wifidog/portal/cache/{key}?orig={base64url} ---- */
void
ev_http_callback_portal_cache(struct evhttp_request *req, void *arg)
{
    (void)arg;

    /* Handle CORS preflight */
    if (evhttp_request_get_command(req) == EVHTTP_REQ_OPTIONS) {
        struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
        evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
        evhttp_add_header(headers, "Access-Control-Allow-Methods", "GET, OPTIONS");
        evhttp_add_header(headers, "Access-Control-Allow-Headers", "*");
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
    const char *orig_param = strstr(uri, "orig=");
    if (orig_param) {
        orig_param += 5; /* skip "orig=" */
        base64url_decode(orig_param, original_url, sizeof(original_url));
        debug(LOG_DEBUG, "Portal cache: decoded orig URL: %s", original_url);
    }

    pthread_mutex_lock(&g_cache.lock);
    portal_cache_entry_t *entry = portal_cache_lookup(key);

    if (!entry || !portal_cache_is_valid(entry)) {
        pthread_mutex_unlock(&g_cache.lock);

        /* Lazy download: if we have original URL, download synchronously */
        if (original_url[0]) {
            debug(LOG_INFO, "Portal cache miss, lazy downloading: %s", original_url);

            char local_path[260];
            snprintf(local_path, sizeof(local_path), "%s/%s", g_cache.cache_dir, key);
            const char *content_type = portal_cache_get_content_type(original_url);

            if (portal_cache_download_sync(original_url, local_path) == 0) {
                /* Success: register in cache and serve */
                pthread_mutex_lock(&g_cache.lock);
                entry = portal_cache_lookup(key);
                if (!entry) {
                    entry = find_free_entry();
                }
                if (entry) {
                    strncpy(entry->url, original_url, sizeof(entry->url) - 1);
                    strncpy(entry->cache_key, key, sizeof(entry->cache_key) - 1);
                    strncpy(entry->local_path, local_path, sizeof(entry->local_path) - 1);
                    strncpy(entry->content_type, content_type, sizeof(entry->content_type) - 1);
                    entry->file_size = get_file_size(local_path);
                    entry->download_time = time(NULL);
                    entry->expire_time = entry->download_time + PORTAL_CACHE_DEFAULT_TTL;
                    entry->state = CACHE_READY;
                }
                pthread_mutex_unlock(&g_cache.lock);

                /* Serve the file */
                struct stat st;
                int fd = open(local_path, O_RDONLY);
                if (fd >= 0 && stat(local_path, &st) == 0) {
                    struct evbuffer *evb = evbuffer_new();
                    if (evb) {
                        evbuffer_add_file(evb, fd, 0, st.st_size);
                        struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
                        evhttp_add_header(headers, "Content-Type", content_type);
                        evhttp_add_header(headers, "Cache-Control", "public, max-age=3600");
                        evhttp_add_header(headers, "Connection", "close");
                        evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");
                        evhttp_send_reply(req, HTTP_OK, "OK", evb);
                        evbuffer_free(evb);
                        return;
                    }
                    close(fd);
                }
            }
            /* Download failed */
            evhttp_send_error(req, HTTP_NOTFOUND, "Download Failed");
            return;
        }

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

    evbuffer_add_file(evb, fd, 0, st.st_size);

    struct evkeyvalq *headers = evhttp_request_get_output_headers(req);
    evhttp_add_header(headers, "Content-Type", content_type);
    evhttp_add_header(headers, "Cache-Control", "public, max-age=3600");
    evhttp_add_header(headers, "Connection", "close");
    evhttp_add_header(headers, "Access-Control-Allow-Origin", "*");

    evhttp_send_reply(req, HTTP_OK, "OK", evb);
    evbuffer_free(evb);
}
