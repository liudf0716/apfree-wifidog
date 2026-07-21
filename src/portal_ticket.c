// SPDX-License-Identifier: GPL-3.0-only
/*
 * Portal Session Ticket implementation (HMAC-SHA256).
 * Wire format: base64url(payload_json) + "." + base64url(hmac_sha256)
 */

#include "common.h"
#include "debug.h"
#include "safe.h"
#include "conf.h"
#include "portal_ticket.h"

#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <ctype.h>
#include <pthread.h>

#define SECRET_MAX 64

typedef struct portal_ticket_entry {
    char tid[PORTAL_TICKET_TID_HEX_LEN + 1];
    char mac[PORTAL_TICKET_MAC_LEN];
    char ip[PORTAL_TICKET_IP_LEN];
    time_t exp;
    int used;
    struct portal_ticket_entry *next;
} portal_ticket_entry_t;

static unsigned char s_secret[SECRET_MAX];
static size_t s_secret_len = 0;
static int s_inited = 0;
static portal_ticket_entry_t *s_store = NULL;
static int s_store_count = 0;
static pthread_mutex_t s_lock = PTHREAD_MUTEX_INITIALIZER;

static const char b64url_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static char *
b64url_encode(const unsigned char *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = safe_malloc(out_len + 1);
    size_t i, j = 0;
    for (i = 0; i < len; i += 3) {
        unsigned int n = ((unsigned int)data[i]) << 16;
        if (i + 1 < len) n |= ((unsigned int)data[i + 1]) << 8;
        if (i + 2 < len) n |= (unsigned int)data[i + 2];
        out[j++] = b64url_table[(n >> 18) & 63];
        out[j++] = b64url_table[(n >> 12) & 63];
        out[j++] = (i + 1 < len) ? b64url_table[(n >> 6) & 63] : '=';
        out[j++] = (i + 2 < len) ? b64url_table[n & 63] : '=';
    }
    /* strip padding for base64url */
    while (j > 0 && out[j - 1] == '=')
        j--;
    out[j] = '\0';
    return out;
}

static int
b64url_decode_char(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '-') return 62;
    if (c == '_') return 63;
    return -1;
}

static unsigned char *
b64url_decode(const char *in, size_t *out_len)
{
    size_t in_len = strlen(in);
    size_t pad = (4 - (in_len % 4)) % 4;
    size_t full_len = in_len + pad;
    char *tmp = safe_malloc(full_len + 1);
    size_t i, j = 0;
    unsigned char *out;

    memcpy(tmp, in, in_len);
    for (i = 0; i < pad; i++)
        tmp[in_len + i] = '=';
    tmp[full_len] = '\0';

    out = safe_malloc(full_len);
    for (i = 0; i < full_len; i += 4) {
        int a = b64url_decode_char(tmp[i]);
        int b = b64url_decode_char(tmp[i + 1]);
        int c = (tmp[i + 2] == '=') ? 0 : b64url_decode_char(tmp[i + 2]);
        int d = (tmp[i + 3] == '=') ? 0 : b64url_decode_char(tmp[i + 3]);
        if (a < 0 || b < 0 || (tmp[i + 2] != '=' && c < 0) || (tmp[i + 3] != '=' && d < 0)) {
            free(tmp);
            free(out);
            return NULL;
        }
        unsigned int n = ((unsigned int)a << 18) | ((unsigned int)b << 12) |
                         ((unsigned int)c << 6) | (unsigned int)d;
        out[j++] = (n >> 16) & 0xff;
        if (tmp[i + 2] != '=')
            out[j++] = (n >> 8) & 0xff;
        if (tmp[i + 3] != '=')
            out[j++] = n & 0xff;
    }
    free(tmp);
    *out_len = j;
    return out;
}

static void
bytes_to_hex(const unsigned char *in, size_t len, char *out)
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < len; i++) {
        out[i * 2] = hex[(in[i] >> 4) & 0xf];
        out[i * 2 + 1] = hex[in[i] & 0xf];
    }
    out[len * 2] = '\0';
}

static int
hex_to_bytes(const char *hex, unsigned char *out, size_t out_max, size_t *out_len)
{
    size_t n = strlen(hex);
    size_t i;
    if (n == 0 || (n % 2) != 0 || n / 2 > out_max)
        return -1;
    for (i = 0; i < n / 2; i++) {
        unsigned int v;
        if (sscanf(hex + i * 2, "%2x", &v) != 1)
            return -1;
        out[i] = (unsigned char)v;
    }
    *out_len = n / 2;
    return 0;
}

int
portal_ticket_normalize_mac(const char *in, char *out, size_t out_len)
{
    char raw[13];
    int n = 0;
    size_t i;

    if (!in || !out || out_len < 18)
        return -1;

    for (i = 0; in[i] && n < 12; i++) {
        char c = (char)tolower((unsigned char)in[i]);
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))
            raw[n++] = c;
    }
    if (n != 12)
        return -1;
    raw[12] = '\0';
    snprintf(out, out_len, "%c%c:%c%c:%c%c:%c%c:%c%c:%c%c",
             raw[0], raw[1], raw[2], raw[3], raw[4], raw[5],
             raw[6], raw[7], raw[8], raw[9], raw[10], raw[11]);
    return 0;
}

static void
store_gc_locked(time_t now)
{
    portal_ticket_entry_t **pp = &s_store;
    while (*pp) {
        portal_ticket_entry_t *e = *pp;
        if (e->exp + PORTAL_TICKET_CLOCK_SKEW < now || e->used) {
            *pp = e->next;
            free(e);
            s_store_count--;
        } else {
            pp = &e->next;
        }
    }
}

static portal_ticket_entry_t *
store_find_locked(const char *tid)
{
    portal_ticket_entry_t *e;
    for (e = s_store; e; e = e->next) {
        if (strcmp(e->tid, tid) == 0)
            return e;
    }
    return NULL;
}

static char *
hmac_b64url(const char *msg)
{
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    if (!HMAC(EVP_sha256(), s_secret, (int)s_secret_len,
              (const unsigned char *)msg, strlen(msg), md, &md_len))
        return NULL;
    return b64url_encode(md, md_len);
}

static int
str_ieq(const char *a, const char *b)
{
    if (!a || !b)
        return 0;
    while (*a && *b) {
        if (tolower((unsigned char)*a) != tolower((unsigned char)*b))
            return 0;
        a++;
        b++;
    }
    return *a == '\0' && *b == '\0';
}

void
portal_ticket_init(void)
{
    s_config *cfg = config_get_config();
    unsigned char rnd[32];

    pthread_mutex_lock(&s_lock);
    if (s_inited) {
        pthread_mutex_unlock(&s_lock);
        return;
    }

    memset(s_secret, 0, sizeof(s_secret));
    s_secret_len = 0;

    if (cfg && cfg->portal_ticket_secret && cfg->portal_ticket_secret[0]) {
        if (hex_to_bytes(cfg->portal_ticket_secret, s_secret, sizeof(s_secret), &s_secret_len) != 0) {
            /* treat as raw string secret */
            size_t n = strlen(cfg->portal_ticket_secret);
            if (n > sizeof(s_secret))
                n = sizeof(s_secret);
            memcpy(s_secret, cfg->portal_ticket_secret, n);
            s_secret_len = n;
        }
    }

    if (s_secret_len < 16) {
        if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
            /* weak fallback */
            size_t i;
            for (i = 0; i < sizeof(rnd); i++)
                rnd[i] = (unsigned char)(rand() & 0xff);
        }
        memcpy(s_secret, rnd, sizeof(rnd));
        s_secret_len = sizeof(rnd);
        debug(LOG_INFO, "portal_ticket: auto-generated in-memory HMAC secret");
    } else {
        debug(LOG_INFO, "portal_ticket: using configured secret (%zu bytes)", s_secret_len);
    }

    s_inited = 1;
    pthread_mutex_unlock(&s_lock);
}

void
portal_ticket_cleanup(void)
{
    portal_ticket_entry_t *e;

    pthread_mutex_lock(&s_lock);
    while (s_store) {
        e = s_store;
        s_store = e->next;
        free(e);
    }
    s_store_count = 0;
    s_inited = 0;
    s_secret_len = 0;
    pthread_mutex_unlock(&s_lock);
}

char *
portal_ticket_issue(const char *device_id, const char *gw_id,
                    const char *mac, const char *ip)
{
    unsigned char tid_raw[16], nonce_raw[16];
    char tid_hex[PORTAL_TICKET_TID_HEX_LEN + 1];
    char nonce_hex[PORTAL_TICKET_TID_HEX_LEN + 1];
    char mac_n[PORTAL_TICKET_MAC_LEN];
    char payload[512];
    char *payload_b64 = NULL;
    char *sig_b64 = NULL;
    char *blob = NULL;
    portal_ticket_entry_t *entry;
    time_t now, exp;
    int ttl;
    s_config *cfg;

    if (!s_inited)
        portal_ticket_init();

    if (!device_id || !gw_id || !mac || !ip)
        return NULL;

    if (portal_ticket_normalize_mac(mac, mac_n, sizeof(mac_n)) != 0) {
        debug(LOG_ERR, "portal_ticket: invalid mac %s", mac);
        return NULL;
    }

    cfg = config_get_config();
    ttl = (cfg && cfg->portal_ticket_ttl > 0) ? cfg->portal_ticket_ttl : PORTAL_TICKET_DEFAULT_TTL;
    now = time(NULL);
    exp = now + ttl;

    if (RAND_bytes(tid_raw, sizeof(tid_raw)) != 1 ||
        RAND_bytes(nonce_raw, sizeof(nonce_raw)) != 1) {
        debug(LOG_ERR, "portal_ticket: RAND_bytes failed");
        return NULL;
    }
    bytes_to_hex(tid_raw, sizeof(tid_raw), tid_hex);
    bytes_to_hex(nonce_raw, sizeof(nonce_raw), nonce_hex);

    /* compact JSON payload (order fixed for readability) */
    snprintf(payload, sizeof(payload),
             "{\"v\":1,\"tid\":\"%s\",\"device_id\":\"%s\",\"gw_id\":\"%s\","
             "\"mac\":\"%s\",\"ip\":\"%s\",\"iat\":%ld,\"exp\":%ld,"
             "\"nonce\":\"%s\",\"scope\":\"%s\"}",
             tid_hex, device_id, gw_id, mac_n, ip,
             (long)now, (long)exp, nonce_hex, PORTAL_TICKET_SCOPE);

    payload_b64 = b64url_encode((const unsigned char *)payload, strlen(payload));
    if (!payload_b64)
        return NULL;

    sig_b64 = hmac_b64url(payload_b64);
    if (!sig_b64) {
        free(payload_b64);
        return NULL;
    }

    safe_asprintf(&blob, "%s.%s", payload_b64, sig_b64);
    free(payload_b64);
    free(sig_b64);
    if (!blob)
        return NULL;

    entry = safe_malloc(sizeof(*entry));
    memset(entry, 0, sizeof(*entry));
    snprintf(entry->tid, sizeof(entry->tid), "%s", tid_hex);
    snprintf(entry->mac, sizeof(entry->mac), "%s", mac_n);
    snprintf(entry->ip, sizeof(entry->ip), "%s", ip);
    entry->exp = exp;
    entry->used = 0;

    {
        int store_max = PORTAL_TICKET_DEFAULT_STORE_MAX;
        if (cfg && cfg->portal_ticket_store_max >= 16)
            store_max = cfg->portal_ticket_store_max;

        pthread_mutex_lock(&s_lock);
        store_gc_locked(now);
        while (s_store_count >= store_max) {
            /* drop oldest-ish: head of list */
            portal_ticket_entry_t *old = s_store;
            if (!old)
                break;
            s_store = old->next;
            free(old);
            s_store_count--;
        }
    }
    entry->next = s_store;
    s_store = entry;
    s_store_count++;
    pthread_mutex_unlock(&s_lock);

    debug(LOG_INFO, "PORTAL_TICKET_ISSUE tid=%s mac=%s ip=%s exp=%ld",
          tid_hex, mac_n, ip, (long)exp);
    return blob;
}

static int
parse_payload_json(const char *json, portal_ticket_payload_t *out)
{
    json_object *j = json_tokener_parse(json);
    json_object *v;
    const char *s;

    if (!j)
        return -1;
    memset(out, 0, sizeof(*out));

    if (!json_object_object_get_ex(j, "v", &v))
        goto fail;
    out->v = json_object_get_int(v);

    if (!json_object_object_get_ex(j, "tid", &v) || !(s = json_object_get_string(v)))
        goto fail;
    snprintf(out->tid, sizeof(out->tid), "%s", s);

    if (!json_object_object_get_ex(j, "device_id", &v) || !(s = json_object_get_string(v)))
        goto fail;
    snprintf(out->device_id, sizeof(out->device_id), "%s", s);

    if (!json_object_object_get_ex(j, "gw_id", &v) || !(s = json_object_get_string(v)))
        goto fail;
    snprintf(out->gw_id, sizeof(out->gw_id), "%s", s);

    if (!json_object_object_get_ex(j, "mac", &v) || !(s = json_object_get_string(v)))
        goto fail;
    if (portal_ticket_normalize_mac(s, out->mac, sizeof(out->mac)) != 0)
        goto fail;

    if (!json_object_object_get_ex(j, "ip", &v) || !(s = json_object_get_string(v)))
        goto fail;
    snprintf(out->ip, sizeof(out->ip), "%s", s);

    if (!json_object_object_get_ex(j, "iat", &v))
        goto fail;
    out->iat = (time_t)json_object_get_int64(v);

    if (!json_object_object_get_ex(j, "exp", &v))
        goto fail;
    out->exp = (time_t)json_object_get_int64(v);

    if (json_object_object_get_ex(j, "nonce", &v) && (s = json_object_get_string(v)))
        snprintf(out->nonce, sizeof(out->nonce), "%s", s);

    if (json_object_object_get_ex(j, "scope", &v) && (s = json_object_get_string(v)))
        snprintf(out->scope, sizeof(out->scope), "%s", s);
    else
        snprintf(out->scope, sizeof(out->scope), "%s", PORTAL_TICKET_SCOPE);

    json_object_put(j);
    return 0;
fail:
    json_object_put(j);
    return -1;
}

int
portal_ticket_verify(const char *ticket_blob, portal_ticket_payload_t *out)
{
    char *dot;
    char *payload_b64 = NULL;
    const char *sig_part;
    char *expect_sig = NULL;
    portal_ticket_payload_t payload;
    portal_ticket_entry_t *e;
    time_t now;
    s_config *cfg;
    const char *local_device_id;

    if (!s_inited)
        portal_ticket_init();

    if (!ticket_blob || !out)
        return -1;

    dot = strchr(ticket_blob, '.');
    if (!dot || dot == ticket_blob || *(dot + 1) == '\0') {
        debug(LOG_WARNING, "AUTH_REJECT bad ticket format");
        return -1;
    }

    {
        size_t plen = (size_t)(dot - ticket_blob);
        payload_b64 = safe_malloc(plen + 1);
        memcpy(payload_b64, ticket_blob, plen);
        payload_b64[plen] = '\0';
    }
    sig_part = dot + 1;

    expect_sig = hmac_b64url(payload_b64);
    if (!expect_sig || strcmp(expect_sig, sig_part) != 0) {
        debug(LOG_WARNING, "AUTH_REJECT bad ticket signature");
        free(payload_b64);
        free(expect_sig);
        return -1;
    }
    free(expect_sig);

    {
        unsigned char *payload_raw;
        size_t payload_len;
        char *json;
        payload_raw = b64url_decode(payload_b64, &payload_len);
        free(payload_b64);
        if (!payload_raw)
            return -1;
        json = safe_malloc(payload_len + 1);
        memcpy(json, payload_raw, payload_len);
        json[payload_len] = '\0';
        free(payload_raw);
        if (parse_payload_json(json, &payload) != 0) {
            free(json);
            debug(LOG_WARNING, "AUTH_REJECT ticket payload parse failed");
            return -1;
        }
        free(json);
    }

    now = time(NULL);
    if (payload.exp + PORTAL_TICKET_CLOCK_SKEW < now) {
        debug(LOG_WARNING, "AUTH_REJECT ticket expired tid=%s", payload.tid);
        return -1;
    }
    if (strcmp(payload.scope, PORTAL_TICKET_SCOPE) != 0) {
        debug(LOG_WARNING, "AUTH_REJECT bad scope");
        return -1;
    }
    if (payload.v != 1) {
        debug(LOG_WARNING, "AUTH_REJECT unsupported ticket version %d", payload.v);
        return -1;
    }

    cfg = config_get_config();
    local_device_id = get_device_id();
    if (local_device_id && !str_ieq(payload.device_id, local_device_id)) {
        debug(LOG_WARNING, "AUTH_REJECT device_id mismatch ticket=%s local=%s",
              payload.device_id, local_device_id);
        return -1;
    }

    pthread_mutex_lock(&s_lock);
    store_gc_locked(now);
    e = store_find_locked(payload.tid);
    if (!e) {
        pthread_mutex_unlock(&s_lock);
        debug(LOG_WARNING, "AUTH_REJECT unknown tid=%s (restarted or forged)", payload.tid);
        return -1;
    }
    if (e->used) {
        pthread_mutex_unlock(&s_lock);
        debug(LOG_WARNING, "AUTH_REJECT tid already used tid=%s", payload.tid);
        return -1;
    }
    if (strcmp(e->mac, payload.mac) != 0) {
        pthread_mutex_unlock(&s_lock);
        debug(LOG_WARNING, "AUTH_REJECT store mac mismatch");
        return -1;
    }
    pthread_mutex_unlock(&s_lock);

    /* optional strict IP: checked by caller with ARP */
    (void)cfg;
    *out = payload;
    return 0;
}

int
portal_ticket_consume(const char *tid)
{
    portal_ticket_entry_t *e;
    int rc = -1;

    if (!tid)
        return -1;

    pthread_mutex_lock(&s_lock);
    e = store_find_locked(tid);
    if (e && !e->used) {
        e->used = 1;
        rc = 0;
        debug(LOG_INFO, "AUTH_CONSUME tid=%s mac=%s", e->tid, e->mac);
    }
    pthread_mutex_unlock(&s_lock);
    return rc;
}
