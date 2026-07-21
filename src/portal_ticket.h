// SPDX-License-Identifier: GPL-3.0-only
/*
 * Portal Session Ticket — gateway-issued short-lived credential for portal auth.
 * Secret stays on the gateway; AWAS only transports the blob.
 */

#ifndef _PORTAL_TICKET_H_
#define _PORTAL_TICKET_H_

#include <time.h>

#define PORTAL_TICKET_TID_HEX_LEN   32  /* 16 bytes as hex */
#define PORTAL_TICKET_MAC_LEN       18
#define PORTAL_TICKET_IP_LEN        64
#define PORTAL_TICKET_ID_LEN        64
#define PORTAL_TICKET_SCOPE         "portal_auth"
#define PORTAL_TICKET_DEFAULT_TTL   100
#define PORTAL_TICKET_DEFAULT_STORE_MAX 1024
#define PORTAL_TICKET_CLOCK_SKEW    60

typedef struct portal_ticket_payload {
    int  v;
    char tid[PORTAL_TICKET_TID_HEX_LEN + 1];
    char device_id[PORTAL_TICKET_ID_LEN];
    char gw_id[PORTAL_TICKET_ID_LEN];
    char mac[PORTAL_TICKET_MAC_LEN];
    char ip[PORTAL_TICKET_IP_LEN];
    time_t iat;
    time_t exp;
    char nonce[PORTAL_TICKET_TID_HEX_LEN + 1];
    char scope[32];
} portal_ticket_payload_t;

/**
 * Initialize ticket subsystem (secret, store). Safe to call once after config_read.
 * Auto-generates an in-memory secret if none is configured.
 */
void portal_ticket_init(void);

/** Destroy store (process exit). */
void portal_ticket_cleanup(void);

/**
 * Issue a ticket for an observed LAN client.
 * @return heap-allocated portal_ticket blob (caller frees), or NULL on failure
 */
char *portal_ticket_issue(const char *device_id, const char *gw_id,
                          const char *mac, const char *ip);

/**
 * Verify signature + exp + scope + local store consistency.
 * Does NOT mark used.
 * @return 0 on success, -1 on failure
 */
int portal_ticket_verify(const char *ticket_blob, portal_ticket_payload_t *out);

/**
 * Mark tid consumed (single-use). Returns 0 if first consume, -1 if unknown/already used.
 */
int portal_ticket_consume(const char *tid);

/** Normalize MAC to lowercase aa:bb:cc:dd:ee:ff form; returns 0 on success. */
int portal_ticket_normalize_mac(const char *in, char *out, size_t out_len);

#endif /* _PORTAL_TICKET_H_ */
