#ifndef _ROAM_SYNC_H_
#define _ROAM_SYNC_H_

#include <stdint.h>
#include <time.h>
#include <pthread.h>

#define MAX_MAC_LEN 18
#define MAX_TOKEN_LEN 64

typedef struct _roam_cache_entry {
    char mac[MAX_MAC_LEN];
    char token[MAX_TOKEN_LEN];
    uint64_t expire_at;
    int is_active;
    struct _roam_cache_entry *next;
} t_roam_cache_entry;

typedef struct {
    t_roam_cache_entry *buckets[256];
    pthread_rwlock_t rwlock;
    int enabled;
    char venue_id[64];
} t_roam_table;

void roam_sync_init(void);
void roam_sync_cleanup(void);

void roam_sync_set_enabled(int enabled);
int roam_sync_is_enabled(void);
void roam_sync_set_venue_id(const char *venue_id);
void roam_sync_get_venue_id(char *out_buf, size_t max_len);

void roam_sync_dispatch_event(const char *json_raw);

int roam_cache_lookup(const char *mac, t_roam_cache_entry *out_entry);
void roam_cache_add(const char *mac, const char *token, uint64_t expire_at);
void roam_cache_del(const char *mac);
void roam_cache_clear(void);
void roam_cache_purge_expired(void);

#endif /* _ROAM_SYNC_H_ */
