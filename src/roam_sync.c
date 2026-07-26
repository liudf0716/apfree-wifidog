#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <json-c/json.h>

#include "debug.h"
#include "roam_sync.h"
#include "client_list.h"
#include "firewall.h"
#include "mqtt_thread.h"

static t_roam_table g_roam_table;

static unsigned char hash_mac(const char *mac) {
    unsigned int hash = 0;
    while (*mac) {
        hash = (hash * 31) + (*mac == ':' ? 0 : *mac);
        mac++;
    }
    return (unsigned char)(hash % 256);
}

void roam_sync_init(void) {
    memset(&g_roam_table, 0, sizeof(g_roam_table));
    pthread_rwlock_init(&g_roam_table.rwlock, NULL);
    debug(LOG_INFO, "Roaming sync module initialized");
}

void roam_sync_cleanup(void) {
    roam_cache_clear();
    pthread_rwlock_destroy(&g_roam_table.rwlock);
    debug(LOG_INFO, "Roaming sync module cleaned up");
}

void roam_sync_set_venue_id(const char *venue_id) {
    if (!venue_id) return;
    pthread_rwlock_wrlock(&g_roam_table.rwlock);
    snprintf(g_roam_table.venue_id, sizeof(g_roam_table.venue_id), "%s", venue_id);
    pthread_rwlock_unlock(&g_roam_table.rwlock);
    mqtt_subscribe_venue_topic(venue_id);
    debug(LOG_INFO, "Roaming venue_id set to: %s", venue_id);
}

void roam_sync_get_venue_id(char *out_buf, size_t max_len) {
    if (!out_buf || max_len == 0) return;
    pthread_rwlock_rdlock(&g_roam_table.rwlock);
    snprintf(out_buf, max_len, "%s", g_roam_table.venue_id);
    pthread_rwlock_unlock(&g_roam_table.rwlock);
}

void roam_cache_purge_expired(void) {
    uint64_t now = (uint64_t)time(NULL);
    pthread_rwlock_wrlock(&g_roam_table.rwlock);
    for (int i = 0; i < 256; i++) {
        t_roam_cache_entry *curr = g_roam_table.buckets[i];
        t_roam_cache_entry *prev = NULL;
        while (curr) {
            if (curr->expire_at <= now) {
                t_roam_cache_entry *to_free = curr;
                if (prev) {
                    prev->next = curr->next;
                    curr = curr->next;
                } else {
                    g_roam_table.buckets[i] = curr->next;
                    curr = curr->next;
                }
                debug(LOG_DEBUG, "Purged expired roam cache entry: %s", to_free->mac);
                free(to_free);
            } else {
                prev = curr;
                curr = curr->next;
            }
        }
    }
    pthread_rwlock_unlock(&g_roam_table.rwlock);
}

int roam_cache_lookup(const char *mac, t_roam_cache_entry *out_entry) {
    if (!mac) return 0;

    unsigned char idx = hash_mac(mac);
    uint64_t now = (uint64_t)time(NULL);
    int found = 0;

    pthread_rwlock_rdlock(&g_roam_table.rwlock);
    t_roam_cache_entry *curr = g_roam_table.buckets[idx];
    while (curr) {
        if (strcasecmp(curr->mac, mac) == 0) {
            if (curr->expire_at > now) {
                if (out_entry) {
                    memcpy(out_entry, curr, sizeof(t_roam_cache_entry));
                }
                found = 1;
            } else {
                debug(LOG_DEBUG, "Roaming cache entry for %s expired", mac);
            }
            break;
        }
        curr = curr->next;
    }
    pthread_rwlock_unlock(&g_roam_table.rwlock);

    return found;
}

void roam_cache_add(const char *mac, const char *token, uint64_t expire_at) {
    if (!mac) return;
    unsigned char idx = hash_mac(mac);

    pthread_rwlock_wrlock(&g_roam_table.rwlock);
    t_roam_cache_entry *curr = g_roam_table.buckets[idx];
    while (curr) {
        if (strcasecmp(curr->mac, mac) == 0) {
            if (token) snprintf(curr->token, sizeof(curr->token), "%s", token);
            curr->expire_at = expire_at;
            curr->is_active = 1;
            pthread_rwlock_unlock(&g_roam_table.rwlock);
            debug(LOG_INFO, "Updated roaming cache entry: %s, expire_at: %llu", mac, (unsigned long long)expire_at);
            return;
        }
        curr = curr->next;
    }

    t_roam_cache_entry *new_node = malloc(sizeof(t_roam_cache_entry));
    if (!new_node) {
        pthread_rwlock_unlock(&g_roam_table.rwlock);
        debug(LOG_ERR, "Failed to allocate memory for roam cache node");
        return;
    }

    memset(new_node, 0, sizeof(t_roam_cache_entry));
    snprintf(new_node->mac, sizeof(new_node->mac), "%s", mac);
    if (token) snprintf(new_node->token, sizeof(new_node->token), "%s", token);
    new_node->expire_at = expire_at;
    new_node->is_active = 1;
    new_node->next = g_roam_table.buckets[idx];
    g_roam_table.buckets[idx] = new_node;

    pthread_rwlock_unlock(&g_roam_table.rwlock);
    debug(LOG_INFO, "Added new roaming cache entry: %s, expire_at: %llu", mac, (unsigned long long)expire_at);
}

void roam_cache_del(const char *mac) {
    if (!mac) return;
    unsigned char idx = hash_mac(mac);

    pthread_rwlock_wrlock(&g_roam_table.rwlock);
    t_roam_cache_entry *curr = g_roam_table.buckets[idx];
    t_roam_cache_entry *prev = NULL;

    while (curr) {
        if (strcasecmp(curr->mac, mac) == 0) {
            if (prev) {
                prev->next = curr->next;
            } else {
                g_roam_table.buckets[idx] = curr->next;
            }
            free(curr);
            pthread_rwlock_unlock(&g_roam_table.rwlock);
            debug(LOG_INFO, "Deleted roaming cache entry: %s", mac);
            return;
        }
        prev = curr;
        curr = curr->next;
    }
    pthread_rwlock_unlock(&g_roam_table.rwlock);
}

void roam_cache_clear(void) {
    pthread_rwlock_wrlock(&g_roam_table.rwlock);
    for (int i = 0; i < 256; i++) {
        t_roam_cache_entry *curr = g_roam_table.buckets[i];
        while (curr) {
            t_roam_cache_entry *tmp = curr;
            curr = curr->next;
            free(tmp);
        }
        g_roam_table.buckets[i] = NULL;
    }
    pthread_rwlock_unlock(&g_roam_table.rwlock);
    debug(LOG_INFO, "Cleared all roaming cache entries");
}

void roam_sync_dispatch_event(const char *json_raw) {
    if (!json_raw) return;

    json_object *jobj = json_tokener_parse(json_raw);
    if (!jobj) {
        debug(LOG_ERR, "roam_sync_dispatch_event: Failed to parse JSON");
        return;
    }

    json_object *jobj_event = NULL;
    if (!json_object_object_get_ex(jobj, "event", &jobj_event)) {
        json_object_put(jobj);
        return;
    }

    const char *event = json_object_get_string(jobj_event);
    if (!event) {
        json_object_put(jobj);
        return;
    }

    if (strcmp(event, "AUTH_ADD") == 0) {
        json_object *j_mac = NULL, *j_token = NULL, *j_exp = NULL;
        json_object_object_get_ex(jobj, "mac", &j_mac);
        json_object_object_get_ex(jobj, "token", &j_token);
        json_object_object_get_ex(jobj, "expire_at", &j_exp);

        if (j_mac) {
            const char *mac_str = json_object_get_string(j_mac);
            const char *token_str = j_token ? json_object_get_string(j_token) : "";
            uint64_t exp = j_exp ? (uint64_t)json_object_get_int64(j_exp) : 0;
            roam_cache_add(mac_str, token_str, exp);
        }
    } else if (strcmp(event, "AUTH_DEL") == 0) {
        json_object *j_mac = NULL;
        json_object_object_get_ex(jobj, "mac", &j_mac);
        if (j_mac) {
            const char *mac_str = json_object_get_string(j_mac);
            roam_cache_del(mac_str);
            
            // Delete from client list if present
            LOCK_CLIENT_LIST();
            t_client *client = client_list_find_by_mac(mac_str);
            if (client) {
                fw_deny(client);
                client_list_delete(client);
            }
            UNLOCK_CLIENT_LIST();
        }
    } else if (strcmp(event, "AUTH_UPDATE") == 0) {
        json_object *j_mac = NULL, *j_exp = NULL;
        json_object_object_get_ex(jobj, "mac", &j_mac);
        json_object_object_get_ex(jobj, "new_expire_at", &j_exp);
        if (j_mac && j_exp) {
            const char *mac_str = json_object_get_string(j_mac);
            uint64_t new_exp = (uint64_t)json_object_get_int64(j_exp);
            t_roam_cache_entry entry;
            if (roam_cache_lookup(mac_str, &entry)) {
                roam_cache_add(mac_str, entry.token, new_exp);
            }
        }
    } else if (strcmp(event, "ROAM_SNAPSHOT_SYNC") == 0) {
        json_object *j_clients = NULL;
        if (json_object_object_get_ex(jobj, "clients", &j_clients) && json_object_get_type(j_clients) == json_type_array) {
            int len = json_object_array_length(j_clients);
            roam_cache_clear();
            for (int i = 0; i < len; i++) {
                json_object *item = json_object_array_get_idx(j_clients, i);
                json_object *j_mac = NULL, *j_token = NULL, *j_exp = NULL;
                json_object_object_get_ex(item, "mac", &j_mac);
                json_object_object_get_ex(item, "token", &j_token);
                json_object_object_get_ex(item, "expire_at", &j_exp);
                if (j_mac) {
                    const char *mac_str = json_object_get_string(j_mac);
                    const char *token_str = j_token ? json_object_get_string(j_token) : "";
                    uint64_t exp = j_exp ? (uint64_t)json_object_get_int64(j_exp) : 0;
                    roam_cache_add(mac_str, token_str, exp);
                }
            }
            debug(LOG_INFO, "Applied roaming snapshot sync with %d entries", len);
        }
    } else if (strcmp(event, "CONFIG_UPDATE") == 0) {
        json_object *j_venue = NULL;
        if (json_object_object_get_ex(jobj, "venue_id", &j_venue)) {
            roam_sync_set_venue_id(json_object_get_string(j_venue));
        }
    }

    json_object_put(jobj);
}
