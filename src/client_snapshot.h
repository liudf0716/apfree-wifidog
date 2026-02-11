#ifndef _CLIENT_SNAPSHOT_H_
#define _CLIENT_SNAPSHOT_H_

#include <stdbool.h>
#include <stdint.h>
#include "conf.h"

/**
 * @brief Save all online clients and trusted MACs to /etc/client_snapshot.json
 * @return 0 on success, -1 on error
 */
int client_snapshot_save(void);

/**
 * @brief Load online clients and trusted MACs from /etc/client_snapshot.json
 * @return 0 on success, -1 on error
 * @note This function provides internal locking
 */
int client_snapshot_load(void);

/**
 * @brief Load online clients and trusted MACs from /etc/client_snapshot.json (without locking)
 * @return 0 on success, -1 on error
 * @note This function does not provide internal locking, caller must hold LOCK_CLIENT_LIST()
 */
int __client_snapshot_load(void);

/**
 * @brief Dump client snapshot as JSON string
 * @return JSON string (caller must free)
 */
char *client_snapshot_dump_json(void);

/**
 * @brief Query status of a client (compatible with current HTTP query interface)
 */
char *client_snapshot_query_status(const char *key,
                   const char *gw_mac,
                   const char *gw_address,
                   query_choice_t choice);

/**
 * @brief Add a MAC to the trusted list in snapshot
 */
bool client_snapshot_add_trusted_mac(const char *mac, uint32_t remaining_time, const char *serial);

/**
 * @brief Remove a MAC from the trusted list in snapshot
 */
bool client_snapshot_remove_trusted_mac(const char *mac);

#endif /* _CLIENT_SNAPSHOT_H_ */
