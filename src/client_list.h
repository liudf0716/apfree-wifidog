/* vim: set et sw=4 ts=4 sts=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
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

/* $Id$ */
/** @file client_list.h
    @brief Client List functions
    @author Copyright (C) 2004 Alexandre Carmel-Veilleux <acv@acv.ca>
	@author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
*/

#ifndef _CLIENT_LIST_H_
#define _CLIENT_LIST_H_

#include "conf.h"

/** Global mutex to protect access to the client list */
extern pthread_mutex_t client_list_mutex;
extern pthread_mutex_t offline_client_list_mutex;

/** Counters struct for a client's bandwidth usage (in bytes)
 */
typedef struct _t_counters {
    unsigned long long incoming;        /**< @brief Incoming data byte total*/
	unsigned long long incoming_packets;        /**< @brief Incoming data packet total*/
    unsigned long long outgoing;        /**< @brief Outgoing data total*/
	unsigned long long outgoing_packets;        /**< @brief Outgoing data packet total*/
    unsigned long long incoming_history;        /**< @brief Incoming data before wifidog restarted*/
    unsigned long long outgoing_history;        /**< @brief Outgoing data before wifidog restarted*/
    /* Delta traffic stats by t123yh */
    unsigned long long incoming_delta;      /**< @brief Incoming data after last report*/
    unsigned long long outgoing_delta;      /**< @brief Outgoing data after last report*/
    time_t last_updated;        			/**< @brief Last update of the counters */
} t_counters;

/** Client node for the connected client linked list.
 */
typedef struct _t_client {
    struct _t_client *next;             /**< @brief Pointer to the next client */
    unsigned long long id;           	/**< @brief Unique ID per client */
    char *ip;                           /**< @brief Client address */
    char *mac;                          /**< @brief Client Mac address */
    char *token;                        /**< @brief Client token */
    int fw_connection_state;     		/**< @brief Connection state in the firewall */
	int fd;              				/**< @brief Client HTTP socket (valid only
											during login before one of the
											_http_* function is called */
    t_counters counters;                /**< @brief Counters for input/output of the client. */
	time_t 	first_login;				/**< @brief first login time */
	char	*name;						/**< @brief device name */
	short 	is_online;
	short	wired;						/** default 0: wireless */
	t_gateway_setting *gw_setting;
} t_client;

// liudf added 20160216
typedef struct _t_offline_client {
	struct _t_offline_client *next;
	char *ip;
	char *mac;
	
	time_t 	last_login;	
	time_t	first_login;
	char 	client_type; // 1 is apple;
	char 	temp_passed;
	short 	hit_counts; 
	
} t_offline_client;

struct wd_request_context;

/** @brief Get a new client struct, not added to the list yet */
t_client *client_get_new(void);

t_offline_client *offline_client_get_new(void);

/** @brief Get the first element of the list of connected clients */
t_client *client_get_first_client(void);

t_offline_client *client_get_first_offline_client(void);

/** @brief Initializes the client list */
void client_list_init(void);

void offline_client_list_init(void);

/** @brief Insert client at head of list */
void client_list_insert_client(t_client *);

void offline_client_list_insert_client(t_offline_client *);

/** @brief Destroy the client list. Including all free... */
void client_list_destroy(t_client *);

void offline_client_list_destroy(t_offline_client *);

/** @brief Adds a new client to the connections list */
t_client *client_list_add(const char *, const char *, const char *, t_gateway_setting *);

t_offline_client *offline_client_list_add(const char *, const char *);

/** Duplicate the whole client list to process in a thread safe way */
int client_list_dup(t_client **);

/** @brief Create a duplicate of a client. */
t_client *client_dup(const t_client *);

/** @brief Finds a client by its IP and MAC */
t_client *client_list_find(const char *, const char *);

/** @brief Find a client in the list from a client struct, matching operates by id. */
t_client *client_list_find_by_client(t_client *);

t_client *client_list_find_by_client_id(unsigned long long);

/** @brief Finds a client only by its IP */
t_client *client_list_find_by_ip(const char *); /* needed by fw_iptables.c, auth.c 
                                                 * and wdctl_thread.c */

/** @brief Finds a client only by its Mac */
t_client *client_list_find_by_mac(const char *);        /* needed by wdctl_thread.c */

t_offline_client *offline_client_list_find_by_mac(const char *);

/** @brief Finds a client by its token */
t_client *client_list_find_by_token(const char *);

/** @brief Deletes a client from the connections list and frees its memory*/
void client_list_delete(t_client *);

/** @brief safe client_list_delete by using lock */
void safe_client_list_delete(t_client *);

void offline_client_list_delete(t_offline_client *);

/** @brief Removes a client from the connections list */
void client_list_remove(t_client *);

void offline_client_list_remove(t_offline_client *);

/** @brief Free memory associated with a client */
void client_free_node(t_client *);

void offline_client_free_node(t_offline_client *);

int offline_client_number();

int offline_client_ageout();

void reset_client_list();

void add_online_client(const char *ip, const char *mac, json_object *roam_client);

#define LOCK_OFFLINE_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Locking offline client list"); \
	pthread_mutex_lock(&offline_client_list_mutex); \
	debug(LOG_DEBUG, "Offline client list locked"); \
} while (0)

#define UNLOCK_OFFLINE_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Unlocking offline client list"); \
	pthread_mutex_unlock(&offline_client_list_mutex); \
	debug(LOG_DEBUG, "Offline client list unlocked"); \
} while (0)

#define LOCK_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Locking client list"); \
	pthread_mutex_lock(&client_list_mutex); \
	debug(LOG_DEBUG, "Client list locked"); \
} while (0)

#define UNLOCK_CLIENT_LIST() do { \
	debug(LOG_DEBUG, "Unlocking client list"); \
	pthread_mutex_unlock(&client_list_mutex); \
	debug(LOG_DEBUG, "Client list unlocked"); \
} while (0)

#endif                          /* _CLIENT_LIST_H_ */
