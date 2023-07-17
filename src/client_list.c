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

/** @file client_list.c
  @brief Client List Functions
  @author Copyright (C) 2004 Alexandre Carmel-Veillex <acv@acv.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE

#include "common.h"
#include "safe.h"
#include "debug.h"
#include "conf.h"
#include "client_list.h"
#include "firewall.h"
#include "util.h"
#include "centralserver.h"

/** @internal
 * Holds a pointer to the first element of the list 
 */
static t_client *firstclient = NULL;

// liudf added 20160216
static t_offline_client *first_offline_client = NULL;

/** @internal
 * Client ID
 */
static volatile unsigned long long client_id = 1;

/**
 * Mutex to protect client_id and guarantee uniqueness.
 */
static pthread_mutex_t client_id_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Global mutex to protect access to the client list */
pthread_mutex_t client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

// liudf added 20160216
pthread_mutex_t offline_client_list_mutex = PTHREAD_MUTEX_INITIALIZER;

/** Get a new client struct, not added to the list yet
 * @return Pointer to newly created client object not on the list yet.
 */
t_client *
client_get_new(void)
{
    t_client *client;
    client = safe_malloc(sizeof(t_client));
	client->wired = -1; // not get state
    return client;
}

// liudf added 20160216
t_offline_client *
offline_client_get_new(void)
{
	t_offline_client *client;
	client = safe_malloc(sizeof(t_offline_client));
	return client;
}

/** Get the first element of the list of connected clients
 */
t_client *
client_get_first_client(void)
{
    return firstclient;
}

// liudf added 20160216
t_offline_client *
client_get_first_offline_client(void)
{
	return first_offline_client;
}

/**
 * Initializes the list of connected clients (client)
 */
void
client_list_init(void)
{
    firstclient = NULL;
}

// liudf added 20160216
void
offline_client_list_init(void)
{
	first_offline_client = NULL;
}

/** Insert client at head of list. Lock should be held when calling this!
 * @param Pointer to t_client object.
 */
void
client_list_insert_client(t_client * client)
{
    t_client *prev_head;

    pthread_mutex_lock(&client_id_mutex);
    client->id = client_id++;
    pthread_mutex_unlock(&client_id_mutex);

    prev_head = firstclient;
    client->next = prev_head;
    firstclient = client;
}

// liudf added 20160216
// before use this api, must lock offline_client_list
void
offline_client_list_insert_client(t_offline_client *client)
{
	t_offline_client *prev_head;

	prev_head = first_offline_client;
	client->next = prev_head;
	first_offline_client = client;
}

/** Based on the parameters it receives, this function creates a new entry
 * in the connections list. All the memory allocation is done here.
 * Client is inserted at the head of the list.
 * @param ip IP address
 * @param mac MAC address
 * @param token Token
 * @return Pointer to the client we just created
 * 
 */
t_client *
client_list_add(const char *ip, const char *mac, const char *token)
{
    t_client *curclient;  

    curclient = client_get_new();

    curclient->ip = safe_strdup(ip);
    curclient->mac = safe_strdup(mac);
    curclient->token = safe_strdup(token);
    curclient->counters.incoming_delta = curclient->counters.outgoing_delta = 
            curclient->counters.incoming = curclient->counters.incoming_history = curclient->counters.outgoing =
        curclient->counters.outgoing_history = 0;
    curclient->counters.last_updated = time(NULL);

    client_list_insert_client(curclient);

    debug(LOG_INFO, "Added a new client to linked list: IP: %s Token: %s", ip, token);

    return curclient;
}


// liudf added 201602016
t_offline_client *
offline_client_list_add(const char *ip, const char *mac)
{
	t_offline_client *curclient;
	
    curclient = offline_client_get_new();

    curclient->ip 			= safe_strdup(ip);
    curclient->mac 			= safe_strdup(mac);
	curclient->last_login 	= time(NULL);
	curclient->first_login 	= time(NULL);
	curclient->client_type 	= 0;
	curclient->hit_counts 	= 0;
	curclient->temp_passed 	= 0;

	offline_client_list_insert_client(curclient);
	
    debug(LOG_INFO, "Added a new offline client to linked list: IP: %s Mac: %s", ip, mac);
	return curclient;
}

/** 
 * @brief Duplicate the whole client list to process in a thread safe way
 * MUTEX MUST BE HELD.
 * @param dest pointer TO A POINTER to a t_client (i.e.: t_client **ptr)
 * @return int Number of clients copied
 */
int
client_list_dup(t_client ** dest)
{
    t_client *new, *cur, *top, *prev;
    int copied = 0;

    cur = firstclient;
    new = top = prev = NULL;

    if (NULL == cur) {
        *dest = new;            /* NULL */
        return copied;
    }

    while (NULL != cur) {
        new = client_dup(cur);
        if (NULL == top) {
            /* first item */
            top = new;
        } else {
            prev->next = new;
        }
        prev = new;
        copied++;
        cur = cur->next;
    }

    *dest = top;
    return copied;
}

/** Create a duplicate of a client.
 * @param src Original client
 * @return duplicate client object with next == NULL
 */
t_client *
client_dup(const t_client * src)
{
    t_client *new = NULL;
    
    if (NULL == src) {
        return NULL;
    }
    
    new = client_get_new();

    new->id = src->id;
    new->ip = safe_strdup(src->ip);
    new->mac = safe_strdup(src->mac);
    new->token = safe_strdup(src->token);
	new->fw_connection_state = src->fw_connection_state;
    new->counters.incoming = src->counters.incoming;
    new->counters.incoming_history = src->counters.incoming_history;
    new->counters.incoming_delta = src->counters.incoming_delta;
    new->counters.outgoing = src->counters.outgoing;
    new->counters.outgoing_history = src->counters.outgoing_history;
    new->counters.outgoing_delta = src->counters.outgoing_delta;
    new->counters.last_updated = src->counters.last_updated;
	
	// liudf added 20160128
	if(src->name)
		new->name = safe_strdup(src->name);
	new->first_login = src->first_login;
	new->is_online = src->is_online;
	new->wired	= src->wired;
    new->next = NULL;

    return new;
}

/**
 * @brief find client by client's id
 * 
 */ 
t_client *
client_list_find_by_client_id(unsigned long long id)
{
    t_client *c = firstclient;

    while (NULL != c) {
        if (c->id == id) {
            return c;
        }
        c = c->next;
    }
    return NULL;
}

/** Find a client in the list from a client struct, matching operates by id.
 * This is useful from a copy of client to find the original.
 * @param client Client to find
 * @return pointer to the client in the list.
 */
t_client *
client_list_find_by_client(t_client * client)
{
    t_client *c = firstclient;

    while (NULL != c) {
        if (c->id == client->id) {
            return c;
        }
        c = c->next;
    }
    return NULL;
}

/** Finds a  client by its IP and MAC, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @param mac MAC we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find(const char *ip, const char *mac)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip) && 0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/**
 * Finds a  client by its IP, returns NULL if the client could not
 * be found
 * @param ip IP we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_ip(const char *ip)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->ip, ip))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}


/**
 * Finds a  client by its Mac, returns NULL if the client could not
 * be found
 * @param mac Mac we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_mac(const char *mac)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->mac, mac))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

// liudf added 20160216
t_offline_client *
offline_client_list_find_by_mac(const char *mac)
{
	t_offline_client *ptr;
	
	ptr = first_offline_client;
	while(NULL != ptr) {
		if(0 == strcmp(ptr->mac, mac)) {
			return ptr;
		}
		ptr = ptr->next;
	}
	return NULL;
}

/** Finds a client by its token
 * @param token Token we are looking for in the linked list
 * @return Pointer to the client, or NULL if not found
 */
t_client *
client_list_find_by_token(const char *token)
{
    t_client *ptr;

    ptr = firstclient;
    while (NULL != ptr) {
        if (0 == strcmp(ptr->token, token))
            return ptr;
        ptr = ptr->next;
    }

    return NULL;
}

/** Destroy the client list. Including all free...
 * DOES NOT UPDATE firstclient or anything else.
 * @param list List to destroy (first item)
 */
void
client_list_destroy(t_client * list)
{
    t_client *next;

    while (NULL != list) {
        next = list->next;
        client_free_node(list);
        list = next;
    }
}

// liudf added 20160216
void
offline_client_list_destroy(t_offline_client *list)
{
	t_offline_client *next;

	while(list) {
		next = list->next;
		offline_client_free_node(list);
		list = next;
	}
}
/** @internal
 * @brief Frees the memory used by a t_client structure
 * This function frees the memory used by the t_client structure in the
 * proper order.
 * @param client Points to the client to be freed
 */
void
client_free_node(t_client * client)
{
    if(!client) return;
    if(client->mac) free(client->mac);
    if(client->ip) free(client->ip);
    if(client->token) free(client->token);
	if (client->name) free(client->name);
    free(client);
}

// liudf added 20160216
void
offline_client_free_node(t_offline_client *client)
{
    if(!client) return;
	if(client->ip) free(client->ip);
	if(client->mac) free(client->mac);
	free(client);
}

int 
offline_client_number()
{
	int number = 0;
	t_offline_client *ptr = first_offline_client;
	while(ptr) {
		ptr = ptr->next;
		number++;
	}
	return number;
}

/**
 * @brief safely remove and delete ageout clients from offline clients list
 * 
 */ 
int 
offline_client_ageout()
{
	time_t cur_time = time(NULL);
	int number = 0;
	
	debug(LOG_DEBUG, "offline_client_ageout !");
	LOCK_OFFLINE_CLIENT_LIST();	
	t_offline_client *ptr = first_offline_client;
	while(ptr) {
		int idle_time = cur_time - ptr->last_login;
		if(idle_time > 60) { //if 1 minutes stay idle
			t_offline_client *ptmp = ptr;
			ptr = ptr->next;
			offline_client_list_delete(ptmp);
			// maybe we should block it from route
		} else  {
			ptr = ptr->next;
			number++;
		}
	}
	UNLOCK_OFFLINE_CLIENT_LIST();
	return number;
}


/**
 * @brief Deletes a client from the connections list
 *
 * Removes the specified client from the connections list and then calls
 * the function to free the memory used by the client.
 * @param client Points to the client to be deleted
 */
void
client_list_delete(t_client *client)
{
    client_list_remove(client);
    client_free_node(client);
}

/**
 * @brief safe delete client from the connections list
 * 
 */ 
void
safe_client_list_delete(t_client *client)
{
    LOCK_CLIENT_LIST();
    client_list_delete(client);
    UNLOCK_CLIENT_LIST();
}

/**
 * @brief unsafely remove client from offline clients list and free the client
 * 
 */ 
void
offline_client_list_delete(t_offline_client *client)
{
	offline_client_list_remove(client);
	offline_client_free_node(client);
}

/**
 * @brief unsafely remove client from offline clients list
 * 
 */ 
void
offline_client_list_remove(t_offline_client *client)
{
	t_offline_client *ptr = first_offline_client;
	
	if(!ptr) {
		debug(LOG_ERR, "Node offline list empty!");
	} else if (ptr == client) {
		first_offline_client = ptr->next;
	} else {
		/* Loop forward until we reach our point in the list. */
        while (ptr->next != NULL && ptr->next != client) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        } else {
            ptr->next = client->next;
        }

	}
}
/**
 * @brief Removes a client from the connections list
 *
 * @param client Points to the client to be deleted
 */
void
client_list_remove(t_client * client)
{
    t_client *ptr = firstclient;
    if (ptr == NULL) {
        debug(LOG_ERR, "Node list empty!");
    } else if (ptr == client) {
        firstclient = ptr->next;
    } else {
        /* Loop forward until we reach our point in the list. */
        while (ptr->next && ptr->next != client) {
            ptr = ptr->next;
        }
        /* If we reach the end before finding out element, complain. */
        if (ptr->next == NULL) {
            debug(LOG_ERR, "Node to delete could not be found.");
        } else {
            ptr->next = client->next;
        }
    }
}

/**
 * @brief set all connected clients to offline status
 * 
 */ 
void
reset_client_list()
{
    t_client *ptr = firstclient;
    while (ptr) {
		ptr->is_online = 0;
        ptr = ptr->next;
    }
}

/*
 * brief: according to auth server's roam response, safely adding client to connect list
 * The roam_client  json like this:
 * {"token":"client_token", "firstLogin":"first login time"}
 * 
 * @param roam_client The response json data from auth server
 * 
 */
void  
add_online_client(const char *ip, const char *mac, json_object *client)
{
	
    LOCK_CLIENT_LIST();

    t_client *old_client = client_list_find_by_mac(mac);
    if(!old_client) { // no such client in connect list
        json_object *token_jo 		= NULL;
        json_object *first_login_jo = NULL;
        const char *token 		= NULL;
        int first_login;

        if (!json_object_object_get_ex(client, "token", &token_jo)) {
            UNLOCK_CLIENT_LIST();
            return;
        } else 
            token = json_object_get_string(token_jo);

        if (!json_object_object_get_ex(client, "firstLogin", &first_login_jo)) {
            UNLOCK_CLIENT_LIST();
            return;
        } else
            first_login = json_object_get_int(first_login_jo);

        if(token) {
            t_client *client = client_list_add(ip, mac, token);
            client->wired = 0;

            if (first_login) {
                client->first_login = first_login;
            } else {
                client->first_login = time(NULL);
            }
            fw_allow(client, FW_MARK_KNOWN);
        }
    } else if (strcmp(old_client->ip, ip) != 0) { // The client has logined; but its ip changed
        fw_deny(old_client);
        free(old_client->ip);
        old_client->ip = safe_strdup(ip);
        fw_allow(old_client, FW_MARK_KNOWN);
    }

    UNLOCK_CLIENT_LIST();

}
