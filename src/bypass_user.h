#ifndef _BYPASS_USER_H_
#define _BYPASS_USER_H_

#include <stdint.h>
#include <stdbool.h>

typedef enum mac_choice_t_ {
	TRUSTED_MAC,
	UNTRUSTED_MAC,
	TRUSTED_LOCAL_MAC,
	ROAM_MAC
} mac_choice_t;

typedef enum {
    QUERY_BY_IP,
    QUERY_BY_MAC,
} query_choice_t;

/**
 * Trusted MAC Addresses
 */
typedef struct _trusted_mac_t {
	struct _trusted_mac_t *next;
    char 	*mac;
	char 	*ip;
	char 	*serial;
	uint32_t 	is_online;
	uint32_t 	remaining_time;
} t_trusted_mac;

typedef t_trusted_mac t_untrusted_mac;

void remove_mac_from_list(const char *, mac_choice_t );
t_trusted_mac *add_mac_from_list(const char *, const uint32_t , const char *, mac_choice_t which);

bool add_bypass_user(const char *, const uint32_t , const char *);
bool remove_bypass_user(const char *);
char *dump_bypass_user_list_json();
char *query_bypass_user_status(const char *, const char *, const char *, query_choice_t choice);
void save_bypass_user_list();
void load_bypass_user_list();

#endif