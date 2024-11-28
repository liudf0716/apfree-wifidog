#include "common.h"
#include "conf.h"
#include "debug.h"
#include "safe.h"
#include "util.h"
#include "bypass_user.h"

void
remove_mac_from_list(const char *mac, mac_choice_t which)
{
    s_config *config = config_get_config();
	t_trusted_mac *p = NULL, *p1 = NULL;
	switch(which) {
	case TRUSTED_MAC:
		p = config->trustedmaclist;
		p1 = p;
		break;
	case UNTRUSTED_MAC:
		p = config->mac_blacklist;
		p1 = p;
		break;
	case TRUSTED_LOCAL_MAC:
		p = config->trusted_local_maclist;
		p1 = p;
		break;
	case ROAM_MAC:
		p = config->roam_maclist;
		p1 = p;
		break;
	default:
		return;
	}
	
	if (p == NULL) {
		return;
	}
	
	debug(LOG_DEBUG, "Remove MAC address [%s] to  mac list [%d]", mac, which);
	
	LOCK_CONFIG();

	while(p) {
		if(strcmp(p->mac, mac) == 0) {
			break;
		}
		p1 = p;
		p = p->next;
	}

	if(p) {
		switch(which) {
		case TRUSTED_MAC:
			if(p == config->trustedmaclist)
				config->trustedmaclist = p->next;
			else
				p1->next = p->next;
			break;
		case UNTRUSTED_MAC:
			if(p == config->mac_blacklist)
				config->mac_blacklist = p->next;
			else
				p1->next = p->next;
			break;
		case TRUSTED_LOCAL_MAC:
			if(p == config->trusted_local_maclist)
				config->trusted_local_maclist = p->next;
			else
				p1->next = p->next;
			break;
		case ROAM_MAC:
			if(p == config->roam_maclist)
				config->roam_maclist = p->next;
			else
				p1->next = p->next;
			break;
		}	
		free(p->mac);
		if(p->ip) free(p->ip);
		free(p);
	}

	UNLOCK_CONFIG();
}

t_trusted_mac *
add_mac_from_list(const char *mac, const uint16_t remaining_time, const char *serial, mac_choice_t which)
{
    s_config *config = config_get_config();
	t_trusted_mac *pret = NULL, *p = NULL;

	debug(LOG_DEBUG, "Adding MAC address [%s] to  mac list [%d]", mac, which);

	LOCK_CONFIG();

	switch (which) {
	case TRUSTED_MAC:
		if (config->trustedmaclist == NULL) {
			config->trustedmaclist = safe_malloc(sizeof(t_trusted_mac));
			config->trustedmaclist->mac = safe_strdup(mac);
			config->trustedmaclist->remaining_time = remaining_time?remaining_time:UINT16_MAX;
			config->trustedmaclist->serial = serial?safe_strdup(serial):NULL;
			config->trustedmaclist->next = NULL;
			pret = config->trustedmaclist;
			UNLOCK_CONFIG();
			return pret;
		} else {
			p = config->trustedmaclist;
		}
		break;
	case UNTRUSTED_MAC:
		if (config->mac_blacklist == NULL) {
			config->mac_blacklist = safe_malloc(sizeof(t_untrusted_mac));
			config->mac_blacklist->mac = safe_strdup(mac);
			config->mac_blacklist->next = NULL;
			UNLOCK_CONFIG();
			return pret;
		} else {
			p = config->mac_blacklist;
		}
		break;
	case TRUSTED_LOCAL_MAC:
		if (config->trusted_local_maclist == NULL) {
			config->trusted_local_maclist = safe_malloc(sizeof(t_trusted_mac));
			config->trusted_local_maclist->mac = safe_strdup(mac);
			config->trusted_local_maclist->next = NULL;
			pret = config->trusted_local_maclist;
			UNLOCK_CONFIG();
			return pret;
		} else {
			p = config->trusted_local_maclist;
		}
		break;
	case ROAM_MAC: //deprecated
		break;
	}
	
	
	int skipmac;
	/* Advance to the last entry */
	skipmac = 0;
	while (p != NULL) {
		if (0 == strcmp(p->mac, mac)) {
			skipmac = 1;
		}
		p = p->next;
	}
	if (!skipmac) {
		p = safe_malloc(sizeof(t_trusted_mac));
		p->mac = safe_strdup(mac);
		p->remaining_time = remaining_time?remaining_time:UINT16_MAX;
		p->serial = serial?safe_strdup(serial):NULL;
		switch (which) {
		case TRUSTED_MAC:
			p->next = config->trustedmaclist;
			config->trustedmaclist = p;
			pret = p;
			break;
		case UNTRUSTED_MAC:
			p->next = config->mac_blacklist;
			config->mac_blacklist = p;
			pret = p;
			break;
		case TRUSTED_LOCAL_MAC:
			p->next = config->trusted_local_maclist;
			config->trusted_local_maclist = p;
			pret = p;
			break;
		case ROAM_MAC: //deprecated
			break;
		}
		
	} else {
		debug(LOG_ERR,
			"MAC address [%s] already on mac list.  ",
			mac);
	}

	UNLOCK_CONFIG();
	return pret;
}

bool
add_bypass_user(const char *mac, const uint16_t remaining_time, const char *serial)
{
	if (mac == NULL || !is_valid_mac(mac) || serial == NULL) {
		return false;
	}
	if (add_mac_from_list(mac, remaining_time, serial, TRUSTED_MAC) == NULL) {
		return false;
	}

	return true;
}

bool
remove_bypass_user(const char *mac)
{
	if (mac == NULL || !is_valid_mac(mac)) {
		return false;
	}
	
	remove_mac_from_list(mac, TRUSTED_MAC);
	return true;
}