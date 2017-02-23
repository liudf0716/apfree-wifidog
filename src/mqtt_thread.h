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
/** @file mqtt_thread.h
  @brief 
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
  
  */
#ifndef	_MQTT_THREAD_H_
#define	_MQTT_THREAD_H_

#include "wdctl_thread.h"

void set_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void del_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void clear_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void show_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void save_rule_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void get_status_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void reboot_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);

struct wifidog_mqtt_op {
	char	*operation,
	void	(*process_mqtt_op)(void *mosq, int type, const char *value, const int req_id, const s_config *config)
} mqtt_op [] = {
	{"set_trusted", set_trusted_op},
	{"del_trusted", del_trusted_op},
	{"clear_trusted", clear_trusted_op},
	{"show_trusted", show_trusted_op},
	{"save_rule", save_rule_op},
	{"get_status", get_status_op},
	{"reboot", reboot_device_op},
	{NULL, NULL}
};

struct wifidog_mqtt_add_type {
	char 	*type,
	void	(*process_mqtt_set_type)(const char *args)
} mqtt_set_type [] = {
	{"domain", add_trusted_domains},
	{"pdomain", add_trusted_pdomains},
	{"ip", add_trusted_iplist},
	{"mac", add_trusted_maclist},
	{NULL, NULL}
};

struct wifidog_mqtt_del_type {
	char 	*type,
	void	(*process_mqtt_del_type)(const char *args)
} mqtt_del_type [] = {
	{"domain", del_trusted_domains},
	{"pdomain", del_trusted_pdomains},
	{"ip", del_trusted_iplist},
	{"mac", del_trusted_maclist},
	{NULL, NULL}
};

struct wifidog_mqtt_clear_type {
	char	*type,
	void	(*process_mqtt_clear_type)(void)
} mqtt_clear_type [] = {
	{"domain", clear_trusted_domains},
	{"pdomain", clear_trusted_pdomains},
	{"ip", clear_trusted_iplist},
	{"mac", clear_trusted_maclist},
	{NULL, NULL}
};

struct wifidog_mqtt_show_type {
	char	*type,
	void	(*process_mqtt_show_type)(void)
} mqtt_show_type [] = {
	{"domain", show_trusted_domains},
	{"pdomains", show_trusted_pdomains},
	{"ip", show_trusted_iplist},
	{"mac", show_trusted_maclist},
	{NULL, NULL}
};

void thread_mqtt(void *arg);

#endif