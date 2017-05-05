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

#define _MQTT_SUPPORT_
#ifdef  _MQTT_SUPPORT_

#include "wdctl_thread.h"
#include "conf.h"

void set_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void del_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void clear_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void show_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void save_rule_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void get_status_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void reboot_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void reset_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);
void set_auth_server_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config);

void thread_mqtt(void *arg);
#else
#endif

#endif
