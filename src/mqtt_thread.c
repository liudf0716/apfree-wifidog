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
/** @file mqtt_thread.c
  @brief 
  @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
  
  */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>

#include <mosquitto.h>
#include <json-c/json.h>

#include "mqtt_thread.h"
#include "wdctl_thread.h"
#include "conf.h"
#include "debug.h"
#include "safe.h"

static void
send_mqtt_response(struct mosquitto *mosq, const unsigned int req_id, int res_id, const char *msg, const s_config *config)
{
	char *topic = NULL;
	char *res_data = NULL;
	safe_asprintf(&topic, "wifidog/%s/response/%d", config->gw_id, req_id);
	safe_asprintf(&res_data, "{response:\"%d\",msg:\"%s\"}", res_id, msg==NULL?"null":msg);
	mosquitto_publish(mosq, NULL, topic, strlen(res_data), res_data, 0, false);
	free(topic);
	free(res_data);
}

void 
set_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	if (!type || !value) {
		debug(LOG_INFO, "set trusted operation, type or value is NULL");	
		send_mqtt_response(mosq, req_id, 400, "type or value is NULL", config);
		return;
	}

	for(int i = 0; mqtt_set_type[i].type != NULL; i++) {
		if (strcmp(mqtt_set_type[i].type, type) == 0) {
			debug(LOG_DEBUG, "set trusted operation, type is %s value is %s", type, value);
			mqtt_set_type[i].process_mqtt_set_type(value);
			send_mqtt_response(mosq, req_id, 200, "Ok", config);
			break;
		}	
	}
}

void 
del_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	if (!type || !value) {
		debug(LOG_INFO, "del trusted operation, type or value is NULL");	
		send_mqtt_response(mosq, req_id, 400, "type or value is NULL", config);
		return;
	}

	for(int i = 0; mqtt_del_type[i].type != NULL; i++) {
		if (strcmp(mqtt_del_type[i].type, type) == 0) {
			debug(LOG_DEBUG, "del trusted operation, type is %s value is %s", type, value);
			mqtt_del_type[i].process_mqtt_del_type(value);
			send_mqtt_response(mosq, req_id, 200, "Ok", config);
			break;
		}	
	}
}

void 
clear_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	if (!type) {
		debug(LOG_INFO, "clear trusted operaion, type is NULL");
		send_mqtt_response(mosq, req_id, 400, "type is NULL", config);
		return;
	}

	for(int i = 0; mqtt_clear_type[i].type != NULL; i++) {
		if (strcmp(mqtt_clear_type[i].type, type) == 0) {
			debug(LOG_DEBUG, "clear trusted operation, type is %s", type);
			mqtt_clear_type[i].process_mqtt_clear_type();
			send_mqtt_response(mosq, req_id, 200, "Ok", config);
			break;
		}	
	}
}

void 
show_trusted_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	if (!type) {
		debug(LOG_INFO, "show trusted operaion, type is NULL");
		send_mqtt_response(mosq, req_id, 400, "type is NULL", config);
		return;
	}

	for(int i = 0; mqtt_show_type[i].type != NULL; i++) {
		if (strcmp(mqtt_show_type[i].type, type) == 0) {
			debug(LOG_DEBUG, "show trusted operation, type is %s", type);
			char *msg = mqtt_show_type[i].process_mqtt_show_type();
			send_mqtt_response(mosq, req_id, 200, msg, config);
			if (msg)
				free(msg);
			break;
		}	
	}
}

void 
save_rule_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	user_cfg_save();
	send_mqtt_response(mosq, req_id, 200, "Ok", config);
}

void 
get_status_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{

}

void 
reboot_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	system("reboot");
}

static void
process_mqtt_reqeust(struct mosquitto *mosq, const unsigned int req_id, const char *data, s_config *config)
{
	json_object *json_request = json_tokener_parse(data);
	if (!json_request) {
		debug(LOG_INFO, "user request is not valid");
		return;
	}

	const char *op = json_object_get_string(json_object_object_get(json_request, "op"));
	if (!op) {
		debug(LOG_INFO, "No op item get");
		return;
	}

	int i = 0;
	for (; mqtt_op[i].operation != NULL; i++) {
		if (strcmp(op, mqtt_op[i].operation) == 0 && mqtt_op[i].process_mqtt_op) {
			const char *type = json_object_get_string(json_object_object_get(json_request, "type"));
			const char *value = json_object_get_string(json_object_object_get(json_request, "value"));
			mqtt_op[i].process_mqtt_op(mosq, type, value, req_id, config);
			break;
		}
	}
}

static unsigned int
get_topic_req_id(const char *topic)
{
	char *pos = rindex(topic, '/');
	if (!pos || strlen(pos++) < 2)
		return 0;

	return (int)strtol(pos, NULL, 10);
}

static void 
mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	s_config *config = obj;

	if (message->payloadlen) {
		debug(LOG_DEBUG, "topic is %s, data is %s", message->topic, message->payload);
		unsigned int req_id = get_topic_req_id(message->topic);
		if (req_id) {
			process_mqtt_reqeust(mosq, req_id, message->payload, config);
		}
		else 
			debug(LOG_INFO, "error: can not get req_id");
	}
}

static void
mqtt_connect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	s_config 		*config = obj;

	char *default_topic = NULL;
	safe_asprintf(&default_topic, "wifidog/%s/request/+", config->gw_id);
	mosquitto_subscribe(mosq, NULL, default_topic, 0); // qos is 0
	free(default_topic);
}

void thread_mqtt(void *arg)
{
	s_config *config = arg;
	int major = 0, minor = 0, revision = 0;
	struct mosquitto *mosq = NULL;
	char *host 	= config->mqtt_server->hostname;
	int  port 	= config->mqtt_server->port;
	char *cafile = config->mqtt_server->cafile;
	int  keepalive = 60;
	int  retval = 0;

 	mosquitto_lib_version(&major, &minor, &revision);
    debug(LOG_DEBUG, "Mosquitto library version : %d.%d.%d\n", major, minor, revision); 

    /* Init mosquitto library */
    mosquitto_lib_init();

     /* Create a new mosquitto client instance */
    mosq = mosquitto_new(config->gw_id, true, config);
    if( mosq == NULL ) {
        switch(errno){
            case ENOMEM:
                debug(LOG_INFO, "Error: Out of memory.\n");
                break;
            case EINVAL:
                debug(LOG_INFO, "Error: Invalid id and/or clean_session.\n");
                break;
        }
        mosquitto_lib_cleanup();
        return ;
    }
   	
   	if (mosquitto_tls_set(mosq, cafile, NULL, NULL, NULL, NULL)) {
   		debug(LOG_INFO, "Error : Problem setting TLS option");
    	mosquitto_destroy(mosq);
    	mosquitto_lib_cleanup();
        return ;
   	}

   	// Attention! this setting is not secure, but can simplify our deploy
    if (mosquitto_tls_insecure_set(mosq, true)) {
    	debug(LOG_INFO, "Error : Problem setting TLS insecure option");
    	mosquitto_destroy(mosq);
    	mosquitto_lib_cleanup();
        return ;
    }

    mosquitto_connect_callback_set(mosq, mqtt_connect_callback);
    mosquitto_message_callback_set(mosq, mqtt_message_callback);

   	switch( retval = mosquitto_connect(mosq, host, port, keepalive) ) {
        case MOSQ_ERR_INVAL:
            debug(LOG_INFO, "Error : %s\n", mosquitto_strerror(retval)); 
            break;
        case MOSQ_ERR_ERRNO:
            debug(LOG_INFO, "Error : %s\n", strerror(errno));
            break;

        mosquitto_destroy(mosq);
     	mosquitto_lib_cleanup();
        return ;
    }

    retval = mosquitto_loop_forever(mosq, -1, 1);

    mosquitto_destroy(mosq);
    mosquitto_lib_cleanup();
}