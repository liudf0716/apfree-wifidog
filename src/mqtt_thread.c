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
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
  
  */

#include "common.h"
#include "mqtt_thread.h"
#include "wdctl_thread.h"
#include "conf.h"
#include "debug.h"
#include "safe.h"
#include "wd_util.h"
#include "centralserver.h"

#ifdef	_MQTT_SUPPORT_

static struct wifidog_mqtt_op {
	char	*operation;
	void	(*process_mqtt_op)(void *, const char *, const char *, const int , const s_config *);
} mqtt_op[] = {
	{"set_trusted", set_trusted_op},
	{"del_trusted", del_trusted_op},
	{"clear_trusted", clear_trusted_op},
	{"show_trusted", show_trusted_op},
	{"save_rule", save_rule_op},
	{"get_status", get_status_op},
	{"reboot", reboot_device_op},
	{"reset", reset_device_op},
	{"set_auth_serv",set_auth_server_op},
	{NULL, NULL}
};

static struct wifidog_mqtt_add_type {
	char 	*type;
	void	(*process_mqtt_set_type)(const char *args);
} mqtt_set_type[] = {
	{"domain", add_trusted_domains},
	{"pdomain", add_trusted_pdomains},
	{"ip", add_trusted_iplist},
	{"mac", add_trusted_maclist},
	{NULL, NULL}
};

static struct wifidog_mqtt_del_type {
	char 	*type;
	void	(*process_mqtt_del_type)(const char *args);
} mqtt_del_type[] = {
	{"domain", del_trusted_domains},
	{"pdomain", del_trusted_pdomains},
	{"ip", del_trusted_iplist},
	{"mac", del_trusted_maclist},
	{NULL, NULL}
};

static struct wifidog_mqtt_clear_type {
	char	*type;
	void	(*process_mqtt_clear_type)(void);
} mqtt_clear_type[] = {
	{"domain", clear_trusted_domains},
	{"pdomain", clear_trusted_pdomains},
	{"ip", clear_trusted_iplist},
	{"mac", clear_trusted_maclist},
	{NULL, NULL}
};

static struct wifidog_mqtt_show_type {
	char	*type;
	char 	*(*process_mqtt_show_type)(void);
} mqtt_show_type[] = {
	{"domain", show_trusted_domains},
	{"pdomain", show_trusted_pdomains},
	{"ip", show_trusted_iplist},
	{"mac", show_trusted_maclist},
	{NULL, NULL}
};

static void
send_mqtt_response(struct mosquitto *mosq, const unsigned int req_id, int res_id, const char *msg, const s_config *config)
{
	char *topic = NULL;
	char *res_data = NULL;
	safe_asprintf(&topic, "wifidog/%s/response/%d", config->gw_id, req_id);
	safe_asprintf(&res_data, "{\"response\":\"%d\",\"msg\":\"%s\"}", res_id, msg==NULL?"null":msg);
	debug(LOG_DEBUG, "send mqtt response: topic is %s msg is %s", topic, res_data);
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
	char *status = mqtt_get_status_text();
	send_mqtt_response(mosq, req_id, 200, status, config);
	if (status)
		free(status);
}

void 
reboot_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	system("reboot");
}

void
reset_device_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	t_client *p = NULL;
	
	debug(LOG_DEBUG, "value is %s and type is %s received from mqtt",value,type);
 
	if(strcmp(type,"ip") == 0) {
		LOCK_CLIENT_LIST();
		p = client_list_find_by_ip(value);
	}
	else if(strcmp(type,"mac") == 0) {
		LOCK_CLIENT_LIST();
		p = client_list_find_by_mac(value);
	}else {
		return;
	}	

	if (p != NULL)  {
		logout_client(p);
		UNLOCK_CLIENT_LIST();
		send_mqtt_response(mosq, req_id, 200, "Ok", config);
	} else {
		UNLOCK_CLIENT_LIST();
	}
}

void
set_auth_server_op(void *mosq, const char *type, const char *value, const int req_id, const s_config *config)
{
	char * hostname = config->auth_servers->authserv_hostname;
	char * path = config->auth_servers->authserv_path;
	char * tmp_host_name = NULL;
	char * tmp_http_port = NULL;
	char * tmp_path = NULL;
		
	debug(LOG_DEBUG, "value is %s\n", value);
	json_object *json_request = json_tokener_parse(value);
	if (is_error(json_request)) {
		debug(LOG_INFO, "user request is not valid");
		return;
	}

	json_object * jo_host_name = json_object_object_get(json_request, "hostname");
	if(jo_host_name == NULL) {
		debug(LOG_DEBUG, "parse host_name is null");
	} else {
		tmp_host_name = json_object_get_string(jo_host_name);
	}

	json_object * jo_http_port = json_object_object_get(json_request, "port");
	if(jo_http_port == NULL) {
		debug(LOG_DEBUG, "parse http_port is null");
	} else {
		tmp_http_port = json_object_get_string(jo_http_port);
	}

	json_object * jo_path = json_object_object_get(json_request, "path");
	if(jo_path == NULL) {
		debug(LOG_DEBUG, "parse auth server path is null");
	} else {
		tmp_path = json_object_get_string(jo_path);
	}

	debug(LOG_DEBUG, "tmp_host_name is %s, tmp_http_port is %s, tmp_path is %s", tmp_host_name, tmp_http_port,tmp_path);

	LOCK_CONFIG();
	if((tmp_host_name != NULL) && (strcmp(hostname,tmp_host_name) != 0)) {
		free(hostname);
		config->auth_servers->authserv_hostname = safe_strdup(tmp_host_name);
        uci_set_value("wifidog", "wifidog", "auth_server_hostname", config->auth_servers->authserv_hostname);
	}
	if((tmp_path != NULL) && (strcmp(path,tmp_host_name) != 0)) {
		free(path);
		config->auth_servers->authserv_path = safe_strdup(tmp_path);
        uci_set_value("wifidog", "wifidog", "auth_server_path", config->auth_servers->authserv_path);
	}
	if(NULL != tmp_http_port) {
		config->auth_servers->authserv_http_port = atoi(tmp_http_port);
        uci_set_value("wifidog", "wifidog", "auth_server_port", tmp_http_port);
    }
	UNLOCK_CONFIG();
	
	json_object_put(json_request);
	send_mqtt_response(mosq, req_id, 200, "Ok", config);
}

static void
process_mqtt_reqeust(struct mosquitto *mosq, const unsigned int req_id, const char *data, s_config *config)
{
	json_object *json_request = json_tokener_parse(data);
	if (is_error(json_request)) {
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

	json_object_put(json_request);
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
	char *username 	= config->mqtt_server->username;
	char *password 	= config->mqtt_server->password;
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

	if (username != NULL) {
		mosquitto_username_pw_set(mosq, username, password);
	}

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

#else
#endif
