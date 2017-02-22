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

#include "mqtt_thread.h"
#include "conf.h"
#include "debug.h"

static void
mqtt_connect_callback(struct mosquitto *mosq, void *obj, int rc)
{
	s_config 		*config = obj;
	t_mqtt_server	*mqtt_server = config->mqtt_server;
	t_mqtt_topic	*topics = mqtt_server->topics;

	for (; topics != NULL; topics = topics->next) {
		mosquitto_subscribe(mosq, NULL, topics->topic, 0);
	}
}

static void 
mqtt_message_callback(struct mosquitto *mosq, void *obj, const struct mosquitto_message *message)
{
	s_config *config = obj;

	if (message->payloadlen) {
		debug(LOG_DEBUG, "topic is %s, data is %s", message->topic, message->payload);
	}
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
    mosq = mosquitto_new(NULL, true, config);
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