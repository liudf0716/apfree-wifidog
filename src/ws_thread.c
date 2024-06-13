/* vim: set sw=4 ts=4 sts=4 et : */
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

#include "common.h"
#include "ws_thread.h"
#include "debug.h"
#include "conf.h"
#include "firewall.h"
#include "client_list.h"

#define MAX_OUTPUT (512*1024)
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

static struct event_base *ws_base;
static struct evdns_base *ws_dnsbase;
static struct event *ws_heartbeat_ev;
static char *fixed_key = "dGhlIHNhbXBsZSBub25jZQ==";
static char *fixed_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
static bool upgraded = false;

static void
process_ws_msg(const char *msg)
{
	debug(LOG_DEBUG, "process_ws_msg %s\n", msg);
	// parse json data, the msg is json data and like this
	// {"type":"auth", "token":"xxxxx", "client_ip":"ip address", "client_mac":"mac address"}
	json_object *jobj = json_tokener_parse(msg);
	if(jobj == NULL){
		debug(LOG_ERR, "parse json data failed\n");
		return;
	}

	json_object *type = json_object_object_get(jobj, "type");
	if(type == NULL){
		debug(LOG_ERR, "parse json data failed\n");
		json_object_put(jobj);
		return;
	}

	const char *type_str = json_object_get_string(type);
	if (strcmp(type_str, "auth") == 0) {
		json_object *token = json_object_object_get(jobj, "token");
		json_object *client_ip = json_object_object_get(jobj, "client_ip");
		json_object *client_mac = json_object_object_get(jobj, "client_mac");
		json_object *client_name = json_object_object_get(jobj, "client_name");
		if(token == NULL || client_ip == NULL || client_mac == NULL){
			debug(LOG_ERR, "auth: parse json data failed\n");
			json_object_put(jobj);
			return;
		}
		const char *token_str = json_object_get_string(token);
		const char *client_ip_str = json_object_get_string(client_ip);
		const char *client_mac_str = json_object_get_string(client_mac);
		if (client_list_find(client_ip_str, client_mac_str) == NULL)  {
			t_client *client = client_list_add(client_ip_str, client_mac_str, token_str);
			fw_allow(client, FW_MARK_KNOWN);
			if (client_name != NULL) {
				client->name = strdup(json_object_get_string(client_name));
			}
			debug(LOG_DEBUG, "fw_allow client: token %s, client_ip %s, client_mac %s\n", token_str, client_ip_str, client_mac_str);
		} else {
			debug(LOG_DEBUG, "client already exists: token %s, client_ip %s, client_mac %s\n", token_str, client_ip_str, client_mac_str);
		}
	} else if (strcmp(type_str, "tmp_pass") == 0) {
		json_object *client_mac = json_object_object_get(jobj, "client_mac");
		json_object *timeout = json_object_object_get(jobj, "timeout");
		if (client_mac == NULL) {
			debug(LOG_ERR, "temp_pass: parse json data failed\n");
			json_object_put(jobj);
			return;
		}
		const char *client_mac_str = json_object_get_string(client_mac);
		uint32_t timeout_value = 5*60;
		if (timeout != NULL) {
			timeout_value = json_object_get_int(timeout);
		}
		fw_set_mac_temporary(client_mac_str, timeout_value);
	} else {
		debug(LOG_ERR, "unknown type %s\n", type_str);
	}

	json_object_put(jobj);
}


static void 
ws_send(struct evbuffer *buf, const char *msg, const size_t len)
{
	uint8_t a = 0;
	a |= 1 << 7;  //fin
	a |= 1; //text frame
	
	uint8_t b = 0;
	b |= 1 << 7; //mask
	
	uint16_t c = 0;
	uint64_t d = 0;

	//payload len
	if(len < 126){
		b |= len; 
	}
	else if(len < (1 << 16)){
		b |= 126;
		c = htons(len);
	}else{
		b |= 127;
		d = htonll(len);
	}

	evbuffer_add(buf, &a, 1);
	evbuffer_add(buf, &b, 1);

	if(c) evbuffer_add(buf, &c, sizeof(c));
	else if(d) evbuffer_add(buf, &d, sizeof(d));

	uint8_t mask_key[4] = {1, 2, 3, 4};  //should be random
	evbuffer_add(buf, &mask_key, 4);

	uint8_t m;
	for(int i = 0; i < len; i++){
		m = msg[i] ^ mask_key[i%4];
		evbuffer_add(buf, &m, 1); 
	}	
    debug(LOG_DEBUG, "ws send data %d\n", len);
}

static void 
ws_receive(unsigned char *data, const size_t data_len){
	if(data_len < 2)
		return;

	int fin = !!(*data & 0x80);
	int opcode = *data & 0x0F;
	int mask = !!(*(data+1) & 0x80);
	uint64_t payload_len =  *(data+1) & 0x7F;

	size_t header_len = 2 + (mask ? 4 : 0);
	
	debug(LOG_DEBUG, "ws receive fin %d opcode %d data_len %d mask %d head_len %d payload_len %d\n", 
		fin, opcode, data_len, mask, header_len, payload_len);

	if(payload_len < 126){
		if(header_len > data_len)
			return;

	}else if(payload_len == 126){
		header_len += 2;
		if(header_len > data_len)
			return;

		payload_len = ntohs(*(uint16_t*)(data+2));

	}else if(payload_len == 127){
		header_len += 8;
		if(header_len > data_len)
			return;

		payload_len = ntohll(*(uint64_t*)(data+2));
	}

	if(header_len + payload_len > data_len)
		return;


	unsigned char* mask_key = data + header_len - 4;
	debug(LOG_DEBUG, "ws receive opcode %d data_len %d mask %d head_len %d payload_len %d\n", 
		opcode, data_len, mask, header_len, payload_len);
	for(int i = 0; mask && i < payload_len; i++)
		data[header_len + i] ^= mask_key[i%4];


	if(opcode == 0x01) {
        const char *msg = (const char *)(data + header_len);
		process_ws_msg(msg);
    }
}

static void 
ws_request(struct bufferevent* b_ws)
{
	struct evbuffer *out = bufferevent_get_output(b_ws);
    t_auth_serv *auth_server = get_auth_server();
	debug (LOG_DEBUG, "ws_request :  is %s\n", 
		auth_server->authserv_ws_script_path_fragment);
	evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n", auth_server->authserv_ws_script_path_fragment);
    if (!auth_server->authserv_use_ssl) {
	    evbuffer_add_printf(out, "Host:%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_http_port);
	} else {
        evbuffer_add_printf(out, "Host:%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	}
    evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", fixed_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
    if (!auth_server->authserv_use_ssl) {
		evbuffer_add_printf(out, "Origin:http://%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_http_port); 
	} else {
		evbuffer_add_printf(out, "Origin:http://%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	}
	evbuffer_add_printf(out, "\r\n");
}

static void
ws_heartbeat_cb(evutil_socket_t fd, short event, void *arg)
{
	struct bufferevent *b_ws = (struct bufferevent *)arg;
	struct evbuffer *out = bufferevent_get_output(b_ws);
	char jdata[128] = {0};
	snprintf(jdata, 128, "{\"type\":\"heartbeat\",\"gwID\":\"%s\"}", 
		config_get_config()->gw_id);
	debug(LOG_DEBUG, "ws_heartbeat_cb : send heartbeat data\n");
	ws_send(out, jdata, strlen(jdata));
}

static void 
ws_read_cb(struct bufferevent *b_ws, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(b_ws);
    debug (LOG_DEBUG, "ws_read_cb : upgraded is %d\n", upgraded);
	unsigned char data[1024] = {0};
	int pos = 0;
	int data_len = 0;
	while((data_len = evbuffer_get_length(input)) > 0){
		evbuffer_remove(input, data + pos, data_len);
		pos += data_len;
	}
	assert(pos < 1023);
    if (!upgraded) {
        if(!strstr((const char*)data, "\r\n\r\n")) {
            debug (LOG_INFO, "data end");
            return;
        }
        
        if(strncmp((const char*)data, "HTTP/1.1 101", strlen("HTTP/1.1 101")) != 0
            || !strstr((const char*)data, fixed_accept)){
            debug (LOG_INFO, "not web socket supported");
            return;
        }

        upgraded = true;

		// create json data
		char jdata[128] = {0};
		snprintf(jdata, 128, "{\"type\":\"connect\",\"gwID\":\"%s\"}", 
			config_get_config()->gw_id);
		ws_send(bufferevent_get_output(b_ws), jdata, strlen(jdata));
		debug(LOG_DEBUG, "send connect data %s\n", jdata);

		// add timer to send heartbeat
		if (ws_heartbeat_ev != NULL) {
			event_free(ws_heartbeat_ev);
		}
		struct timeval tv;
		tv.tv_sec = 60;
		tv.tv_usec = 0;
		ws_heartbeat_ev = event_new(ws_base, -1, EV_PERSIST, ws_heartbeat_cb, b_ws);
		event_add(ws_heartbeat_ev, &tv);
    } else {
		ws_receive(data, pos);
	}
}

static void 
wsevent_connection_cb(struct bufferevent* b_ws, short events, void *ctx){
	if(events & BEV_EVENT_CONNECTED){
        debug (LOG_DEBUG,"connect ws server and start web socket request\n");
		ws_request(b_ws);
        return;
	} else if(events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)){
		debug(LOG_ERR, "ws connection error: %s\n", strerror(errno));
		sleep(1);
		// reconnect ws server
		if (b_ws != NULL) {
			bufferevent_free(b_ws);
		}
		b_ws = bufferevent_socket_new(ws_base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
		bufferevent_setcb(b_ws, ws_read_cb, NULL, wsevent_connection_cb, NULL);
		bufferevent_enable(b_ws, EV_READ|EV_WRITE);
		t_auth_serv *auth_server = get_auth_server();
		int ret = 0;
		if (!auth_server->authserv_use_ssl) {
		    ret = bufferevent_socket_connect_hostname(b_ws, ws_dnsbase, AF_INET, 
				auth_server->authserv_hostname, auth_server->authserv_http_port); 
		} else {
			ret = bufferevent_socket_connect_hostname(b_ws, ws_dnsbase, AF_INET, 
				auth_server->authserv_hostname, auth_server->authserv_ssl_port); 
		}
		upgraded = false;
		if (ret < 0) {
			debug(LOG_ERR, "ws connection error: %s\n", strerror(errno));
			bufferevent_free(b_ws);
		}
	} 
}

/*
 * launch websocket thread
 */
void
start_ws_thread(void *arg)
{
    t_auth_serv *auth_server = get_auth_server();
    ws_base = event_base_new();
    ws_dnsbase = evdns_base_new(ws_base, 1);

    struct bufferevent *ws_bev = bufferevent_socket_new(ws_base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
	if (ws_bev == NULL) {
		debug(LOG_ERR, "create bufferevent failed\n");
		goto ERR;
	}
	bufferevent_setcb(ws_bev, ws_read_cb, NULL, wsevent_connection_cb, NULL);
	bufferevent_enable(ws_bev, EV_READ|EV_WRITE);

	int ret = 0;
    if (!auth_server->authserv_use_ssl) {
	    ret = bufferevent_socket_connect_hostname(ws_bev, ws_dnsbase, AF_INET, 
            auth_server->authserv_hostname, auth_server->authserv_http_port); 
    } else {
        ret = bufferevent_socket_connect_hostname(ws_bev, ws_dnsbase, AF_INET, 
            auth_server->authserv_hostname, auth_server->authserv_ssl_port); 
    }

	if (ret < 0) {
		debug(LOG_ERR, "ws connection error: %s\n", strerror(errno));
		bufferevent_free(ws_bev);
		goto ERR;
	}

	event_base_dispatch(ws_base);

ERR:
	if (ws_base) event_base_free(ws_base);
	if (ws_dnsbase) evdns_base_free(ws_dnsbase, 0);
	if (ws_bev) bufferevent_free(ws_bev);

    return;
}

/*
 * stop ws thread
 */
void
stop_ws_thread()
{
    event_base_loopexit(ws_base, NULL);
}
