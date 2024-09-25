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
#include "gateway.h"
#include "fw_iptables.h"
#include "fw4_nft.h"
#include "wd_util.h"

#define MAX_OUTPUT (512*1024)
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

static struct event_base *ws_base;
static struct evdns_base *ws_dnsbase;
static struct event *ws_heartbeat_ev;
static char *fixed_key = "dGhlIHNhbXBsZSBub25jZQ==";
static char *fixed_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
static bool upgraded = false;

static SSL_CTX *ssl_ctx = NULL;
static SSL *ssl = NULL;

static void ws_heartbeat_cb(evutil_socket_t , short , void *);
static void wsevent_connection_cb(struct bufferevent* , short , void *);

static void
handle_kickoff_response(json_object *j_auth)
{
	json_object *client_ip = json_object_object_get(j_auth, "client_ip");
	json_object *client_mac = json_object_object_get(j_auth, "client_mac");
	json_object *device_id = json_object_object_get(j_auth, "device_id");
	json_object *gw_id = json_object_object_get(j_auth, "gw_id");
	if(client_ip == NULL || client_mac == NULL || device_id == NULL || gw_id == NULL){
		debug(LOG_ERR, "kickoff: parse json data failed\n");
		return;
	}

	const char *client_ip_str = json_object_get_string(client_ip);
	const char *client_mac_str = json_object_get_string(client_mac);
	const char *device_id_str = json_object_get_string(device_id);
	const char *gw_id_str = json_object_get_string(gw_id);
	t_client *client = client_list_find(client_ip_str, client_mac_str);
	if (client == NULL) {
		debug(LOG_ERR, "kickoff: client %s %s not found\n", client_ip_str, client_mac_str);
		return;
	}
	
	if (get_device_id() == NULL || strcmp(get_device_id(), device_id_str) != 0) {
		debug(LOG_ERR, "kickoff: device_id %s not match\n", device_id_str);
		return;
	}

	if (client->gw_setting == NULL || strcmp(client->gw_setting->gw_id, gw_id_str) != 0) {
		debug(LOG_ERR, "kickoff: client %s %s gw_id %s not match\n", client_ip_str, client_mac_str, gw_id_str);
		return;
	}

	LOCK_CLIENT_LIST();
	fw_deny(client);
	client_list_remove(client);
	client_free_node(client);
	UNLOCK_CLIENT_LIST();
}

static void
handle_auth_response(json_object *j_auth)
{
	json_object *token = json_object_object_get(j_auth, "token");
	json_object *client_ip = json_object_object_get(j_auth, "client_ip");
	json_object *client_mac = json_object_object_get(j_auth, "client_mac");
	json_object *client_name = json_object_object_get(j_auth, "client_name");
	json_object *gw_id = json_object_object_get(j_auth, "gw_id");
	json_object *once_auth = json_object_object_get(j_auth, "once_auth");
	if(token == NULL || client_ip == NULL || client_mac == NULL || gw_id == NULL || once_auth == NULL){
		debug(LOG_ERR, "auth: parse json data failed\n");
		return;
	}

	const char *gw_id_str = json_object_get_string(gw_id);
	const bool once_auth_bool = json_object_get_boolean(once_auth);
	if (once_auth_bool) {
		t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
		if (gw_setting == NULL) {
			debug(LOG_ERR, "auth: gateway %s not found\n", gw_id_str);
			return;
		}
		gw_setting->auth_mode = 0;
		debug(LOG_DEBUG, 
			"auth: once_auth is true, update gw_setting's auth_mode [%d] and refresh gw rule\n", gw_setting->auth_mode);
		nft_reload_gw();
		return;
	}

	const char *token_str = json_object_get_string(token);
	const char *client_ip_str = json_object_get_string(client_ip);
	const char *client_mac_str = json_object_get_string(client_mac);
	if (client_list_find(client_ip_str, client_mac_str) == NULL)  {
		t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
		if (gw_setting == NULL) {
			debug(LOG_ERR, "auth: gateway %s not found\n", gw_id_str);
			return;
		}
		LOCK_CLIENT_LIST();
		t_client *client = client_list_add(client_ip_str, client_mac_str, token_str, gw_setting);
		fw_allow(client, FW_MARK_KNOWN);
		if (client_name != NULL) {
			client->name = strdup(json_object_get_string(client_name));
		}
		client->first_login = time(NULL);
		client->is_online = 1;
		UNLOCK_CLIENT_LIST();
		{
			LOCK_OFFLINE_CLIENT_LIST();
			t_offline_client *o_client = offline_client_list_find_by_mac(client->mac);    
			if(o_client)
				offline_client_list_delete(o_client);
			UNLOCK_OFFLINE_CLIENT_LIST();
		}
		debug(LOG_DEBUG, "fw_allow client: token %s, client_ip %s, client_mac %s gw_setting is %lu\n", 
			token_str, client_ip_str, client_mac_str, client->gw_setting);
	} else {
		debug(LOG_DEBUG, "client already exists: token %s, client_ip %s, client_mac %s\n", token_str, client_ip_str, client_mac_str);
	}
}

static void
handle_tmp_pass_response(json_object *j_tmp_pass)
{
	json_object *client_mac = json_object_object_get(j_tmp_pass, "client_mac");
	json_object *timeout = json_object_object_get(j_tmp_pass, "timeout");
	if(client_mac == NULL){
		debug(LOG_ERR, "temp_pass: parse json data failed\n");
		return;
	}

	const char *client_mac_str = json_object_get_string(client_mac);
	uint32_t timeout_value = 5*60;
	if (timeout != NULL) {
		timeout_value = json_object_get_int(timeout);
	}
	fw_set_mac_temporary(client_mac_str, timeout_value);
}

static void
handle_heartbeat_response(json_object *j_heartbeat)
{
	// heartbeat response content is {"type":"heartbeat", gateway:[{"gw_id":"gw_id", "auth_mode":1},...]}
	json_object *gw_array = json_object_object_get(j_heartbeat, "gateway");
	if(gw_array == NULL){
		debug(LOG_ERR, "heartbeat: parse json data failed\n");
		return;
	}
	assert(json_object_is_type(gw_array, json_type_array));

	int state_changed = 0;
	int gw_num = json_object_array_length(gw_array);
	for(int i = 0; i < gw_num; i++){
		json_object *gw = json_object_array_get_idx(gw_array, i);
		json_object *gw_id = json_object_object_get(gw, "gw_id");
		json_object *auth_mode = json_object_object_get(gw, "auth_mode");
		if (gw_id == NULL || auth_mode == NULL) {
			debug(LOG_ERR, "heartbeat: parse json data failed\n");
			continue;
		}
		const char *gw_id_str = json_object_get_string(gw_id);
		int auth_mode_int = json_object_get_int(auth_mode);
		t_gateway_setting *gw_setting = get_gateway_setting_by_id(gw_id_str);
		if (gw_setting == NULL) {
			debug(LOG_ERR, "heartbeat: gateway %s not found\n", gw_id_str);
			continue;
		}
		if (gw_setting->auth_mode != auth_mode_int) {
			gw_setting->auth_mode = auth_mode_int;
			debug(LOG_DEBUG, "heartbeat: gateway %s auth_mode %d\n", gw_id_str, auth_mode_int);
			state_changed = 1;
		}
	}

	if (state_changed) {
		debug(LOG_DEBUG, "gateway state changed, reload firewall\n");
		nft_reload_gw();
	}

}

static void
start_ws_heartbeat(struct bufferevent *b_ws)
{
	if (ws_heartbeat_ev != NULL) {
		event_free(ws_heartbeat_ev);
		ws_heartbeat_ev = NULL;
	}
	struct timeval tv;
	tv.tv_sec = 60;
	tv.tv_usec = 0;
	ws_heartbeat_ev = event_new(ws_base, -1, EV_PERSIST, ws_heartbeat_cb, b_ws);
	event_add(ws_heartbeat_ev, &tv);
}

static void
process_ws_msg(const char *msg)
{
	debug(LOG_DEBUG, "process_ws_msg %s\n", msg);
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
	if (strcmp(type_str, "heartbeat") == 0) {
		handle_heartbeat_response(jobj);
	} else if (strcmp(type_str, "connect") == 0) {
		handle_heartbeat_response(jobj);
	} else if (strcmp(type_str, "auth") == 0) {
		handle_auth_response(jobj);
	} else if (strcmp(type_str, "kickoff") == 0) {
		handle_kickoff_response(jobj);
	} else if (strcmp(type_str, "tmp_pass") == 0) {
		handle_tmp_pass_response(jobj);
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
	t_ws_server *ws_server = get_ws_server();
	debug (LOG_DEBUG, "ws_request :  is %s\n", ws_server->path);
	evbuffer_add_printf(out, "GET %s HTTP/1.1\r\n", ws_server->path);
    if (!ws_server->use_ssl) {
		evbuffer_add_printf(out, "Host:%s:%d\r\n",ws_server->hostname, ws_server->port);
	} else {
		evbuffer_add_printf(out, "Host:%s:%d\r\n",ws_server->hostname, ws_server->port);
	}
    evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", fixed_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
    if (!ws_server->use_ssl) {
		evbuffer_add_printf(out, "Origin:http://%s:%d\r\n", ws_server->hostname, ws_server->port);
	} else {
		evbuffer_add_printf(out, "Origin:https://%s:%d\r\n", ws_server->hostname, ws_server->port);
	}
	evbuffer_add_printf(out, "\r\n");
}

static void
send_msg(struct evbuffer *out, const char *type)
{
	t_gateway_setting *gw_settings = get_gateway_settings();
	json_object *jobj = json_object_new_object();
	json_object_object_add(jobj, "type", json_object_new_string(type));
	json_object_object_add(jobj, "device_id", json_object_new_string(get_device_id()));
	// new a json array object
	json_object *jarray = json_object_new_array();
	while(gw_settings) {
		json_object *jobj_gw = json_object_new_object();
		json_object_object_add(jobj_gw, "gw_id", json_object_new_string(gw_settings->gw_id));
		json_object_object_add(jobj_gw, "gw_channel", json_object_new_string(gw_settings->gw_channel));
		json_object_object_add(jobj_gw, "gw_address_v4", json_object_new_string(gw_settings->gw_address_v4));
		if (gw_settings->gw_address_v6)
			json_object_object_add(jobj_gw, "gw_address_v6", json_object_new_string(gw_settings->gw_address_v6));
		json_object_object_add(jobj_gw, "auth_mode", json_object_new_int(gw_settings->auth_mode));
		json_object_object_add(jobj_gw, "gw_interface", json_object_new_string(gw_settings->gw_interface));
		json_object_array_add(jarray, jobj_gw);
		gw_settings = gw_settings->next;
	}
	json_object_object_add(jobj, "gateway", jarray);
	const char *jdata = json_object_to_json_string(jobj);
	
	debug(LOG_DEBUG, "ws_heartbeat_cb : send heartbeat data [%s]\n", jdata);
	ws_send(out, jdata, strlen(jdata));
	json_object_put(jobj);
}

static void
ws_heartbeat_cb(evutil_socket_t fd, short event, void *arg)
{
	struct bufferevent *b_ws = (struct bufferevent *)arg;
	struct evbuffer *out = bufferevent_get_output(b_ws);
	send_msg(out, "heartbeat");
}

static void 
ws_read_cb(struct bufferevent *b_ws, void *ctx)
{
	struct evbuffer *input = bufferevent_get_input(b_ws);
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
		debug (LOG_DEBUG, "ws_read_cb : upgraded is %d\n", upgraded);

		send_msg(bufferevent_get_output(b_ws), "connect");

		start_ws_heartbeat(b_ws);
    } else {
		ws_receive(data, pos);
	}
}

static struct bufferevent *
create_ws_bufferevent()
{
    t_ws_server *ws_server = get_ws_server();
    struct bufferevent *bev = NULL;

    if (ws_server->use_ssl) {
        bev = bufferevent_openssl_socket_new(ws_base, -1, ssl,
            BUFFEREVENT_SSL_CONNECTING, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    } else {
        bev = bufferevent_socket_new(ws_base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);
    }

    bufferevent_openssl_set_allow_dirty_shutdown(bev, 1);
    bufferevent_setcb(bev, ws_read_cb, NULL, wsevent_connection_cb, NULL);
    bufferevent_enable(bev, EV_READ|EV_WRITE);

    return bev;
}

static void 
wsevent_connection_cb(struct bufferevent* b_ws, short events, void *ctx){
	if(events & BEV_EVENT_CONNECTED){
        debug (LOG_DEBUG,"wsevent_connection_cb: connect ws server and start web socket request\n");
		ws_request(b_ws);
        return;
	} else if(events & (BEV_EVENT_ERROR | BEV_EVENT_EOF)){
		debug(LOG_ERR, "wsevent_connection_cb [BEV_EVENT_ERROR | BEV_EVENT_EOF] error is: %s\n", strerror(errno));
		// stop heartbeat timer
		if (ws_heartbeat_ev != NULL) {
			event_free(ws_heartbeat_ev);
			ws_heartbeat_ev = NULL;
		}
		// is the error is reset by peer, we should sleep longer
		if (events & BEV_EVENT_EOF)
			sleep(5);
		else
			sleep(2);
		// reconnect ws server
		if (b_ws != NULL) {
			bufferevent_free(b_ws);
		}
		
		b_ws = create_ws_bufferevent();
		int ret = bufferevent_socket_connect_hostname(b_ws, ws_dnsbase, AF_INET, 
													get_ws_server()->hostname, get_ws_server()->port);
		upgraded = false;
		if (ret < 0) {
			debug(LOG_ERR, "wsevent_connection_cb: bufferevent_socket_connect_hostname error: %s\n", strerror(errno));
			bufferevent_free(b_ws);
		}
	} else {
		debug(LOG_ERR, "wsevent_connection_cb: ws connection error: %s\n", strerror(errno));
	}
}

/*
 * launch websocket thread
 */
void
start_ws_thread(void *arg)
{
	t_ws_server *ws_server = get_ws_server();
	if (!RAND_poll()) termination_handler(0);

	/* Create a new OpenSSL context */
	ssl_ctx = SSL_CTX_new(SSLv23_method());
	if (!ssl_ctx) termination_handler(0);

	ssl = SSL_new(ssl_ctx);
	if (!ssl) termination_handler(0);

	// authserv_hostname is the hostname of the auth server, must be domain name
    if (!SSL_set_tlsext_host_name(ssl, ws_server->hostname)) {
        debug(LOG_ERR, "SSL_set_tlsext_host_name failed");
        termination_handler(0);
    }

    ws_base = event_base_new();
	if (ws_base == NULL) {
		debug(LOG_ERR, "create event base failed\n");
		termination_handler(0);
	}
    ws_dnsbase = evdns_base_new(ws_base, 1);
	if (ws_dnsbase == NULL) {
		debug(LOG_ERR, "create dns base failed\n");
		termination_handler(0);
	}

    struct bufferevent *ws_bev = NULL;
	while (1) {
        ws_bev = create_ws_bufferevent();
        int ret = bufferevent_socket_connect_hostname(ws_bev, ws_dnsbase, AF_INET, 
                                                      ws_server->hostname, ws_server->port);
        upgraded = false;
        if (ret < 0) {
            debug(LOG_ERR, "bufferevent_socket_connect_hostname error: %s\n", strerror(errno));
            bufferevent_free(ws_bev);
            sleep(1); // Wait before retrying
        } else {
            break; // Successfully connected
        }
    }

	debug(LOG_DEBUG, "ws thread started\n");
	event_base_dispatch(ws_base);

	if (ws_base) event_base_free(ws_base);
	if (ws_dnsbase) evdns_base_free(ws_dnsbase, 0);
	if (ws_bev) bufferevent_free(ws_bev);
	if (ssl) SSL_free(ssl);
	if (ssl_ctx) SSL_CTX_free(ssl_ctx);

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
