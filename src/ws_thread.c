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

#define MAX_OUTPUT (512*1024)
#define htonll(x) ((1==htonl(1)) ? (x) : ((uint64_t)htonl((x) & 0xFFFFFFFF) << 32) | htonl((x) >> 32))
#define ntohll(x) htonll(x)

static struct event_base *ws_base;
static struct evdns_base *ws_dnsbase;
static struct bufferevent *b_sshclient;
static char *connect_sshsvr_str = "127.0.0.1:22";
static char *fixed_key = "dGhlIHNhbXBsZSBub25jZQ==";
static char *fixed_accept = "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=";
static bool upgraded = false;

static void ssh_read_cb(struct bufferevent* bev, void* ctx);
static void ws_ssh_read_cb(struct bufferevent* bev, void* ctx);

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
ws_receive(struct evbuffer *buf, struct evbuffer *out){
	int data_len = evbuffer_get_length(buf);
    debug (LOG_DEBUG, "ws receive data %d\n", data_len);
	if(data_len < 2)
		return;

	unsigned char* data = evbuffer_pullup(buf, data_len);

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


	const unsigned char* mask_key = data + header_len - 4;

	for(int i = 0; mask && i < payload_len; i++)
		data[header_len + i] ^= mask_key[i%4];


	if(opcode == 0x01) {
        // redirect data to ssh client
        evbuffer_add(out, (const char *)data+header_len, payload_len);
    }
	
	evbuffer_drain(buf, header_len + payload_len);

	//next frame
	ws_receive(buf, out);
}

static void
close_on_finished_writecb(struct bufferevent *bev, void *ctx)
{
	struct evbuffer *b = bufferevent_get_output(bev);

	if (evbuffer_get_length(b) == 0) {
		bufferevent_free(bev);
	}
}

static void
eventcb(struct bufferevent *bev, short what, void *ctx)
{
	struct bufferevent *partner = ctx;

	if (what & (BEV_EVENT_EOF|BEV_EVENT_ERROR)) {
		if (what & BEV_EVENT_ERROR) {
			if (errno)
                debug(LOG_ERR, "connection error %s\n", strerror(errno));
		}

		if (partner) {
			if (evbuffer_get_length(
				    bufferevent_get_output(partner))) {
				/* We still have to flush data from the other
				 * side, but when that's done, close the other
				 * side. */
				bufferevent_setcb(partner,
				    NULL, close_on_finished_writecb,
				    eventcb, NULL);
				bufferevent_disable(partner, EV_READ);
			} else {
				/* We have nothing left to say to the other
				 * side; close it. */
				bufferevent_free(partner);
			}
		}
		bufferevent_free(bev);
	}
}

static void
ssh_drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, ssh_read_cb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void
ws_drained_writecb(struct bufferevent *bev, void *ctx)
{
	struct bufferevent *partner = ctx;

	/* We were choking the other side until we drained our outbuf a bit.
	 * Now it seems drained. */
	bufferevent_setcb(bev, ws_ssh_read_cb, NULL, eventcb, partner);
	bufferevent_setwatermark(bev, EV_WRITE, 0, 0);
	if (partner)
		bufferevent_enable(partner, EV_READ);
}

static void 
ssh_read_cb(struct bufferevent* bev, void* ctx)
{
    struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (!partner) {
        debug (LOG_INFO, "ssh_read_cb: invalid partner\n");
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);

    debug (LOG_DEBUG, "send ssh data to ws server\n");
    // send ssh client output to ws server
    ws_send(dst, evbuffer_pullup(src, len), len);
    evbuffer_drain(src, len);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
        debug (LOG_INFO, "write buffer overflow");
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, ssh_read_cb, ssh_drained_writecb,
		    eventcb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void 
ws_ssh_read_cb(struct bufferevent* bev, void* ctx)
{
    struct bufferevent *partner = ctx;
	struct evbuffer *src, *dst;
	size_t len;
	src = bufferevent_get_input(bev);
	len = evbuffer_get_length(src);
	if (!partner) {
        debug (LOG_INFO, "ws_ssh_read_cb: invalid partner\n");
		evbuffer_drain(src, len);
		return;
	}
	dst = bufferevent_get_output(partner);

    debug (LOG_DEBUG, "send ws server ssh client data to local ssh server\n");
    ws_receive(src, dst);

	if (evbuffer_get_length(dst) >= MAX_OUTPUT) {
        debug (LOG_INFO, "write buffer overflow");
		/* We're giving the other side data faster than it can
		 * pass it on.  Stop reading here until we have drained the
		 * other side to MAX_OUTPUT/2 bytes. */
		bufferevent_setcb(partner, ws_ssh_read_cb, ws_drained_writecb,
		    eventcb, bev);
		bufferevent_setwatermark(partner, EV_WRITE, MAX_OUTPUT/2,
		    MAX_OUTPUT);
		bufferevent_disable(bev, EV_READ);
	}
}

static void 
ws_request(struct bufferevent* b_ws)
{
	struct evbuffer *out = bufferevent_get_output(b_ws);
    t_auth_serv *auth_server = get_auth_server();
	evbuffer_add_printf(out, "GET %s/%s HTTP/1.1\r\n", auth_server->authserv_path, auth_server->authserv_ws_script_path_fragment);
    if (!auth_server->authserv_use_ssl)
	    evbuffer_add_printf(out, "Host:%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_http_port);
	else
        evbuffer_add_printf(out, "Host:%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_ssl_port);
    evbuffer_add_printf(out, "Upgrade:websocket\r\n");
	evbuffer_add_printf(out, "Connection:upgrade\r\n");
	evbuffer_add_printf(out, "Sec-WebSocket-Key:%s\r\n", fixed_key);
	evbuffer_add_printf(out, "Sec-WebSocket-Version:13\r\n");
    if (!auth_server->authserv_use_ssl)
	    evbuffer_add_printf(out, "Origin:http://%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_http_port); 
    else
        evbuffer_add_printf(out, "Origin:http://%s:%d\r\n",auth_server->authserv_hostname, auth_server->authserv_ssl_port);
	evbuffer_add_printf(out, "\r\n");
}

static void 
ws_read_cb(struct bufferevent *b_ws, void *ctx)
{
    debug (LOG_DEBUG, "ws_read_cb : upgraded is %d\n", upgraded);
    if (!upgraded) {
		struct evbuffer *input = bufferevent_get_input(b_ws);
        int data_len = evbuffer_get_length(input);
        unsigned char *data = evbuffer_pullup(input, data_len);
        if(!strstr((const char*)data, "\r\n\r\n")) {
            debug (LOG_INFO, "data end");
            return;
        }
        
        if(strncmp((const char*)data, "HTTP/1.1 101", strlen("HTTP/1.1 101")) != 0
            || !strstr((const char*)data, fixed_accept)){
            debug (LOG_INFO, "not web socket supported");
            return;
        }

        // first connect ssh server
        struct sockaddr_storage connect_sshsvr_addr;
        int connect_sshsvr_addrlen = 0;
        b_sshclient = bufferevent_socket_new(ws_base, -1, BEV_OPT_CLOSE_ON_FREE|BEV_OPT_DEFER_CALLBACKS);   
        memset(&connect_sshsvr_addr, 0, sizeof(connect_sshsvr_addr));
        connect_sshsvr_addrlen = sizeof(connect_sshsvr_addr);
        evutil_parse_sockaddr_port(connect_sshsvr_str, (struct sockaddr*)&connect_sshsvr_addr, &connect_sshsvr_addrlen);
        bufferevent_socket_connect(b_sshclient, (struct sockaddr*)&connect_sshsvr_addr, connect_sshsvr_addrlen);
        
        bufferevent_setcb(b_sshclient, ssh_read_cb, NULL, eventcb, b_ws);
        bufferevent_setcb(b_ws, ws_ssh_read_cb, NULL, eventcb, b_sshclient);

        bufferevent_enable(b_sshclient, EV_READ|EV_WRITE);
        bufferevent_enable(b_ws, EV_READ|EV_WRITE);

        upgraded = true;
    }
    
}

static void 
wsevent_connection_cb(struct bufferevent* b_ws, short events, void *ctx){
	if(events & BEV_EVENT_CONNECTED){
        debug (LOG_DEBUG,"connect ws server and start web socket request\n");
		ws_request(b_ws);
        return;
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

	bufferevent_setcb(ws_bev, ws_read_cb, NULL, wsevent_connection_cb, NULL);
	bufferevent_enable(ws_bev, EV_READ|EV_WRITE);

    if (!auth_server->authserv_use_ssl) {
	    bufferevent_socket_connect_hostname(ws_bev, ws_dnsbase, AF_INET, 
            auth_server->authserv_hostname, auth_server->authserv_http_port); 
    } else {
        bufferevent_socket_connect_hostname(ws_bev, ws_dnsbase, AF_INET, 
            auth_server->authserv_hostname, auth_server->authserv_ssl_port); 
    }
	
	event_base_dispatch(ws_base);

    event_base_free(ws_base);

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
