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
/** @file common.h
    @brief Common constants and other bits
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#ifndef _COMMON_H_
#define _COMMON_H_

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <limits.h>
#include <netdb.h>
#include <pthread.h>
#include <resolv.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <setjmp.h>
#include <signal.h>
#include <stdbool.h>
#include <unistd.h>
#include <poll.h>
#include <assert.h>

#include <arpa/nameser.h>
#include <arpa/inet.h>
#include <linux/version.h>
#include <linux/netlink.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <netinet/ether.h>
#include <sys/uio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>
#include <event2/event.h>
#include <event2/event_struct.h>
#include <event2/http.h>
#include <event2/buffer.h>
#include <event2/util.h>
#include <event2/keyvalq_struct.h>
#include <event2/buffer.h>
#include <event2/dns.h>
#include <event2/listener.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <json-c/json.h>
#ifdef	_MQTT_SUPPORT_
  #include <mosquitto.h>
#endif
#include <uci.h>

#ifdef EVENT__HAVE_NETINET_IN_H
#include <netinet/in.h>
# ifdef _XOPEN_SOURCE_EXTENDED
#  include <arpa/inet.h>
# endif
#endif

/** @brief Read buffer for socket read? */
#define MAX_BUF             4096
#define HTTP_IP_ADDR_LEN    17
#define HTTP_MAC_LEN        18
#define	DEFAULT_MAC			"ff:ff:ff:ff:ff:ff"
#define UNSUPPORTED         "not support"

#define ARRAYLEN(array)     (sizeof(array)/sizeof((array)[0]))

#ifndef is_error
#define is_error(name)  (name == NULL)
#endif

// if disable AUTHSERVER_V2, comment it
#define AUTHSERVER_V2

#endif /* _COMMON_H_ */
