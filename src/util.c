/* vim: set et sw=4 sts=4 ts=4 : */
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

/**
  @file util.c
  @brief Misc utility functions
  @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
  @author Copyright (C) 2006 Benoit Grégoire <bock@step.polymtl.ca>
  @author Copyright (C) 2016 Dengfeng Liu <liudf0716@gmail.com>
 */

#define _GNU_SOURCE

#include <netinet/icmp6.h>

#include "util.h"
#include "debug.h"
#include "common.h"


/** @brief FD for icmp raw socket */
static int icmp_fd;
static int icmp6_fd;

static unsigned short rand16(void);


/** Initialize the ICMP socket
 * @return A boolean of the success
 */
int
init_icmp_socket(void)
{
    int flags, oneopt = 1, zeroopt = 0;

    debug(LOG_INFO, "Creating ICMP socket");
    if ((icmp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) == -1 ||
        (flags = fcntl(icmp_fd, F_GETFL, 0)) == -1 ||
        fcntl(icmp_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
        setsockopt(icmp_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
        debug(LOG_ERR, "Cannot create ICMP raw socket.");
        return 0;
    }

	if ((icmp6_fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1 ||
		(flags = fcntl(icmp6_fd, F_GETFL, 0)) == -1 ||
		fcntl(icmp6_fd, F_SETFL, flags | O_NONBLOCK) == -1 ||
		setsockopt(icmp6_fd, SOL_SOCKET, SO_RCVBUF, &oneopt, sizeof(oneopt)) ||
		setsockopt(icmp6_fd, SOL_SOCKET, SO_DONTROUTE, &zeroopt, sizeof(zeroopt)) == -1) {
		debug(LOG_ERR, "Cannot create ICMP6 raw socket.");
		close(icmp_fd);
		return 0;
	}

    return 1;
}

/** Close the ICMP socket. */
void
close_icmp_socket(void)
{
    debug(LOG_INFO, "Closing ICMP socket");
    close(icmp_fd);
	close(icmp6_fd);
}

/**
 * Ping an IP.
 * @param IP/host as string, will be sent to gethostbyname
 */
void
icmp_ping(const char *host)
{
    struct sockaddr_in saddr;
    struct {
        struct ip ip;
        struct icmp icmp;
    } packet;
    unsigned int i, j;
    int opt = 2000;
    unsigned short id = rand16();

    memset(&saddr, 0, sizeof(saddr));
    saddr.sin_family = AF_INET;
    inet_aton(host, &saddr.sin_addr);
#if defined(HAVE_SOCKADDR_SA_LEN)
    saddr.sin_len = sizeof(struct sockaddr_in);
#endif

    memset(&packet.icmp, 0, sizeof(packet.icmp));
    packet.icmp.icmp_type = ICMP_ECHO;
    packet.icmp.icmp_id = id;

    for (j = 0, i = 0; i < sizeof(struct icmp) / 2; i++)
        j += ((unsigned short *)&packet.icmp)[i];

    while (j >> 16)
        j = (j & 0xffff) + (j >> 16);

    packet.icmp.icmp_cksum = (j == 0xffff) ? j : ~j;

    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    if (sendto(icmp_fd, (char *)&packet.icmp, sizeof(struct icmp), 0,
               (const struct sockaddr *)&saddr, sizeof(saddr)) == -1)
        debug(LOG_ERR, "sendto(): %s", strerror(errno));

    opt = 1;
    if (setsockopt(icmp_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
        debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    return;
}

static unsigned short 
checksum(void *buf, int len) {
	unsigned short *ptr = (unsigned short *)buf;
	unsigned int sum = 0;
	unsigned short result;

	for (sum = 0; len > 1; len -= 2) {
		sum += *ptr++;
	}

	if (len == 1) {
		sum += *(unsigned char *)ptr;
	}

	sum = (sum >> 16) + (sum & 0xFFFF);
	sum += (sum >> 16);
	result = ~sum;

	return result;
}

void icmp6_ping(const char *host) 
{
    struct sockaddr_in6 addr;
    struct icmp6_hdr icmp6_hdr;
    char sendbuf[1024];
	int opt = 2000;

    // Initialize address structure
    memset(&addr, 0, sizeof(addr));
    addr.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, host, &addr.sin6_addr) != 1) {
        debug(LOG_ERR, "inet_pton failed");
		return;
    }

    // Initialize ICMPv6 header
    memset(&icmp6_hdr, 0, sizeof(icmp6_hdr));
    icmp6_hdr.icmp6_type = ICMP6_ECHO_REQUEST;
    icmp6_hdr.icmp6_code = 0;
    icmp6_hdr.icmp6_id = getpid() & 0xFFFF;
    icmp6_hdr.icmp6_seq = 1;
    icmp6_hdr.icmp6_cksum = 0;

    // Calculate checksum
    memcpy(sendbuf, &icmp6_hdr, sizeof(icmp6_hdr));
    icmp6_hdr.icmp6_cksum = checksum(sendbuf, sizeof(icmp6_hdr));
    memcpy(sendbuf, &icmp6_hdr, sizeof(icmp6_hdr));

	if (setsockopt(icmp6_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));

    // Send ICMPv6 echo request
    if (sendto(icmp6_fd, sendbuf, sizeof(icmp6_hdr), 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        debug(LOG_ERR, "sendto failed: %s", strerror(errno));
    }

    opt = 1;
	if (setsockopt(icmp6_fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof(opt)) == -1)
		debug(LOG_ERR, "setsockopt(): %s", strerror(errno));
}

/** Get a 16-bit unsigned random number.
 * @return unsigned short a random number
 */
static unsigned short
rand16(void)
{
    static int been_seeded = 0;

    if (!been_seeded) {
        unsigned int seed = 0;
        struct timeval now;

        /* not a very good seed but what the heck, it needs to be quickly acquired */
        gettimeofday(&now, NULL);
        seed = now.tv_sec ^ now.tv_usec ^ (getpid() << 16);

        srand(seed);
        been_seeded = 1;
    }

    /* Some rand() implementations have less randomness in low bits
     * than in high bits, so we only pay attention to the high ones.
     * But most implementations don't touch the high bit, so we
     * ignore that one. */
    return ((unsigned short)(rand() >> 15));
}

/*
 * Save pid of this wifidog in pid file
 * @param 'pf' as string, it is the pid file absolutely path
 */
void
save_pid_file(const char *pf)
{
    if (pf) {
        FILE *f = fopen(pf, "w");
        if (f) {
            fprintf(f, "%d\n", getpid());

            int ret = fclose(f);
            if (ret == EOF) /* check the return value of fclose */
                debug(LOG_ERR, "fclose() on file %s was failed (%s)", pf, strerror(errno));
        } else /* fopen return NULL, open file failed */
            debug(LOG_ERR, "fopen() on flie %s was failed (%s)", pf, strerror(errno));
    }

    return;
}

// true: 1; false: 0
int
is_valid_ip(const char *ip)
{
	if (!ip) {
		return 0;
	}
	struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

int
is_valid_ip6(const char *ip)
{
	if (!ip) {
		return 0;
	}
	struct sockaddr_in6 sa;
	int result = inet_pton(AF_INET6, ip, &(sa.sin6_addr));
	return result != 0;
}

int 
is_valid_mac(const char *mac)
{
	int i = 0;
	int s = 0;

	if (!mac || strlen(mac) != 17)
		return 0;

	while (*mac) {
		if (isxdigit(*mac)) {
			i++;
		} else if (*mac == ':' || *mac == '-') {
			if (i == 0 || i / 2 - 1 != s)
				break;
			++s;
		} else {
			s = -1;
		}
		++mac;
	}

	return (i == 12 && (s == 5 || s == 0));
}

// when sockfd is block, set timeout for connect
int 
wd_connect(int sockfd, const struct sockaddr *their_addr, socklen_t addrlen, int timeout)
{
	// Set non-blocking 
	long arg = fcntl(sockfd, F_GETFL, NULL); 
	arg |= O_NONBLOCK; 
	fcntl(sockfd, F_SETFL, arg); 
       	
	int res = connect(sockfd, their_addr, addrlen); 
	if ((res == -1) && (errno != EINPROGRESS)) {
		goto ERROR;
	} else if (res == 0) {
		goto SUCCESS;
	} else {
		int so_error = 0;
        unsigned len = sizeof(so_error);

        struct pollfd fds;
        memset(&fds, 0, sizeof(fds));
        fds.fd      = sockfd;
        fds.events   = POLLOUT;
        res = poll(&fds, 1, timeout*1000);
		switch(res) {
		case 1: // data to read				
			getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
			if (so_error == 0) {
				goto SUCCESS;
			}
			break;
		default: 
			break;
		}
	} 

ERROR:
	return -1;
SUCCESS:	
	// Set to blocking mode again... 
	arg = fcntl(sockfd, F_GETFL, NULL); 
	arg &= (~O_NONBLOCK); 
	fcntl(sockfd, F_SETFL, arg); 
	return 0;
}

#define	BUF_MAX		1024

static int 
read_cpu_fields (FILE *fp, unsigned long *fields)
{
	int retval, i;
	char buffer[BUF_MAX] = {0};
	unsigned long total_tick = 0;

	if (!fp || !fgets (buffer, BUF_MAX, fp)) { 
	 	return 0;
	}

	retval = sscanf (buffer, "%*s %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu", 
							&fields[0], 
							&fields[1], 
							&fields[2], 
							&fields[3], 
							&fields[4], 
							&fields[5], 
							&fields[6], 
							&fields[7], 
							&fields[8], 
							&fields[9]); 
	if (retval != 10) { /* Atleast 4 fields is to be read */
		return 0;
	}
	
	for(i = 0; i < 10; i++)
		total_tick += fields[i];
	return total_tick?1:0; // in case of total_tick  is zero, as some platform reporting, I dont know why.
}

float
get_cpu_usage()
{
	FILE *fp;
	unsigned long fields[10], total_tick, total_tick_old, idle, idle_old, del_total_tick, del_idle;
	int i;
	float percent_usage;

	fp = fopen ("/proc/stat", "r");
	if (!fp) {
		return 0.f;	
	}


	if (!read_cpu_fields (fp, fields)) { 
		fclose (fp);
		return 0.f; 
	}

	for (i=0, total_tick = 0; i<10; i++) { 
		total_tick += fields[i]; 
	}
	idle = fields[3]; /* idle ticks index */

	wd_sleep(1, 0);
	total_tick_old = total_tick;
	idle_old = idle;

	fseek (fp, 0, SEEK_SET);
	fflush (fp);
	if (!read_cpu_fields (fp, fields)){ 
		fclose (fp);
		return 0.f; 
	}
	fclose (fp);

	for (i=0, total_tick = 0; i<10; i++) { 
		total_tick += fields[i]; 
	}
	idle = fields[3];

	del_total_tick = total_tick - total_tick_old;
	del_idle = idle - idle_old;

	percent_usage = ((del_total_tick - del_idle) / (float) del_total_tick) * 100; /* 3 is index of idle time */
	debug (LOG_DEBUG, "Total CPU Usage: %3.2lf%%\n", percent_usage);

	return percent_usage;
}

// wd_sleep using select timeout method to instead of sleep-func
// s: second, u: usec 10^6usec = 1s
void 
wd_sleep(unsigned int s, unsigned int u){
	struct timeval timeout;
	timeout.tv_sec = s;
	timeout.tv_usec = u;

	select(0, NULL, NULL, NULL, &timeout);
}
