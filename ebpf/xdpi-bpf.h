#ifndef _XDPI_BPF_H_
#define _XDPI_BPF_H_

/*
 * xdpi-bpf.h - Header file for xDPI (Extended Deep Packet Inspection) in BPF
 * Copyright (C) 2025 Dengfeng Liu <liudf0716@gmail.com>
 *
 * Contains the definitions and structures used by the xDPI BPF module
 */

#include <linux/types.h>

#define INGRESS 0
#define EGRESS 1

/* L7 Protocol IDs - Using #define instead of enum */
#define L7_HTTP     8001
#define L7_HTTPS    8002
#define L7_MSTSC    8001
#define L7_SSH      8002
#define L7_SCP      8003
#define L7_WECHAT   8004
#define L7_DNS      8005
#define L7_DHCP     8006
#define L7_NTP      8007
#define L7_SNMP     8008
#define L7_TFTP     8009
#define L7_RTP      8010
#define L7_RTCP     8011
#define L7_UNKNOWN  9999  /* Default SID for unidentified protocols */

/* Protocol types */
#define PROTO_TCP   1
#define PROTO_UDP   2

/* Common UDP ports */
#define DNS_PORT 53
#define DHCP_SERVER_PORT 67
#define DHCP_CLIENT_PORT 68
#define NTP_PORT 123
#define SNMP_PORT 161
#define SNMP_TRAP_PORT 162
#define TFTP_PORT 69
#define RTP_PORT 5004
#define RTCP_PORT 5005

/* Common TCP ports */
#define HTTP_PORT 80
#define HTTPS_PORT 443
#define SSH_PORT 22
#define MSTSC_PORT 3389

/* Domain entry structure */
#define MAX_DOMAIN_LEN 64

struct domain_entry {
    char domain[MAX_DOMAIN_LEN];
    int domain_len;
    int sid;
    bool used;
};

/* Domain update structure for IOCTL operations */
struct domain_update {
    struct domain_entry entry;
    int index;
};

typedef int (*l7_proto_match_t)(const char *data, int data_sz, __u16 dport);

struct l7_proto_entry {
    char *proto_desc;           /* Protocol description */
    int sid;                    /* Protocol ID */
    int proto_type;           /* Protocol type (TCP/UDP) */
    l7_proto_match_t match_func; /* Protocol matching function */
};

/* IOCTL commands */
#define XDPI_IOC_MAGIC 'X'
#define XDPI_IOC_ADD    _IOW(XDPI_IOC_MAGIC, 1, struct domain_entry)
#define XDPI_IOC_DEL    _IOW(XDPI_IOC_MAGIC, 2, int)
#define XDPI_IOC_UPDATE _IOW(XDPI_IOC_MAGIC, 3, struct domain_entry)

/* Other constants */
#define XDPI_DOMAIN_MAX 256
#define MIN_TCP_DATA_SIZE 50

/* Kernel function declaration for BTF export */
#ifdef __KERNEL__
__bpf_kfunc int bpf_xdpi_skb_match(struct __sk_buff *skb, int dir);
#endif

#endif /* _XDPI_BPF_H_ */
