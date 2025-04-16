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
#define L7_HTTP     1
#define L7_HTTPS    2
#define L7_MSTSC    101
#define L7_SSH      102
#define L7_SCP      103
#define L7_WECHAT   104

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

typedef int (*l7_proto_match_t)(const char *data, int data_sz);

struct l7_proto_entry {
    char                *proto_desc;
    int                 sid;
    l7_proto_match_t    match_func;
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
