#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/device.h>
#include <linux/cdev.h>

#include "xdpi-bpf.h"

/* Module metadata */
MODULE_LICENSE("GPL");                 
MODULE_AUTHOR("Dengfeng Liu <liudf0716@gmail.com>");            
MODULE_DESCRIPTION("xDPI kernel module for apfree-wifidog"); 
MODULE_VERSION("1.0");



// Fixed size array of domain entries
static struct domain_entry domains[XDPI_DOMAIN_MAX];
static DEFINE_SPINLOCK(xdpi_lock);

#define MIN_TCP_DATA_SIZE   50

// Create a proc file for userspace interaction
static struct proc_dir_entry *xdpi_proc_file;
static struct proc_dir_entry *xdpi_l7_proto_file;
static struct proc_dir_entry *xdpi_domain_num_file;

// Character device for ioctl operations
static int xdpi_major = 0;
static struct class *xdpi_class = NULL;
static struct device *xdpi_device = NULL;
#define XDPI_DEVICE_NAME "xdpi"

static int add_domain(struct domain_entry *entry);
static int del_domain(int index);
static int update_domain(struct domain_entry *entry, int index);
static char *xdpi_strstr(const char *haystack, int haystack_sz,
                                 const char *needle, int needle_sz);

// Protocol identification functions
static __always_inline int is_dns(const char *data, int data_sz, __u16 dport)
{
    // First check if this is a DNS port
    if (dport != DNS_PORT)
        return 0;

    if (data_sz < 12) return 0;
    
    // Check DNS header format
    // ID (2 bytes) + Flags (2 bytes) + Questions (2 bytes) + Answer RRs (2 bytes)
    // + Authority RRs (2 bytes) + Additional RRs (2 bytes)
    return 1;
}

static __always_inline int is_dhcp(const char *data, int data_sz, __u16 dport)
{
    // First check if this is a DHCP port
    if (dport != DHCP_SERVER_PORT && dport != DHCP_CLIENT_PORT)
        return 0;

    if (data_sz < 240) return 0;  // Minimum DHCP message size
    
    // Check DHCP message type
    // First byte after UDP header should be message type
    // 1=DISCOVER, 2=OFFER, 3=REQUEST, 4=DECLINE, 5=ACK, 6=NAK, 7=RELEASE, 8=INFORM
    __u8 msg_type = data[0];
    return (msg_type >= 1 && msg_type <= 8);
}

static __always_inline int is_ntp(const char *data, int data_sz, __u16 dport)
{
    // First check if this is an NTP port
    if (dport != NTP_PORT)
        return 0;

    if (data_sz < 48) return 0;  // Minimum NTP message size
    
    // Check NTP version and mode
    // First byte: LI (2 bits) + Version (3 bits) + Mode (3 bits)
    __u8 first_byte = data[0];
    __u8 version = (first_byte >> 3) & 0x07;
    __u8 mode = first_byte & 0x07;
    
    return (version >= 1 && version <= 4) && (mode >= 1 && mode <= 7);
}

static __always_inline int is_snmp(const char *data, int data_sz, __u16 dport)
{
    // First check if this is an SNMP port
    if (dport != SNMP_PORT && dport != SNMP_TRAP_PORT)
        return 0;

    if (data_sz < 8) return 0;
    
    // Check SNMP version and PDU type
    // First byte should be 0x30 (SEQUENCE)
    // Second byte should be length
    // Third byte should be version (0=SNMPv1, 1=SNMPv2c, 3=SNMPv3)
    return (data[0] == 0x30);
}

static __always_inline int is_tftp(const char *data, int data_sz, __u16 dport)
{
    // First check if this is a TFTP port
    if (dport != TFTP_PORT)
        return 0;

    if (data_sz < 4) return 0;
    
    // Check TFTP opcode
    // First two bytes should be opcode
    // 1=RRQ, 2=WRQ, 3=DATA, 4=ACK, 5=ERROR
    __u16 opcode = (data[0] << 8) | data[1];
    return (opcode >= 1 && opcode <= 5);
}

static __always_inline int is_rtp(const char *data, int data_sz, __u16 dport)
{
    // First check if this is an RTP port
    if (dport != RTP_PORT)
        return 0;

    if (data_sz < 12) return 0;  // Minimum RTP header size
    
    // Check RTP version (should be 2)
    // First byte: V=2, P, X, CC
    __u8 version = (data[0] >> 6) & 0x03;
    return (version == 2);
}

// Existing protocol identification functions
static __always_inline int is_mstsc(const char *data, int data_sz, __u16 dport)
{
    return data_sz > 3 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x00;
}

static __always_inline int is_ssh(const char *data, int data_sz, __u16 dport)
{
    return data_sz > 10 && data[0] == 'S' && data[1] == 'S' && data[2] == 'H';
}

static __always_inline int is_http(const char *data, int data_sz, __u16 dport)
{
    if (data_sz < 50)
        return 0;

    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 1;

    return 0;
}

static __always_inline int is_https(const char *data, int data_sz, __u16 dport)
{
    if (data_sz < 50)
        return 0;

    if (data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01) {
        if (data[2] >= 0x00 && data[2] <= 0x04) {
            return 1;
        }
    }

    return 0;
}

static __always_inline int is_scp(const char *data, int data_sz, __u16 dport)
{
    if (data_sz < 50)
        return 0;

    if (data[0] == 'C' || data[0] == 'D') {
        if (data[1] >= '0' && data[1] <= '7' &&
            data[2] >= '0' && data[2] <= '7' &&
            data[3] >= '0' && data[3] <= '7') {
            return 1;
        }
    }

    return 0;
}

static __always_inline int is_wechat(const char *data, int data_sz, __u16 dport)
{
    if (data_sz > 500 && memcmp(data, "POST /mmtls/", 12) == 0) {
        if (xdpi_strstr(data, 300, "MicroMessenger", 14)) {
            return 1;
        }
        return 1;
    }

    return 0;
}

// Protocol entries array
static struct l7_proto_entry l7_proto_entries[] = {
    // TCP protocols
    {
        .proto_desc = "wechat",
        .sid = L7_WECHAT,
        .proto_type = PROTO_TCP,
        .match_func = is_wechat,
    },
    {
        .proto_desc = "http",
        .sid = L7_HTTP,
        .proto_type = PROTO_TCP,
        .match_func = is_http,
    },
    {
        .proto_desc = "https",
        .sid = L7_HTTPS,
        .proto_type = PROTO_TCP,
        .match_func = is_https,
    },
    {
        .proto_desc = "mstsc",
        .sid = L7_MSTSC,
        .proto_type = PROTO_TCP,
        .match_func = is_mstsc,
    },
    {
        .proto_desc = "ssh",
        .sid = L7_SSH,
        .proto_type = PROTO_TCP,
        .match_func = is_ssh,
    },
    {
        .proto_desc = "scp",
        .sid = L7_SCP,
        .proto_type = PROTO_TCP,
        .match_func = is_scp,
    },
    // UDP protocols
    {
        .proto_desc = "dns",
        .sid = L7_DNS,
        .proto_type = PROTO_UDP,
        .match_func = is_dns,
    },
    {
        .proto_desc = "dhcp",
        .sid = L7_DHCP,
        .proto_type = PROTO_UDP,
        .match_func = is_dhcp,
    },
    {
        .proto_desc = "ntp",
        .sid = L7_NTP,
        .proto_type = PROTO_UDP,
        .match_func = is_ntp,
    },
    {
        .proto_desc = "snmp",
        .sid = L7_SNMP,
        .proto_type = PROTO_UDP,
        .match_func = is_snmp,
    },
    {
        .proto_desc = "tftp",
        .sid = L7_TFTP,
        .proto_type = PROTO_UDP,
        .match_func = is_tftp,
    },
    {
        .proto_desc = "rtp",
        .sid = L7_RTP,
        .proto_type = PROTO_UDP,
        .match_func = is_rtp,
    },
};

static __always_inline char *xdpi_strstr(const char *haystack, int haystack_sz,
                                 const char *needle, int needle_sz)
{
    if (haystack_sz < needle_sz)
        return NULL;

    for (int i = 0; i <= haystack_sz - needle_sz; i++) {
        if (memcmp(haystack + i, needle, needle_sz) == 0)
            return (char *)(haystack + i);
    }

    return NULL;
}

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
          "Global functions as their definitions will be in xdpi-bpf BTF");

__bpf_kfunc int bpf_xdpi_skb_match(struct __sk_buff *skb_ctx, int dir)
{
    struct sk_buff *skb = (struct sk_buff *)skb_ctx;
    struct iphdr *ip = NULL;
    struct tcphdr *tcp = NULL;
    struct udphdr *udp = NULL;
    void *ip_buf = NULL;
    void *tcp_buf = NULL;
    void *udp_buf = NULL;
    int ret = -EINVAL;
    
    // For ingress traffic, check if destination port is 80 or 443
    if (dir != INGRESS) {
        return -EACCES;
    }

    // Check if skb is null
    if (!skb)
        return -EINVAL;

    if (unlikely(skb_linearize(skb) != 0))
        return -EFAULT;

    // Check if this is an IP packet
    if (skb->protocol != htons(ETH_P_IP))
        return -EPROTONOSUPPORT;

    // Allocate buffers for headers
    ip_buf = kmalloc(sizeof(struct iphdr), GFP_ATOMIC);
    if (!ip_buf) {
        ret = -ENOMEM;
        goto out;
    }

    ip = skb_header_pointer(skb, skb_network_offset(skb), sizeof(*ip), ip_buf);
    if (!ip) {
        ret = -EINVAL;
        goto out;
    }

    // Handle TCP
    if (ip->protocol == IPPROTO_TCP) {
        tcp_buf = kmalloc(sizeof(struct tcphdr), GFP_ATOMIC);
        if (!tcp_buf) {
            ret = -ENOMEM;
            goto out;
        }

        tcp = skb_header_pointer(skb, skb_network_offset(skb) + ip->ihl * 4, sizeof(*tcp), tcp_buf);
        if (!tcp) {
            ret = -EINVAL;
            goto out;
        }
            
        u8 *data = skb->data + skb_network_offset(skb) + ip->ihl * 4 + tcp->doff * 4;
        int data_len = skb->len - (data - skb->data);

        // Match L7 protocol
        struct l7_proto_entry *proto_entry = NULL;
        for (int i = 0; i < ARRAY_SIZE(l7_proto_entries); i++) {
            if (l7_proto_entries[i].proto_type == PROTO_TCP &&
                l7_proto_entries[i].match_func(data, data_len, 0)) {
                proto_entry = &l7_proto_entries[i];
                break;
            }
        }

        if (!proto_entry) {
            ret = -ENOENT;
            goto out;
        }

        // Return if protocol is not HTTP or HTTPS
        if (proto_entry->sid != L7_HTTP && proto_entry->sid != L7_HTTPS) {
            ret = proto_entry->sid;
            goto out;
        }

        // Match domain for HTTP/HTTPS
        struct domain_entry *domain_entry = NULL;
        spin_lock_bh(&xdpi_lock);
        for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
            if (domains[i].used && domains[i].domain_len <= data_len) {
                if (xdpi_strstr(data, data_len, domains[i].domain, domains[i].domain_len)) {
                    domain_entry = &domains[i];
                    break;
                }
            }
        }
        spin_unlock_bh(&xdpi_lock);

        if (domain_entry) {
            ret = domain_entry->sid;
        } else {
            ret = proto_entry->sid;
        }
    }
    // Handle UDP
    else if (ip->protocol == IPPROTO_UDP) {
        udp_buf = kmalloc(sizeof(struct udphdr), GFP_ATOMIC);
        if (!udp_buf) {
            ret = -ENOMEM;
            goto out;
        }

        udp = skb_header_pointer(skb, skb_network_offset(skb) + ip->ihl * 4, sizeof(*udp), udp_buf);
        if (!udp) {
            ret = -EINVAL;
            goto out;
        }
            
        u8 *data = skb->data + skb_network_offset(skb) + ip->ihl * 4 + sizeof(*udp);
        int data_len = skb->len - (data - skb->data);

        // Match L7 protocol
        struct l7_proto_entry *proto_entry = NULL;
        for (int i = 0; i < ARRAY_SIZE(l7_proto_entries); i++) {
            if (l7_proto_entries[i].proto_type == PROTO_UDP &&
                l7_proto_entries[i].match_func(data, data_len, ntohs(udp->dest))) {
                proto_entry = &l7_proto_entries[i];
                break;
            }
        }

        if (!proto_entry) {
            ret = -ENOENT;
            goto out;
        }

        ret = proto_entry->sid;
    } else {
        ret = -EPROTONOSUPPORT;
    }

out:
    kfree(ip_buf);
    kfree(tcp_buf);
    kfree(udp_buf);
    return ret;
}

__diag_pop();

/* BTF kfunc set registration - simplified version */
BTF_SET8_START(bpf_xdpi_kfunc_ids)
BTF_ID_FLAGS(func, bpf_xdpi_skb_match, 0)
BTF_SET8_END(bpf_xdpi_kfunc_ids)

static const struct btf_kfunc_id_set bpf_xdpi_kfunc_set = {
    .owner = THIS_MODULE,
    .set = &bpf_xdpi_kfunc_ids,
};

// Functions to manage the domain array
static int add_domain(struct domain_entry *entry)
{
    int i;
    int ret = -ENOSPC;
    int free_idx = -1;
    
    if (entry->domain_len >= MAX_DOMAIN_LEN || entry->domain_len <= 0)
        return -EINVAL;

    spin_lock_bh(&xdpi_lock);
    
    // First check if domain already exists
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domains[i].used && domains[i].domain_len == entry->domain_len) {
            if (memcmp(domains[i].domain, entry->domain, entry->domain_len) == 0) {
                // Domain already exists, update access count and time
                domains[i].access_count = entry->access_count;
                domains[i].last_access_time = entry->last_access_time;
                spin_unlock_bh(&xdpi_lock);
                return 0; // Success, domain already exists
            }
        } else if (!domains[i].used && free_idx == -1) {
            free_idx = i; // Remember first free slot
        }
    }
    
    // Domain doesn't exist, add it if we have space
    if (free_idx != -1) {
        memcpy(domains[free_idx].domain, entry->domain, entry->domain_len);
        domains[free_idx].domain[entry->domain_len] = '\0';
        domains[free_idx].domain_len = entry->domain_len;
        domains[free_idx].sid = entry->sid;
        domains[free_idx].used = true;
        domains[free_idx].access_count = entry->access_count;
        domains[free_idx].last_access_time = entry->last_access_time;
        domains[free_idx].first_seen_time = entry->first_seen_time;
        ret = 0;
    }
    
    spin_unlock_bh(&xdpi_lock);
    
    return ret;
}

static int del_domain(int index)
{
    if (index < 0 || index >= XDPI_DOMAIN_MAX)
        return -EINVAL;
    
    spin_lock_bh(&xdpi_lock);
    domains[index].used = false;
    spin_unlock_bh(&xdpi_lock);
    
    return 0;
}

static int update_domain(struct domain_entry *entry, int index)
{
    if (index < 0 || index >= XDPI_DOMAIN_MAX)
        return -EINVAL;
    
    if (!domains[index].used)
        return -ENOENT;
    
    if (entry->domain_len >= MAX_DOMAIN_LEN || entry->domain_len <= 0)
        return -EINVAL;

    spin_lock_bh(&xdpi_lock);
    memcpy(domains[index].domain, entry->domain, entry->domain_len);
    domains[index].domain[entry->domain_len] = '\0';
    domains[index].domain_len = entry->domain_len;
    domains[index].sid = entry->sid;
    domains[index].access_count = entry->access_count;
    domains[index].last_access_time = entry->last_access_time;
    domains[index].first_seen_time = entry->first_seen_time;
    spin_unlock_bh(&xdpi_lock);
    
    return 0;
}

// Proc file operations
static int xdpi_proc_show(struct seq_file *m, void *v)
{
    int i;
    int l7_count = ARRAY_SIZE(l7_proto_entries);
    
    seq_printf(m, "Index | Domain | SID\n");
    seq_printf(m, "---------------------\n");
    
    spin_lock_bh(&xdpi_lock);
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domains[i].used) {
            seq_printf(m, "%5d | %s | %d\n", 
                      i + l7_count + 1, // Start numbering after L7 protocols
                      domains[i].domain, 
                      domains[i].sid);
        }
    }
    spin_unlock_bh(&xdpi_lock);
    
    return 0;
}

static int xdpi_proc_open(struct inode *inode, struct file *file)
{
    return single_open(file, xdpi_proc_show, NULL);
}

static long xdpi_proc_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    
    int index;
    int ret = 0;
    
    switch (cmd) {
    case XDPI_IOC_ADD:
        struct domain_entry entry;
        memset(&entry, 0, sizeof(entry));
        if (copy_from_user(&entry, (void __user *)arg, sizeof(entry)))
            return -EFAULT;
        
        ret = add_domain(&entry);
        break;
        
    case XDPI_IOC_DEL:
        if (copy_from_user(&index, (void __user *)arg, sizeof(index)))
            return -EFAULT;
        
        ret = del_domain(index);
        break;
        
    case XDPI_IOC_UPDATE:
        struct domain_update update;
        memset(&update, 0, sizeof(update));
        if (copy_from_user(&update, (void __user *)arg, sizeof(update)))
        return -EFAULT;

        ret = update_domain(&update.entry, update.index);
        break;
        
    case XDPI_IOC_LIST:
        struct domain_list list;
        memset(&list, 0, sizeof(list));
        
        // Copy the input structure to get max_count
        if (copy_from_user(&list, (void __user *)arg, sizeof(list)))
            return -EFAULT;
            
        // Fill the domain list
        spin_lock_bh(&xdpi_lock);
        list.count = 0;
        for (int i = 0; i < XDPI_DOMAIN_MAX && list.count < list.max_count; i++) {
            if (domains[i].used) {
                memcpy(&list.domains[list.count], &domains[i], sizeof(struct domain_entry));
                list.count++;
            }
        }
        spin_unlock_bh(&xdpi_lock);
        
        // Copy the result back to userspace
        if (copy_to_user((void __user *)arg, &list, sizeof(list)))
            return -EFAULT;
        break;
        
    default:
        ret = -ENOTTY;
    }
    
    return ret;
}

static const struct proc_ops xdpi_proc_ops = {
    .proc_open = xdpi_proc_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Character device open function
static int xdpi_dev_open(struct inode *inode, struct file *file)
{
    return 0;
}

// Character device release function
static int xdpi_dev_release(struct inode *inode, struct file *file)
{
    return 0;
}

static const struct file_operations xdpi_fops = {
    .owner = THIS_MODULE,
    .open = xdpi_dev_open,
    .release = xdpi_dev_release,
    .unlocked_ioctl = xdpi_proc_ioctl,
};

// Proc file operations for L7 protocols
static int xdpi_l7_proto_show(struct seq_file *m, void *v)
{
    int i;
    
    seq_printf(m, "Index | L7Proto | SID\n");
    seq_printf(m, "----------------------\n");
    
    spin_lock_bh(&xdpi_lock);
    for (i = 0; i < ARRAY_SIZE(l7_proto_entries); i++) {
        seq_printf(m, "%5d | %8s | %d\n", 
                  i + 1,
                  l7_proto_entries[i].proto_desc,
                  l7_proto_entries[i].sid);
    }
    spin_unlock_bh(&xdpi_lock);
    
    return 0;
}

static int xdpi_l7_proto_open(struct inode *inode, struct file *file)
{
    return single_open(file, xdpi_l7_proto_show, NULL);
}

static const struct proc_ops xdpi_l7_proto_ops = {
    .proc_open = xdpi_l7_proto_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

// Proc file operations for domain count
static int xdpi_domain_num_show(struct seq_file *m, void *v)
{
    int i;
    int count = 0;
    
    spin_lock_bh(&xdpi_lock);
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domains[i].used) {
            count++;
        }
    }
    spin_unlock_bh(&xdpi_lock);
    
    seq_printf(m, "%d\n", count);
    
    return 0;
}

static int xdpi_domain_num_open(struct inode *inode, struct file *file)
{
    return single_open(file, xdpi_domain_num_show, NULL);
}

static const struct proc_ops xdpi_domain_num_ops = {
    .proc_open = xdpi_domain_num_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
};

static int __init xdpi_init(void)
{
    int ret;
    int i;

    printk(KERN_INFO "Hello, xDPI!\n");
    
    // Initialize domain array
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        domains[i].used = false;
    }
    
    // Register character device for ioctl operations
    xdpi_major = register_chrdev(0, XDPI_DEVICE_NAME, &xdpi_fops);
    if (xdpi_major < 0) {
        pr_err("xdpi: Failed to register character device: %d\n", xdpi_major);
        return xdpi_major;
    }
    
    // Create device class (kernel 6.6+ uses single parameter)
    xdpi_class = class_create(XDPI_DEVICE_NAME);
    if (IS_ERR(xdpi_class)) {
        ret = PTR_ERR(xdpi_class);
        pr_err("xdpi: Failed to create device class: %d\n", ret);
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
        return ret;
    }
    
    // Create device node (/dev/xdpi)
    xdpi_device = device_create(xdpi_class, NULL, MKDEV(xdpi_major, 0), NULL, XDPI_DEVICE_NAME);
    if (IS_ERR(xdpi_device)) {
        ret = PTR_ERR(xdpi_device);
        pr_err("xdpi: Failed to create device: %d\n", ret);
        class_destroy(xdpi_class);
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
        return ret;
    }
    
    // Create proc entries (for reading domain list)
    xdpi_proc_file = proc_create("xdpi_domains", 0644, NULL, &xdpi_proc_ops);
    if (!xdpi_proc_file) {
        pr_err("xdpi: Failed to create proc file\n");
        device_destroy(xdpi_class, MKDEV(xdpi_major, 0));
        class_destroy(xdpi_class);
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
        return -ENOMEM;
    }

    xdpi_l7_proto_file = proc_create("xdpi_l7_proto", 0644, NULL, &xdpi_l7_proto_ops);
    if (!xdpi_l7_proto_file) {
        pr_err("xdpi: Failed to create L7 protocol proc file\n");
        proc_remove(xdpi_proc_file);
        device_destroy(xdpi_class, MKDEV(xdpi_major, 0));
        class_destroy(xdpi_class);
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
        return -ENOMEM;
    }
    
    xdpi_domain_num_file = proc_create("xdpi_domain_num", 0644, NULL, &xdpi_domain_num_ops);
    if (!xdpi_domain_num_file) {
        pr_err("xdpi: Failed to create domain number proc file\n");
        proc_remove(xdpi_proc_file);
        proc_remove(xdpi_l7_proto_file);
        device_destroy(xdpi_class, MKDEV(xdpi_major, 0));
        class_destroy(xdpi_class);
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
        return -ENOMEM;
    }
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_xdpi_kfunc_set);
    if (ret) {
        pr_err("xdpi_bpf: Failed to register BTF kfunc ID set: %d\n", ret);
        proc_remove(xdpi_proc_file);
        proc_remove(xdpi_l7_proto_file);
        proc_remove(xdpi_domain_num_file);
        device_destroy(xdpi_class, MKDEV(xdpi_major, 0));
        class_destroy(xdpi_class);
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
        return ret;
    }
    
    printk(KERN_INFO "bpf_kfunc_xdpi: Module loaded successfully (device: /dev/%s)\n", XDPI_DEVICE_NAME);
    return 0; 
}

static void __exit xdpi_exit(void)
{
    if (xdpi_proc_file)
        proc_remove(xdpi_proc_file);
    if (xdpi_l7_proto_file)
        proc_remove(xdpi_l7_proto_file);
    if (xdpi_domain_num_file)
        proc_remove(xdpi_domain_num_file);
    
    // Cleanup character device
    if (xdpi_device)
        device_destroy(xdpi_class, MKDEV(xdpi_major, 0));
    if (xdpi_class)
        class_destroy(xdpi_class);
    if (xdpi_major > 0)
        unregister_chrdev(xdpi_major, XDPI_DEVICE_NAME);
    
    printk(KERN_INFO "Goodbye, xDPI!\n");
}

module_init(xdpi_init);
module_exit(xdpi_exit);