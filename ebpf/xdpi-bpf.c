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
#include <linux/uaccess.h>


#define XDPI_DOMAIN_MAX 256
#define MAX_DOMAIN_LEN 64

typedef enum {
    INGRESS,
    EGRESS,
} direction_t;

typedef enum {
    L7_HTTP = 1,
    L7_HTTPS = 2,
    L7_MSTSC = 101,
    L7_SSH = 103,
    L7_SCP = 104,
} proto_id_t;

struct domain_entry {
    char domain[MAX_DOMAIN_LEN];
    int domain_len;
    int sid;
    bool used;
};

struct domain_update {
    struct domain_entry entry;
    int index;
};

typedef int (*l7_proto_match_t)(const char *data, int data_sz);

struct l7_proto_entry {
    char *proto_desc;
    int  sid;
    l7_proto_match_t match_func;
};

// Fixed size array of domain entries
static struct domain_entry domains[XDPI_DOMAIN_MAX];
static DEFINE_SPINLOCK(xdpi_lock);

// IOCTL commands
#define XDPI_IOC_MAGIC 'X'
#define XDPI_IOC_ADD    _IOW(XDPI_IOC_MAGIC, 1, struct domain_entry)
#define XDPI_IOC_DEL    _IOW(XDPI_IOC_MAGIC, 2, int)
#define XDPI_IOC_UPDATE _IOW(XDPI_IOC_MAGIC, 3, struct domain_entry)
#define MIN_TCP_DATA_SIZE   50

// Create a proc file for userspace interaction
static struct proc_dir_entry *xdpi_proc_file;
static struct proc_dir_entry *xdpi_l7_proto_file;

static int add_domain(struct domain_entry *entry);
static int del_domain(int index);
static int update_domain(struct domain_entry *entry, int index);

static __always_inline int is_mstsc(const char *data, int data_sz)
{
    return data_sz > 3 && data[0] == 0x03 && data[1] == 0x00 && data[2] == 0x00;
}

static __always_inline int is_ssh(const char *data, int data_sz)
{
    return data_sz > 10 && data[0] == 'S' && data[1] == 'S' && data[2] == 'H';
}

static __always_inline int is_http(const char *data, int data_sz)
{
    // Check for minimum data size
    if (data_sz < 50)
        return 0;

    // Check for HTTP methods
    if (data[0] == 'G' && data[1] == 'E' && data[2] == 'T' && data[3] == ' ') return 1;  // GET
    if (data[0] == 'P' && data[1] == 'O' && data[2] == 'S' && data[3] == 'T') return 1; // POST

    return 0;
}

static __always_inline int is_https(const char *data, int data_sz)
{
    // Check for minimum data size
    if (data_sz < 50)
        return 0;

    if (data[0] == 0x16 && data[1] == 0x03 && data[5] == 0x01) {
        if (data[2] >= 0x00 && data[2] <= 0x04) {
            return 1;
        }
    }

    return 0;
}

static __always_inline int is_scp(const char *data, int data_sz)
{
    // Check for minimum data size
    if (data_sz < 50)
        return 0;

    // SCP protocol typically starts with 'C' (for file copy) or 'D' (for directory)
    // followed by permissions and file size
    if (data[0] == 'C' || data[0] == 'D') {
        // Check if the next characters are digits (permissions)
        if (data[1] >= '0' && data[1] <= '7' &&
            data[2] >= '0' && data[2] <= '7' &&
            data[3] >= '0' && data[3] <= '7') {
            return 1;
        }
    }

    return 0;
}

static struct l7_proto_entry l7_proto_entries[] = {
    {
        .proto_desc = "http",
        .sid = L7_HTTP,
        .match_func = is_http,
    },
    {
        .proto_desc = "https",
        .sid = L7_HTTPS,
        .match_func = is_https,
    },
    {
        .proto_desc = "mstsc",
        .sid = L7_MSTSC,
        .match_func = is_mstsc,
    },
    {
        .proto_desc = "ssh",
        .sid = L7_SSH,
        .match_func = is_ssh,
    }, 
    {
        .proto_desc = "scp",
        .sid = L7_SCP,
        .match_func = is_scp,
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

__bpf_kfunc int bpf_xdpi_skb_match(struct __sk_buff *skb_ctx, direction_t dir)
{
    struct sk_buff *skb = (struct sk_buff *)skb_ctx;
    
    // For ingress traffic, check if destination port is 80 or 443
    if (dir != INGRESS) {
        return -EACCES;
    }

    // Check if skb is null
    if (!skb)
        return -EINVAL;

    if (unlikely(skb_linearize(skb) != 0))
        return -EFAULT;

    // Check if this is a TCP packet by examining protocol
    if (skb->protocol != htons(ETH_P_IP))
        return -EPROTONOSUPPORT;

    char ip_buf[sizeof(struct iphdr)] = {};
    char tcp_buf[sizeof(struct tcphdr)] = {};
    struct iphdr *ip = skb_header_pointer(skb, skb_network_offset(skb), sizeof(*ip), ip_buf);
    if (!ip || ip->protocol != IPPROTO_TCP)
        return -EPROTONOSUPPORT;

    struct tcphdr *tcp = skb_header_pointer(skb, skb_network_offset(skb) + ip->ihl * 4, sizeof(*tcp), tcp_buf);
    if (!tcp)
        return -EINVAL;
        
    u8 *data = skb->data + skb_network_offset(skb) + ip->ihl * 4 + tcp->doff * 4;
    int data_len = skb->len - (data - skb->data);
    //printk("xdpi: skb data_len %d dport %d\n", data_len, dport);

    spin_lock_bh(&xdpi_lock);

    // Match L7 protocol
    struct l7_proto_entry *proto_entry = NULL;
    for (int i = 0; i < ARRAY_SIZE(l7_proto_entries); i++) {
        if (l7_proto_entries[i].match_func(data, data_len)) {
            proto_entry = &l7_proto_entries[i];
            break;
        }
    }

    if (!proto_entry) {
        spin_unlock_bh(&xdpi_lock);
        return -ENOENT;
    }

    // Return if protocol is not HTTP or HTTPS
    if (proto_entry->sid != L7_HTTP && proto_entry->sid != L7_HTTPS) {
        spin_unlock_bh(&xdpi_lock);
        return proto_entry->sid;
    }

    // Return if data length is insufficient
    if (data_len < MIN_TCP_DATA_SIZE) {
        spin_unlock_bh(&xdpi_lock);
        return proto_entry->sid;
    }

    // Match domain
    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        struct domain_entry *domain_entry = &domains[i];
        if (domain_entry->used && domain_entry->domain_len <= data_len) {
            if (xdpi_strstr(data, data_len, domain_entry->domain, domain_entry->domain_len)) {
                spin_unlock_bh(&xdpi_lock);
                return domain_entry->sid;
            }
        }
    }

    spin_unlock_bh(&xdpi_lock);

    return proto_entry->sid;
}

__diag_pop();

BTF_SET8_START(bpf_kfunc_xdpi_ids_set)
BTF_ID_FLAGS(func, bpf_xdpi_skb_match)
BTF_SET8_END(bpf_kfunc_xdpi_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_xdpi_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_xdpi_ids_set,
};

// Functions to manage the domain array
static int add_domain(struct domain_entry *entry)
{
    int i;
    int ret = -ENOSPC;
    
    if (entry->domain_len >= MAX_DOMAIN_LEN || entry->domain_len <= 0)
        return -EINVAL;

    spin_lock_bh(&xdpi_lock);
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (!domains[i].used) {
            memcpy(domains[i].domain, entry->domain, entry->domain_len);
            domains[i].domain[entry->domain_len] = '\0';
            domains[i].domain_len = entry->domain_len;
            domains[i].sid = entry->sid;
            domains[i].used = true;
            ret = 0;
            break;
        }
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
    .proc_ioctl = xdpi_proc_ioctl,
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

static int __init xdpi_init(void)
{
    int ret;
    int i;

    printk(KERN_INFO "Hello, xDPI!\n");
    
    // Initialize domain array
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        domains[i].used = false;
    }
    
    // Create proc entries
    xdpi_proc_file = proc_create("xdpi_domains", 0644, NULL, &xdpi_proc_ops);
    if (!xdpi_proc_file) {
        pr_err("xdpi: Failed to create proc file\n");
        return -ENOMEM;
    }

    xdpi_l7_proto_file = proc_create("xdpi_l7_proto", 0644, NULL, &xdpi_l7_proto_ops);
    if (!xdpi_l7_proto_file) {
        pr_err("xdpi: Failed to create L7 protocol proc file\n");
        proc_remove(xdpi_proc_file);
        return -ENOMEM;
    }
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_kfunc_xdpi_set);
    if (ret) {
        pr_err("bpf_kfunc_xdpi: Failed to register BTF kfunc ID set\n");
        proc_remove(xdpi_proc_file);
        proc_remove(xdpi_l7_proto_file);
        return ret;
    }
    
    printk(KERN_INFO "bpf_kfunc_xdpi: Module loaded successfully\n");
    return 0; 
}

static void __exit xdpi_exit(void)
{
    if (xdpi_proc_file)
        proc_remove(xdpi_proc_file);
    if (xdpi_l7_proto_file)
        proc_remove(xdpi_l7_proto_file);
    
    printk(KERN_INFO "Goodbye, xDPI!\n");
}

module_init(xdpi_init);
module_exit(xdpi_exit);

MODULE_LICENSE("GPL");                 
MODULE_AUTHOR("Dengfeng Liu <liudf0716@gmail.com>");            
MODULE_DESCRIPTION("xDPI for apfree-wifidog in linux kernel 6.6"); 
MODULE_VERSION("1.0");