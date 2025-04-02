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

// Fixed size array of domain entries
static struct domain_entry domains[XDPI_DOMAIN_MAX];
static DEFINE_SPINLOCK(domains_lock);

// IOCTL commands
#define XDPI_IOC_MAGIC 'X'
#define XDPI_IOC_ADD    _IOW(XDPI_IOC_MAGIC, 1, struct domain_entry)
#define XDPI_IOC_DEL    _IOW(XDPI_IOC_MAGIC, 2, int)
#define XDPI_IOC_UPDATE _IOW(XDPI_IOC_MAGIC, 3, struct domain_entry)

// Create a proc file for userspace interaction
static struct proc_dir_entry *xdpi_proc_file;

static int add_domain(struct domain_entry *entry);
static int del_domain(int index);
static int update_domain(struct domain_entry *entry, int index);

static inline char *xdpi_strstr(const char *haystack, int haystack_sz,
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
    u8 *data;
    int data_len;
    int min_data_len = 50;
    
    // For ingress traffic, check if destination port is 80 or 443
    if (dir != INGRESS) {
        return -1;
    }

    // Check if skb is null
    if (!skb)
        return -1;
    
    if (unlikely(skb_linearize(skb) != 0))
        return -1;

    // Check if this is a TCP packet by examining protocol
    if (skb->protocol != htons(ETH_P_IP))
        return -1;

    char ip_buf[sizeof(struct iphdr)] = {};
    char tcp_buf[sizeof(struct tcphdr)] = {};
    struct iphdr *ip = skb_header_pointer(skb, skb_network_offset(skb), sizeof(*ip), ip_buf);
    if (!ip || ip->protocol != IPPROTO_TCP)
        return -1;

    struct tcphdr *tcp = skb_header_pointer(skb, skb_transport_offset(skb), sizeof(*tcp), tcp_buf);
    if (!tcp)
        return -1;
        
    u16 dport = ntohs(tcp->dest);
    if (dport != 80 && dport != 443)
        return -1;

    // Get the data and data length from the TCP packet
    data = skb_transport_header(skb) + tcp->doff * 4;
    data_len = skb->len - (data - skb->data);

    // Ensure we have enough data to analyze
    if (data_len < min_data_len)
        return -1;


    for (int i = 0; i < XDPI_DOMAIN_MAX; i++) {
        struct domain_entry *entry;
        spin_lock_bh(&domains_lock);
        entry = &domains[i];
        if (entry && entry->used && entry->domain_len <= data_len) {
            char *found = xdpi_strstr(data, data_len, entry->domain, entry->domain_len);
            if (found) {
                spin_unlock_bh(&domains_lock);
                return entry->sid;
            }
        }
        spin_unlock_bh(&domains_lock);
    }

    return -1;
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

    spin_lock_bh(&domains_lock);
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
    spin_unlock_bh(&domains_lock);
    
    return ret;
}

static int del_domain(int index)
{
    if (index < 0 || index >= XDPI_DOMAIN_MAX)
        return -EINVAL;
    
    spin_lock_bh(&domains_lock);
    domains[index].used = false;
    spin_unlock_bh(&domains_lock);
    
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

    spin_lock_bh(&domains_lock);
    memcpy(domains[index].domain, entry->domain, entry->domain_len);
    domains[index].domain[entry->domain_len] = '\0';
    domains[index].domain_len = entry->domain_len;
    domains[index].sid = entry->sid;
    spin_unlock_bh(&domains_lock);
    
    return 0;
}

// Proc file operations
static int xdpi_proc_show(struct seq_file *m, void *v)
{
    int i;
    
    seq_printf(m, "Index | Domain | SID\n");
    seq_printf(m, "---------------------\n");
    
    spin_lock_bh(&domains_lock);
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        if (domains[i].used) {
            seq_printf(m, "%5d | %s | %d\n", i, domains[i].domain, domains[i].sid);
        }
    }
    spin_unlock_bh(&domains_lock);
    
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

static int __init xdpi_init(void)
{
    int ret;
    int i;

    printk(KERN_INFO "Hello, xDPI!\n");
    
    // Initialize domain array
    for (i = 0; i < XDPI_DOMAIN_MAX; i++) {
        domains[i].used = false;
    }
    
    // Create proc entry
    xdpi_proc_file = proc_create("xdpi_domains", 0644, NULL, &xdpi_proc_ops);
    if (!xdpi_proc_file) {
        pr_err("xdpi: Failed to create proc file\n");
        return -ENOMEM;
    }
    
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_kfunc_xdpi_set);
    if (ret) {
        pr_err("bpf_kfunc_xdpi: Failed to register BTF kfunc ID set\n");
        proc_remove(xdpi_proc_file);
        return ret;
    }
    
    printk(KERN_INFO "bpf_kfunc_xdpi: Module loaded successfully\n");
    return 0; 
}

static void __exit xdpi_exit(void)
{
    if (xdpi_proc_file)
        proc_remove(xdpi_proc_file);
    
    printk(KERN_INFO "Goodbye, xDPI!\n");
}

module_init(xdpi_init);
module_exit(xdpi_exit);

MODULE_LICENSE("GPL");                 
MODULE_AUTHOR("Dengfeng Liu <liudf0716@gmail.com>");            
MODULE_DESCRIPTION("xDPI for apfree-wifidog in linux kernel 6.6"); 
MODULE_VERSION("1.0");