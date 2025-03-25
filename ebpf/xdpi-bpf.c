#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>

__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz);

__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_strstr(const char *str, u32 str__sz, const char *substr, u32 substr__sz)
{
    if (substr__sz == 0)
    {
        return 0;
    }
    if (substr__sz > str__sz)
    {
        return -1;
    }
    for (size_t i = 0; i <= str__sz - substr__sz; i++)
    {
        size_t j = 0;
        while (j < substr__sz && str[i + j] == substr[j])
        {
            j++;
        }
        if (j == substr__sz)
        {
            return i;
        }
    }
    return -1;
}


__bpf_kfunc_end_defs();


BTF_KFUNCS_START(bpf_kfunc_xdpi_ids_set)
BTF_ID_FLAGS(func, bpf_strstr)
BTF_KFUNCS_END(bpf_kfunc_xdpi_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_xdpi_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_xdpi_ids_set,
};

static int __init xdpi_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, xDPI!\n");
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_xdpi_set);
    if (ret)
    {
        pr_err("bpf_kfunc_xdpi: Failed to register BTF kfunc ID set\n");
        return ret;
    }
    printk(KERN_INFO "bpf_kfunc_xdpi: Module loaded successfully\n");
    return 0; 
}

static void __exit xdpi_exit(void)
{
    /* Unregister the BTF kfunc ID set */
    unregister_btf_kfunc_id_set(BPF_PROG_TYPE_KPROBE, &bpf_kfunc_xdpi_set);
    printk(KERN_INFO "Goodbye, xDPI!\n");
}

/* Macros to define the module's init and exit points */
module_init(xdpi_init);
module_exit(xdpi_exit);

MODULE_LICENSE("GPL");                 
MODULE_AUTHOR("Dengfeng Liu <liudf0716@gmail.com>");            
MODULE_DESCRIPTION("xDPI for apfree-wifidog"); 
MODULE_VERSION("1.0");            