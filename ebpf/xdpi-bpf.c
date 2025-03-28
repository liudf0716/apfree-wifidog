#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/btf_ids.h>
#include <linux/bpf_verifier.h>
#include <linux/filter.h>

__diag_push();
__diag_ignore_all("-Wmissing-prototypes",
		  "Global functions as their definitions will be in xdpi-bpf BTF");

__bpf_kfunc int bpf_xdpi_match(const u8 *str, u16 str__sz)
{
    return -1;
}

__diag_pop();


BTF_SET8_START(bpf_kfunc_xdpi_ids_set)
BTF_ID_FLAGS(func, bpf_xdpi_match)
BTF_SET8_END(bpf_kfunc_xdpi_ids_set)

static const struct btf_kfunc_id_set bpf_kfunc_xdpi_set = {
    .owner = THIS_MODULE,
    .set = &bpf_kfunc_xdpi_ids_set,
};

static int __init xdpi_init(void)
{
    int ret;

    printk(KERN_INFO "Hello, xDPI!\n");
    ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_SCHED_CLS, &bpf_kfunc_xdpi_set);
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
    printk(KERN_INFO "Goodbye, xDPI!\n");
}

/* Macros to define the module's init and exit points */
module_init(xdpi_init);
module_exit(xdpi_exit);

MODULE_LICENSE("GPL");                 
MODULE_AUTHOR("Dengfeng Liu <liudf0716@gmail.com>");            
MODULE_DESCRIPTION("xDPI for apfree-wifidog in linux kernel 6.6"); 
MODULE_VERSION("1.0");            