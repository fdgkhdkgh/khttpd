#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/kthread.h>

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("NCTU, Taiwan");
MODULE_DESCRIPTION("kthread sample");
MODULE_VERSION("0.1");

#define DEFAULT_PARAMETER 10

static ushort para = DEFAULT_PARAMETER;
module_param(para, ushort, S_IRUGO);

static ushort para2 = DEFAULT_PARAMETER;
module_param(para2, ushort, S_IRUGO);

static int __init simple_init(void) {
    printk("start simple module init !!\n");
    printk("para : %d\n", para);
    printk("para2 : %d\n", para2);
    return 0;
}

static void __exit simple_exit(void) {
    printk("stop simple module !!\n");
}

module_init(simple_init);
module_exit(simple_exit);

