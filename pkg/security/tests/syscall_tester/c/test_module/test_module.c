#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Datadog");
MODULE_DESCRIPTION("A simple test_module");
MODULE_VERSION("1.0");

static int __init hello_start(void)
{
	printk(KERN_INFO "test_module: Hello there !\n");
	return 0;
}

static void __exit hello_end(void)
{
	printk(KERN_INFO "test_module: Goodbye !\n");
}

module_init(hello_start);
module_exit(hello_end);
