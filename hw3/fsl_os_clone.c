#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/svector.h>
#include <linux/syscalls.h>

static int __init fsl_os_clone_init(void)
{
	if (fsl_os_clone2_ptr == NULL)
		fsl_os_clone2_ptr = fsl_os_clone2;
	return 0;
}

static void __exit fsl_os_clone_exit(void)
{
	if (fsl_os_clone2_ptr != NULL)
		fsl_os_clone2_ptr = NULL;
	pr_debug("clone2 module is unintstalled\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mallesham Dasari");
MODULE_DESCRIPTION("Module for new version of clone");
module_init(fsl_os_clone_init);
module_exit(fsl_os_clone_exit);

/* EOF */
