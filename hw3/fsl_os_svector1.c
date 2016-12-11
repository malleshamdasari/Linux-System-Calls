#include <linux/module.h>
#include <linux/svector.h>

#define print printk

char svname[FSL_OS_SVNAME_LEN];
int b_wrap_override[FSL_OS_SYSCALLS];

void fsl_os_open1(char *file, int flag)
{
	print("Open system call\n");
}

void fsl_os_read1(char *file, int flags)
{
	print("Read system call\n");
}

void fsl_os_write1(char *file, int flags)
{
	print("Write system call\n");
}

void fsl_os_close1(char *file, int flags)
{
	print("Close system call\n");
}

void fsl_os_mkdir1(const char *file, int flags)
{
	print("Mkdir1 system call\n");
}

/** Override syscalls operations
 */
static const struct fsl_os_svector_t svector1 = {
fsl_os_open:fsl_os_open1,
fsl_os_read:fsl_os_read1,
fsl_os_write:fsl_os_write1,
fsl_os_close:fsl_os_close1,
fsl_os_mkdir:fsl_os_mkdir1,
};

static int __init new_vector_init(void)
{
	int retval = 0;

	memset(svname, 0, FSL_OS_SVNAME_LEN);
	memcpy(svname, THIS_MODULE->name, FSL_OS_SVNAME_LEN);
	retval = register_svector(svname, (void **)&svector1,
					(void *)b_wrap_override);
	return retval;
}

static void __exit new_vector_exit(void)
{
	unregister_svector(svname);
}

MODULE_AUTHOR("Mallesham Dasari");
MODULE_DESCRIPTION("Syscall vector1");
MODULE_LICENSE("GPL");
module_init(new_vector_init);
module_exit(new_vector_exit);

/* EOF */
