#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <asm/paravirt.h>
#include <linux/svector.h>

#include "fsl_os_sci.h"

unsigned long **fsl_os_svector;
unsigned long original_cr0;

asmlinkage long (*ref_sys_read)(unsigned int, char __user *, size_t);

asmlinkage long (*ref_sys_mkdir)(const char __user *pathname, umode_t mode);

asmlinkage long fsl_os_sys_mkdir(const char __user *pathname, umode_t mode)
{
	long ret = 0;
	struct task_struct *tsk;
	struct fsl_os_svector_t *sv;

	tsk = get_current();
	if (tsk->sv_ptr) {
		pr_debug("function overridden\n");
		sv = (struct fsl_os_svector_t *)tsk->sv_ptr;
		sv->fsl_os_mkdir(pathname, mode);
	} else {
		ret = ref_sys_mkdir(pathname, mode);
		pr_debug("Folder to create: %s\n", pathname);
	}
	return ret;
}

asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{
	long ret;

	ret = ref_sys_read(fd, buf, count);

	if (count == 1 && fd == 0)
		pr_debug("intercept: 0x%02X", buf[0]);
	return ret;
}

static unsigned long **aquire_fsl_os_svector(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;
		if (sct[__NR_close] == (unsigned long *) sys_close)
			return sct;
		offset += sizeof(void *);
	}
	return NULL;
}

int fsl_os_override_syscalls(void)
{
	unsigned long **i = (fsl_os_svector = aquire_fsl_os_svector());

	if (!i)
		return -1;
	ref_sys_mkdir = (void *)fsl_os_svector[__NR_mkdir];
	fsl_os_svector[__NR_mkdir] = (unsigned long *)fsl_os_sys_mkdir;

	return 0;
}

int fsl_os_restore_syscalls(void)
{
	fsl_os_svector[__NR_mkdir] = (unsigned long *)ref_sys_mkdir;

	return 0;
}

static int __init syscall_intercept_begin(void)
{
	original_cr0 = read_cr0();
	write_cr0(original_cr0 & ~0x00010000);
	fsl_os_override_syscalls();
	write_cr0(original_cr0);

	return 0;
}

static void __exit syscall_intercept_end(void)
{
	if (!fsl_os_svector)
		return;

	write_cr0(original_cr0 & ~0x00010000);
	fsl_os_restore_syscalls();
	write_cr0(original_cr0);
}

module_init(syscall_intercept_begin);
module_exit(syscall_intercept_end);

MODULE_LICENSE("GPL");
