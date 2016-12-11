#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/svector.h>

#define pr_debug printf

int main(int argc, char **argv)
{
	int i, err, vcount;
	struct fsl_os_svectors_t vlist;

	/* First get the number of syscall vectors available */
	err = syscall(FSL_OS_SYSCALL_NO, FSL_OS_COUNT_OP, &vcount);
	if (err < 0) {
		err = -errno;
		goto out;
	}
	vlist.svc = vcount;
	pr_debug("Syscall Vector Count: %d\n", vcount);

	/* Now, get the syscall vector list and display */
	vlist.svlist = calloc(vcount, sizeof(char *));
	for (i = 0; i < vlist.svc; i++)
		vlist.svlist[i] = calloc(1, FSL_OS_SVNAME_LEN);
	err = syscall(FSL_OS_SYSCALL_NO, FSL_OS_LIST_OP, &vlist);
	if (err < 0) {
		err = -errno;
		goto out;
	}

	/* Display the available syscall vector list */
	printf("################### Syscall Vector List ##################\n");
	for (i = 0; i < vlist.svc; i++)
		printf("%d. %s\n", i+1, vlist.svlist[i]);
out:
	if (err < 0)
		pr_debug("Returned with Error: %d\n", err);
	fflush(stdout);
	return err;
}
