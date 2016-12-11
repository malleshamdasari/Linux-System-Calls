#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/svector.h>

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

	vlist.pid = atoi(argv[1]);

	/* Now, get the syscall vector list and display */
	vlist.svlist = calloc(vcount, sizeof(char *));
	for (i = 0; i < vlist.svc; i++)
		vlist.svlist[i] = calloc(1, FSL_OS_SVNAME_LEN);
	err = syscall(FSL_OS_SYSCALL_NO, FSL_OS_PID_SV, &vlist);
	if (err < 0) {
		err = -errno;
		goto out;
	}

	if (vlist.svc == 0) {
		printf("It has default svector/the process id is invalid\n");
		goto out;
	}

	/* Display the available syscall vector list */
	printf("Syscall Vector List of process %d\n", atoi(argv[1]));
	for (i = 0; i < vlist.svc; i++)
		printf("%d. %s\n", i+1, vlist.svlist[i]);
out:
	if (err < 0)
		printf("Returned with Error: %d\n", err);
	fflush(stdout);
	return err;
}
