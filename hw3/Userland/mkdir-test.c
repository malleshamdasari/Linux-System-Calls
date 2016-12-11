#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <linux/svector.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
	char name[FSL_OS_SVNAME_LEN] = {0x00,};
	int retval;

	if (argc >= 2) {
		memcpy(name, argv[1], FSL_OS_SVNAME_LEN);
		retval = syscall(FSL_OS_SYSCALL_NO, FSL_OS_LOAD_OP, name);
		if (retval < 0) {
			printf("Invalid svector: %d\n", errno);
			retval = -errno;
			goto out;
		}
	}
	retval = mkdir("mallesh1", 0);
	if (argc >= 3) {
		memset(name, 0x00, FSL_OS_SVNAME_LEN);
		memcpy(name, argv[2], FSL_OS_SVNAME_LEN);
		retval = syscall(FSL_OS_SYSCALL_NO, FSL_OS_LOAD_OP, name);
		if (retval < 0) {
			printf("Invalid svector : %d\n", errno);
			retval = -errno;
			goto out;
		}
	}
	retval = mkdir("mallesh2", 0);
	retval = syscall(FSL_OS_SYSCALL_NO, FSL_OS_DEFAULT, NULL);
	if (retval < 0) {
		printf("Invalid svector : %d\n", errno);
		retval = -errno;
		goto out;
	}
	retval = mkdir("mallesh3", 0);
out:
	fflush(stdout);
	return retval;
}
