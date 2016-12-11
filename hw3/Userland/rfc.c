#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <linux/svector.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv)

{
	char name[FSL_OS_SVNAME_LEN] = {0x00,};
	int retval;

	if (argc >= 2) {
		memcpy(name, argv[1], FSL_OS_SVNAME_LEN);
		retval = syscall(FSL_OS_SYSCALL_NO, FSL_OS_LOAD_OP, name);
		if (retval < 0) {
			printf("Error : %d - ", errno);
			return -1;
		}
	}

	if (fork() == 0) {
		retval = mkdir("child-mallesh", 0);
		sleep(30);
		if (argc >= 2) {
			printf("Child can also change svector\n");
			memcpy(name, argv[2], FSL_OS_SVNAME_LEN);
			retval = syscall(FSL_OS_SYSCALL_NO, FSL_OS_LOAD_OP,
									name);
			if (retval < 0) {
				printf("Error : %d - ", errno);
				return -1;
			}
		}
		sleep(10);
		retval = mkdir("child-mallesh2", 0);
	} else {
		retval = mkdir("parent-mallesh", 0);
		sleep(100);
	}

	if (retval < 0) {
		printf("Error : %d - ", errno);
		return -1;
	}

	close(retval);

	return 0;
}
