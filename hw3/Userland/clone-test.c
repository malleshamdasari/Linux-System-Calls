#define _GNU_SOURCE
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sched.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <linux/svector.h>
#include <uapi/linux/sched.h>

/* New stack size for the child process */
#define STACK_SIZE (1024 * 1024)

static int child_func(void *arg)
{
	int retval = 0;

	printf("Child Process\n");
	retval = mkdir("child-clone", 0);
	sleep(2);

	return retval;
}

int main(int argc, char *argv[])
{
	char *stack;
	char *stackTop;
	pid_t pid;
	int retval = 0;
	char name[FSL_OS_SVNAME_LEN] = {0x00,};

	if (argc >= 2) {
		memcpy(name, argv[1], FSL_OS_SVNAME_LEN);
		retval = syscall(FSL_OS_SYSCALL_NO, FSL_OS_LOAD_OP, name);
		if (retval < 0) {
			printf("Vector not set\n");
			goto out;
		}
	}

	stack = malloc(STACK_SIZE);
	if (stack == NULL) {
		printf("No Memory\n");
		goto out;
	}
	stackTop = stack + STACK_SIZE;

	//pid = clone(child_func, stackTop, 0, 0);
	pid = clone(child_func, stackTop, CLONE_SYSCALLS, 0);
	if (pid == -1) {
		printf("Not cloned\n");
		goto out;
	}
	retval = mkdir("parent-clone", 0);
	sleep(1);

	if (waitpid(pid, NULL, 0) == -1) {
		printf("Fsl os Wait\n");
		goto out;
	}
out:
	return retval;
}
