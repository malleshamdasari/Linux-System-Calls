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

#define STACK_SIZE (1024 * 1024)

struct fsl_os_clone_args_t {
	long clone_flags;
	long *sp;
	int (*child_ptr)(void *arg);
	int (*parent_ptr)(void *arg);
	void *args;
};

int child_func(void *arg)
{
	printf("Hello.. Im in child\n");
	sleep(10);
	return 0;
}

int main(int argc, char *argv[])
{
	int pid = 0;
    	char *stack;                    /* Start of stack buffer */
    	char *stackTop;                 /* End of stack buffer */
 	stack = malloc(STACK_SIZE);
    	if (stack == NULL)
        	goto out;
    	stackTop = stack + STACK_SIZE;  /* Assume stack grows downward */


	struct fsl_os_clone_args_t *clone_args;

	clone_args = malloc(sizeof(struct fsl_os_clone_args_t));
	clone_args->child_ptr = child_func;
	clone_args->parent_ptr = child_func;
	clone_args->sp = (long *)stackTop;
	clone_args->clone_flags = CLONE_CHILD_SETTID|CLONE_PARENT_SETTID|SIGCHLD;
	clone_args->args = NULL;
	printf("address: %p \n",clone_args->child_ptr);
	if ((pid = syscall(FSL_OS_CLONE_NO, 100, (void *)clone_args)) != 0 )
		child_func(NULL);
out:
	return 0;
}
