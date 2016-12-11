#ifndef __FSL_OS_SVECTOR_H__
#define __FSL_OS_SVECTOR_H__

/* Syscall info */
#define FSL_OS_SYSCALLS 	331
#define FSL_OS_SYSCALL_NO 	329
#define FSL_OS_CLONE_NO 	330

/* Operations on svector */
#define FSL_OS_LIST_OP 		0
#define FSL_OS_LOAD_OP 		1
#define FSL_OS_COUNT_OP 	2
#define FSL_OS_DEFAULT	 	3
#define FSL_OS_PID_SV	 	4

/* Vector name length */
#define FSL_OS_SVNAME_LEN 	128

#define SYS_CALL_OPEN		1
#define SYS_CALL_READ		2
#define SYS_CALL_WRITE		3
#define SYS_CALL_CLOSE		4
#define SYS_CALL_MKDIR		5

extern void *fsl_os_syscall_ptr;
extern void *fsl_os_clone2_ptr;
extern void *fsl_os_fork_handler;
extern void *fsl_os_exit_handler;

struct fsl_os_svector_t {
	void (*fsl_os_open)(const char *file, int flag);
	void (*fsl_os_read)(char *file, int flag);
	void (*fsl_os_write)(char *file, int flag);
	void (*fsl_os_close)(char *file, int flag);
	void (*fsl_os_mkdir)(const char *file, int flag);
	int (*fsl_os_rmdir)(const char *file, int flag);
	void (*fsl_os_unlink)(const char *file, int flag);
};

struct fsl_os_svectors_t {
	int svc;
	int pid;
	char **svlist;
};

int register_svector(char *, void **, void *);

int unregister_svector(char *);

int fsl_os_sys_clone2(unsigned long *args);

#endif

/* EOF */
