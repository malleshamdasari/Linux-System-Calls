#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/svector.h>
#include <linux/rwsem.h>
#include <linux/list.h>
#include <linux/syscalls.h>

#define MAX_PID_SV_COUNT	10
#define print printk

struct syscall_vector_t {
	atomic_t refcount;
	char svname[FSL_OS_SVNAME_LEN];
	void *svptr;
	int pid[MAX_PID_SV_COUNT];
	int *b_wrap_override;
	struct list_head vlist;
};

struct fsl_os_clone_args_t {
	long clone_flags;
	long *sp;
	int (*child_ptr)(void *arg);
	int (*parent_ptr)(void *arg);
	void *args;
};

struct rw_semaphore sv_lock;
struct syscall_vector_t sv;

int fsl_os_kmalloc_verify(void *buf)
{
	int ret = 0;

	if (!buf) {
		ret = -ENOMEM;
		print("Out of Memory\n");
	}

	return ret;
}

int register_svector(char *name, void **svptr, void *b_wrap_override)
{
	int err = 0;
	struct syscall_vector_t *tmp;

	tmp = kmalloc(sizeof(struct syscall_vector_t), GFP_KERNEL);
	err = fsl_os_kmalloc_verify((void *)tmp);
	if (err < 0)
		goto out;

	memcpy(tmp->svname, name, FSL_OS_SVNAME_LEN);
	tmp->svptr = svptr;
	tmp->b_wrap_override = (int *)b_wrap_override;
	atomic_set(&(tmp->refcount), 0);
	down_write(&sv_lock);
	list_add(&(tmp->vlist), &(sv.vlist));
	up_write(&sv_lock);
out:
	return err;
}
EXPORT_SYMBOL(register_svector);

int unregister_svector(char *name)
{
	struct list_head *pos, *q;
	struct syscall_vector_t *tmp;
	bool is_vector_found = false;

	down_write(&sv_lock);
	list_for_each_safe(pos, q, &sv.vlist) {
		tmp = list_entry(pos, struct syscall_vector_t, vlist);
		if (memcmp(tmp->svname, name, strlen(name)) == 0) {
			list_del(pos);
			kfree(tmp);
			is_vector_found = true;
			break;
		}
	}
	up_write(&sv_lock);

	if (!is_vector_found)
		print("Error : Vector not loaded.\n");

	return 0;
}
EXPORT_SYMBOL(unregister_svector);

int fsl_os_process_exit_cb(void *ptr)
{
	int i, count = 0;
	struct list_head *pos;
	struct syscall_vector_t *tmp;
	bool is_vector_found = false;

	down_read(&sv_lock);
	list_for_each(pos, &sv.vlist) {
		tmp = list_entry(pos, struct syscall_vector_t, vlist);
		if (tmp->svptr == ptr) {
			atomic_dec(&(tmp->refcount));
			module_put(find_module(tmp->svname));
			is_vector_found = true;
			count = atomic_read(&(tmp->refcount));
			for (i = 0; i < count; i++) {
				if (current->pid == tmp->pid[i])
					tmp->pid[i] = 0;
			}
			break;
		}
	}
	up_read(&sv_lock);

	if (!is_vector_found)
		print("Error : Vector not loaded.\n");

	return 0;
}

long fsl_os_syscall(int option, void *data)
{
	int i = 0, err = 0;
	int count = 0, vec_count = 0;
	char *k_input = NULL;
	int pid_sv_count = 0, rf_count = 0;
	struct task_struct *ptr = NULL;
	struct list_head *pos;
	struct syscall_vector_t *tmp;
	bool is_vector_found = false;
	struct fsl_os_svectors_t *vecnames = NULL;
	struct fsl_os_svectors_t *k_vecnames = NULL;
	char **names_list = NULL;

	if (option == FSL_OS_COUNT_OP) {
		if (!(access_ok(VERIFY_WRITE, data, sizeof(int *)))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			return -1;
		}

		down_read(&sv_lock);
		list_for_each(pos, &sv.vlist) {
			tmp = list_entry(pos, struct syscall_vector_t,
					vlist);
			count++;
		}
		up_read(&sv_lock);
		*(int *)data = count;
	} else if (option == FSL_OS_LIST_OP) {
		vecnames = (struct fsl_os_svectors_t *)data;
		if (!(access_ok(VERIFY_READ, data,
					sizeof(struct fsl_os_svectors_t)))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			goto out;
		}
		k_vecnames = kmalloc(sizeof(struct fsl_os_svectors_t),
								GFP_KERNEL);
		err = fsl_os_kmalloc_verify(k_vecnames);
		if (err < 0)
			goto out;
		if (copy_from_user(k_vecnames, vecnames,
					sizeof(struct fsl_os_svectors_t))) {
			err = -EFAULT;
			print("Error : copy_from_user failed.\n");
			goto free_k_vecnames;
		}
		vec_count = k_vecnames->svc;

		if (!(access_ok(VERIFY_READ, k_vecnames->svlist,
						vec_count * sizeof(char *)))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			goto free_k_vecnames;
		}

		names_list = kmalloc(vec_count * sizeof(char *), GFP_KERNEL);
		err = fsl_os_kmalloc_verify(names_list);
		if (err < 0)
			goto free_k_vecnames;

		if (copy_from_user(names_list, k_vecnames->svlist,
					vec_count * sizeof(char *))) {
			err = -EFAULT;
			print("Error : copy_from_user failed.\n");
			goto free_names_list;
		}

		for (count = 0; count < vec_count; count++) {
			if (!(access_ok(VERIFY_WRITE, names_list[count],
							FSL_OS_SVNAME_LEN))) {
				err = -EACCES;
				print("Error: access_ok failed\n");
				goto free_names_list;
			}
		}

		count = 0;

		down_read(&sv_lock);
		list_for_each(pos, &sv.vlist) {
			if (count >= vec_count)
				break;
			tmp = list_entry(pos, struct syscall_vector_t,
					vlist);
			if (tmp && tmp->svname) {
				err = copy_to_user(names_list[count],
					tmp->svname, FSL_OS_SVNAME_LEN);
			}
			count++;
		}
		up_read(&sv_lock);

free_names_list:
		kfree(names_list);

free_k_vecnames:
		kfree(k_vecnames);

	} else if (option == FSL_OS_LOAD_OP) {

		if (!(access_ok(VERIFY_READ, data, FSL_OS_SVNAME_LEN))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			return -1;
		}

		k_input = kmalloc(FSL_OS_SVNAME_LEN, GFP_KERNEL);
		err = fsl_os_kmalloc_verify((void *)k_input);
		if (err < 0)
			goto err_kmalloc;

		if (copy_from_user(k_input, data, FSL_OS_SVNAME_LEN)) {
			err = -EFAULT;
			print("Error : copy_from_user failed.\n");
			goto err_kmalloc;
		}

		ptr = get_current();

		if (ptr->sv_ptr)
			fsl_os_process_exit_cb(ptr->sv_ptr);

		down_read(&sv_lock);
		list_for_each(pos, &sv.vlist) {
			tmp = list_entry(pos, struct syscall_vector_t,
					vlist);
			if (memcmp(tmp->svname, k_input,
					strlen(k_input)) == 0) {
				try_module_get(find_module(tmp->svname));
				atomic_inc(&(tmp->refcount));
				ptr->sv_ptr = tmp->svptr;
				ptr->wrap_override = tmp->b_wrap_override;
				ptr->is_vector_set = 1;
				is_vector_found = true;
				rf_count = atomic_read(&(tmp->refcount));
				tmp->pid[rf_count-1] = ptr->pid;
				break;
			}
		}

		up_read(&sv_lock);
		if (!is_vector_found) {
			print("Error : Vector not loaded.\n");
			err = -EINVAL;
		}
err_kmalloc:
		kfree(k_input);
	} else if (option == FSL_OS_DEFAULT) {
		ptr = get_current();
		if (ptr->sv_ptr)
			fsl_os_process_exit_cb(ptr->sv_ptr);
		ptr->sv_ptr = NULL;
	} else if (option == FSL_OS_PID_SV) {
		vecnames = (struct fsl_os_svectors_t *)data;
		if (!(access_ok(VERIFY_READ, data,
					sizeof(struct fsl_os_svectors_t)))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			goto out;
		}
		k_vecnames = kmalloc(sizeof(struct fsl_os_svectors_t),
								GFP_KERNEL);
		err = fsl_os_kmalloc_verify(k_vecnames);
		if (err < 0)
			goto out;
		if (copy_from_user(k_vecnames, vecnames,
					sizeof(struct fsl_os_svectors_t))) {
			err = -EFAULT;
			print("Error : copy_from_user failed.\n");
			goto free_ksv;
		}
		vec_count = k_vecnames->svc;

		if (!(access_ok(VERIFY_READ, k_vecnames->svlist,
						vec_count * sizeof(char *)))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			goto free_ksv;
		}

		names_list = kmalloc(vec_count * sizeof(char *), GFP_KERNEL);
		err = fsl_os_kmalloc_verify(names_list);
		if (err < 0)
			goto free_ksv;

		if (copy_from_user(names_list, k_vecnames->svlist,
					vec_count * sizeof(char *))) {
			err = -EFAULT;
			print("Error : copy_from_user failed.\n");
			goto free_nl;
		}

		for (count = 0; count < vec_count; count++) {
			if (!(access_ok(VERIFY_WRITE, names_list[count],
							FSL_OS_SVNAME_LEN))) {
				err = -EACCES;
				print("Error: access_ok failed\n");
				goto free_nl;
			}
		}

		count = 0;
		pid_sv_count = 0;
		down_read(&sv_lock);
		list_for_each(pos, &sv.vlist) {
			if (count >= vec_count)
				break;
			tmp = list_entry(pos, struct syscall_vector_t,
					vlist);
			if (tmp && tmp->svname) {
				rf_count = atomic_read(&(tmp->refcount));
				for (i = 0; i < rf_count; i++) {
					if (k_vecnames->pid == tmp->pid[i]) {
						err = copy_to_user(names_list[
				pid_sv_count], tmp->svname, FSL_OS_SVNAME_LEN);
					pid_sv_count++;
					}
				}
			}
			count++;
		}
		up_read(&sv_lock);
		*(int *)data = pid_sv_count;

free_nl:
		kfree(names_list);

free_ksv:
		kfree(k_vecnames);
	}
out:
	return err;
}

int fsl_os_process_fork_cb(void *ptr, int pid)
{
	int count = 0;
	struct list_head *pos;
	struct syscall_vector_t *tmp;
	bool is_vector_found = false;

	down_read(&sv_lock);
	list_for_each(pos, &sv.vlist) {
		tmp = list_entry(pos, struct syscall_vector_t, vlist);
		if (tmp->svptr == ptr) {
			atomic_inc(&(tmp->refcount));
			try_module_get(find_module(tmp->svname));
			is_vector_found = true;
			count = atomic_read(&(tmp->refcount));
			tmp->pid[count-1] = pid;
			break;
		}
	}

	up_read(&sv_lock);
	if (!is_vector_found)
		print("Error : Vector not loaded.\n");

	return 0;
}

asmlinkage long fsl_os_clone2(int option, void *data)
{
	int err = 0, pid;
	//struct pid *pid_struct;
	//struct task_struct *tsk;
	struct fsl_os_clone_args_t *clone_args;

	/* No arguments: -EINVAL for NULL */
	if (data == NULL) {
		printk("No arguments passed: Failed. \n");
		err = -EINVAL;
		goto out;
        }
	
	/* Check the read access permissions of userspace arguments. */
	if(!access_ok(VERIFY_READ, data, sizeof(struct fsl_os_clone_args_t))) {
		printk(KERN_ERR "Checking read permissions: Failed. \n");
		err = -EFAULT;
		goto out;
	}

	/* Allocate the memory for arguments structure. */
	if ((clone_args = kmalloc(sizeof(struct fsl_os_clone_args_t),
						GFP_KERNEL)) == NULL) {
		printk(KERN_ERR "Memory Allocation of arguments: Failed. \n");
		err = -ENOMEM;
		goto out;
	}

	/* Get the userspace arguments. */
	if(copy_from_user(clone_args, (struct fsl_os_clone_args_t *)data,
				sizeof(struct fsl_os_clone_args_t))!=0) {
		printk(KERN_ERR "Copying the arguments from user: Failed. \n");
		err = -EFAULT;	
		goto out;
	}

	pid = fsl_os_sys_clone2((unsigned long *)data);
	printk("pid: %d \n",pid);
	//pid_struct = find_get_pid(pid);
	//tsk = pid_task(pid_struct,PIDTYPE_PID);
#if 0
	int err = 0, pid;
	struct pid *pid_struct;
	struct task_struct *tsk;
	char *k_input = NULL;
	int rf_count = 0;
	struct task_struct *ptr = NULL;
	struct list_head *pos;
	struct syscall_vector_t *tmp;
	bool is_vector_found = false;

	pid = fsl_os_sys_clone2((unsigned long *)data);
	pid_struct = find_get_pid(pid);
	tsk = pid_task(pid_struct,PIDTYPE_PID);

	if (tsk != NULL) {
		if (!(access_ok(VERIFY_READ, data, FSL_OS_SVNAME_LEN))) {
			err = -EACCES;
			print("Error : access_ok returned FALSE\n");
			return -1;
		}

		k_input = kmalloc(FSL_OS_SVNAME_LEN, GFP_KERNEL);
		err = fsl_os_kmalloc_verify((void *)k_input);
		if (err < 0)
			goto err_kmalloc;

		if (copy_from_user(k_input, data, FSL_OS_SVNAME_LEN)) {
			err = -EFAULT;
			print("Error : copy_from_user failed.\n");
			goto err_kmalloc;
		}

		ptr = get_current();

		if (ptr->sv_ptr)
			fsl_os_process_exit_cb(ptr->sv_ptr);

		down_read(&sv_lock);
		list_for_each(pos, &sv.vlist) {
			tmp = list_entry(pos, struct syscall_vector_t,
					vlist);
			if (memcmp(tmp->svname, k_input,
					strlen(k_input)) == 0) {
				try_module_get(find_module(tmp->svname));
				atomic_inc(&(tmp->refcount));
				ptr->sv_ptr = tmp->svptr;
				ptr->wrap_override = tmp->b_wrap_override;
				ptr->is_vector_set = 1;
				is_vector_found = true;
				rf_count = atomic_read(&(tmp->refcount));
				tmp->pid[rf_count-1] = ptr->pid;
				break;
			}
		}

		up_read(&sv_lock);
		if (!is_vector_found) {
			print("Error : Vector not loaded.\n");
			err = -EINVAL;
		}
err_kmalloc:
		kfree(k_input);
	}
#endif
	printk("flag: %d \n",option);
out:
	return pid;
}

static int __init fsl_os_syscall_init(void)
{
	if (fsl_os_syscall_ptr == NULL) {
		init_rwsem(&sv_lock);
		down_write(&sv_lock);
		INIT_LIST_HEAD(&sv.vlist);
		up_write(&sv_lock);
		fsl_os_fork_handler = fsl_os_process_fork_cb;
		fsl_os_exit_handler = fsl_os_process_exit_cb;
		fsl_os_syscall_ptr = fsl_os_syscall;
		print("svector module is installed\n");
	}
	if (fsl_os_clone2_ptr == NULL)
		fsl_os_clone2_ptr = fsl_os_clone2;
	return 0;
}

static void __exit fsl_os_syscall_exit(void)
{
	if (fsl_os_syscall_ptr == fsl_os_syscall) {
		fsl_os_fork_handler = NULL;
		fsl_os_exit_handler = NULL;
		fsl_os_syscall_ptr = NULL;
	}
	if (fsl_os_clone2_ptr != NULL)
		fsl_os_clone2_ptr = NULL;
	print("svector module is unintstalled\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Mallesham Dasari");
MODULE_DESCRIPTION("Syscall for adding/deleting Syscall Vectors");
module_init(fsl_os_syscall_init);
module_exit(fsl_os_syscall_exit);

/* EOF */
