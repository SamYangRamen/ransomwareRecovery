#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/unistd.h>
#include <linux/kallsyms.h>
#include <linux/uaccess.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/fcntl.h>
#include <linux/time.h>
#include <linux/stat.h>
#include <linux/inotify.h>
#include <linux/cred.h>

#include "file_handle.h"
#include "flag_handle.h"

// cat /usr/src/kernels/3.10.0-1062.el7.x86_64/include/linux/kallsyms.h | grep "kallsyms_lookup_name"
// find -name unistd_32.h

MODULE_LICENSE("GPL");

#define PATH_MAX 4096
#define BUF_SIZE 1024

typedef struct fd_data {
	int fd;
	char *pathname;
	struct fd_list *next;
} fd_data;

monitor_file *file_list;
monitor_flag *flag_list;

void **sys_call_table;
int count;
int dummy_count;
int open_count;
int fd_count;
int fd, wd;

//int my_fd;
//char my_pathname[100];
//fd_data *fd_list;

void EnablePageWriting(void){
    write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
    write_cr0(read_cr0() | 0x10000);

}

static void time_cat(char *buf)
{
	time_t time_tmp;
	struct tm cur_tm;
	int p;

	struct timespec tv;
	getnstimeofday(&tv);

	time_tmp = tv.tv_sec + 32400;
	time_to_tm(time_tmp, 0, &cur_tm);
	p = strlen(buf);
	
	p += snprintf(buf+p, sizeof(cur_tm.tm_year), "%.2lu", cur_tm.tm_year-100);
	p += snprintf(buf+p, sizeof(cur_tm.tm_mon), "%.2d", cur_tm.tm_mon+1);
	p += snprintf(buf+p, sizeof(cur_tm.tm_mday), "%.2d", cur_tm.tm_mday);
	p += snprintf(buf+p, sizeof(cur_tm.tm_hour), "%.2d", cur_tm.tm_hour);
	p += snprintf(buf+p, sizeof(cur_tm.tm_min), "%.2d", cur_tm.tm_min);
	p += snprintf(buf+p, sizeof(cur_tm.tm_sec), "%.2d", cur_tm.tm_sec);
	p += snprintf(buf+p, sizeof(tv.tv_nsec), "%.6ld", tv.tv_nsec / 1000);
}

/*
static void make_dummy_file(char *pathname)
{
	struct cred *old_cred;
	old_cred = get_current_cred();
	commit_creds(prepare_kernel_cred(0));

	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());
	unsigned char buf[BUF_SIZE];
	char file_path[1024];
	strcpy(file_path, "/home/rnd/source/abc/dummy_");
	int len = strlen(file_path);
	file_path[len] = dummy_count++ + 48;
	file_path[len + 1] = '\0';
	
	memset(buf, 0, sizeof(buf));
	strcpy(buf, pathname);
	strcat(buf, "\0");
	struct file *fp = filp_open(file_path, O_WRONLY|O_CREAT|O_TRUNC, 0777);
	vfs_write(fp, buf, sizeof(buf), &fp->f_pos);
	filp_close(fp, NULL);

	set_fs (oldfs);
	commit_creds(old_cred);
}
*/
static void do_backup(const char *orig_path, int i_node)
{
	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());

	struct file *orig_fp = filp_open(orig_path, O_RDONLY, 0);
	if(IS_ERR(orig_fp))
	{
		printk("Cannot Backup\n");
		//filp_close(orig_fp, NULL);
		return;
	}
	//printk("Backup Start\n");
	char *copy_path = kmalloc(PATH_MAX, GFP_KERNEL);
	memset(copy_path, 0, PATH_MAX);
	//strncpy(copy_path, orig_path, strlen(orig_path) - 4);
	strcpy(copy_path, "/home/rnd/fiotest/");
	time_cat(copy_path);
	strcat(copy_path, ".doc");
	struct file *copy_fp = filp_open(copy_path, O_WRONLY|O_CREAT, 0777);

	unsigned int orig_size = 0;
	struct kstat orig_stat;
	memset(&orig_stat, 0, sizeof(orig_stat));
	vfs_stat(orig_path, &orig_stat);
	orig_size = orig_stat.size;

	unsigned char buf[BUF_SIZE];
	unsigned int quotient = 0, remainder = 0, i;
	quotient = orig_size / BUF_SIZE;
	remainder = orig_size % BUF_SIZE;

	if (quotient > 0)
		for (i = 0; i < quotient; i++) {
			vfs_read(orig_fp, buf, BUF_SIZE, &orig_fp->f_pos);
			vfs_write(copy_fp, buf, BUF_SIZE, &copy_fp->f_pos);
		}
	if (remainder > 0) {
		int padding = 8 - orig_size % 8;

		vfs_read(orig_fp, buf, remainder, &orig_fp->f_pos);
		memset(buf + remainder, (unsigned char)padding, padding * sizeof(unsigned char));
		vfs_write(copy_fp, buf, remainder + padding, &copy_fp->f_pos);
	}
	//vfs_fsync(copy_path, 0);

	filp_close(orig_fp, NULL);
	filp_close(copy_fp, NULL);
	kfree(copy_path);

	set_fs (oldfs);

	add_file(orig_path, copy_path, &file_list, 0, i_node);
	printk("Backup Complete\n");
}

asmlinkage int (*original_open) (const char *, int, mode_t);
asmlinkage int new_open(const char *pathname, int flags, mode_t mode)
{
	if(!strstr(pathname, "/home/rnd/monitor/"))
		return (*original_open)(pathname, flags, mode);

	unsigned int orig_size = 0;
	struct kstat st;
	memset(&st, 0, sizeof(st));
	vfs_stat(pathname, &st);
	orig_size = st.size;

	if((flags & O_CREAT) && (!is_flag_in(O_CREAT, st.ino, flag_list)) && (st.size != 0))
	{
		add_flag(flags, st.ino, &flag_list);
	}
	else if((flags & O_RDWR) || (flags & O_NOATIME))
	{
		if(is_flag_in(O_CREAT, st.ino, flag_list))
		{
			if(st.size != 0)
			{
				do_backup(pathname);
				del_flag(O_CREAT, st.ino, &flag_list);
			}
		}
		else
		{
			if(!is_file_in(pathname, file_list) && st.size != 0)
			{
				do_backup(pathname, st.ino);
				printk_file_nodes(file_list);
			}
		}
	}
	//char flag_list[1000];
	//memset(flag_list, 0, sizeof(flag_list));
	//strcpy(flag_list, "");

/*
	if(flags & O_RDONLY)
		strcat(flag_list, "[O_RDONLY]");
	if(flags & O_WRONLY)
		strcat(flag_list, "[O_WRONLY]");
	if(flags & O_RDWR)
		strcat(flag_list, "[O_RDWR]");
	if(flags & O_CREAT)
		strcat(flag_list, "[O_CREAT]");
	if(flags & O_EXCL)
		strcat(flag_list, "[O_EXCL]");
	if(flags & O_TRUNC)
		strcat(flag_list, "[O_TRUNC]");
	if(flags & O_APPEND)
		strcat(flag_list, "[O_APPEND]");
	if(flags & O_NOCTTY)
		strcat(flag_list, "[O_NOCTTY]");
	if(flags & O_NONBLOCK)
		strcat(flag_list, "[O_NONBLOCK]");
	if(flags & O_NDELAY)
		strcat(flag_list, "[O_NDELAY]");
	if(flags & O_SYNC)
		strcat(flag_list, "[O_SYNC]");
	if(flags & O_DSYNC)
		strcat(flag_list, "[O_DSYNC]");
	//if(flags & O_ASYNC)
		//strcat(flag_list, "[O_ASYNC]");
	if(flags & O_CLOEXEC)
		strcat(flag_list, "[O_CLOEXEC]");
	if(flags & O_DIRECT)
		strcat(flag_list, "[O_DIRECT]");
	if(flags & O_DIRECTORY)
		strcat(flag_list, "[O_DIRECTORY]");
	if(flags & O_PATH)
		strcat(flag_list, "[O_PATH]");
	if(flags & O_TMPFILE)
		strcat(flag_list, "[O_TMPFILE]");
	if(flags & O_NOFOLLOW)
		strcat(flag_list, "[O_NOFOLLOW]");
	if(flags & O_LARGEFILE)
		strcat(flag_list, "[O_LARGEFILE]");
	if(flags & O_NOATIME)
		strcat(flag_list, "[O_NOATIME]");
	if(!strcmp(flag_list, ""))
		strcat(flag_list, "[NONE]");
	printk(KERN_ALERT "OPEN : %s | %s\n", pathname, flag_list);
*/

	//printk("-----------------------------\n");
	printk("[inode : %d][fsize : %d][ctime : %d][mtime : %d]\n", st.ino, st.size, st.ctime, st.mtime);
	do_backup(pathname);
	printk("-----------------------------\n");
	
	//if(strncmp(pathname, "/var/log/journal", 16) && strncmp(pathname, "/var/lib/rsyslog", 16))
		//printk(KERN_ALERT "OPEN : %s\n", pathname);
	
	return (*original_open)(pathname, flags, mode);
}
/*
asmlinkage ssize_t (*original_read) (int, void *, size_t);
asmlinkage ssize_t new_read(int fd, void *buf, size_t nbytes)
{
	//if(my_fd == fd)
		//printk(KERN_INFO "TEST READ : %d %s\n", fd, my_pathname);
	//if(strcmp("4", (char*)buf))
	//if(strstr((char*)buf, "/home/rnd/source/"))
		//printk("READ : %s\n", (char*)buf);
	return (*original_read)(fd, buf, nbytes);
}

asmlinkage ssize_t (*original_write) (int fd, void *buf, size_t n);
asmlinkage ssize_t new_write(int fd, void *buf, size_t n)
{
	//if(my_fd == fd)
		//printk(KERN_INFO "TEST WRITE : %d %s\n", fd, my_pathname);
	//if(strcmp("4", (char*)buf))
		//printk("WRITE : %s\n", (char*)buf);
	//printk("Write hooking\n");
	return (*original_write)(fd, buf, n);
}
*/
asmlinkage int (*original_creat) (const char *, mode_t);
asmlinkage int new_creat(const char *file, mode_t mode)
{
	if(strstr(file, "/home/rnd/monitor/"))
		printk(KERN_ALERT "CREAT : %d | %s\n", mode, file);
	//count++;
	return (*original_creat)(file, mode);
}

asmlinkage int (*original_rename) (const char *, const char *);
asmlinkage int new_rename(const char *oldpath, const char *newpath)
{
	if(strstr(oldpath, "/home/rnd/monitor/") && strstr(newpath, "/home/rnd/monitor/"))
	{
		printk(KERN_ALERT "RENAME : %s -> %s\n", oldpath, newpath);
		//do_backup(oldpath);
	}

	return (*original_rename)(oldpath, newpath);
}

asmlinkage int (*original_unlink) (const char *);
asmlinkage int new_unlink(const char *pathname)
{
	//printk("UNLINK : %s\n", pathname);
	//make_dummy_file();

	if(strstr(pathname, "/home/rnd/monitor/"))
	{
		//make_dummy_file(pathname);
		printk(KERN_ALERT "UNLINK : %s", pathname);
	}
	return (*original_unlink)(pathname);
}

/*
asmlinkage int (*original_close) (int fd);
asmlinkage int new_close(int fd)
{
	//if(my_fd == fd)
		//printk(KERN_INFO "TEST CLOSE : %d %s\n", fd, my_pathname);
	
	return (*original_close)(fd);
}
*/

static void disable_page_protection(void) {
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (value & 0x00010000) {
		value &= ~0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}

static void enable_page_protection(void) {
	unsigned long value;
	asm volatile("mov %%cr0,%0" : "=r" (value));
	if (!(value & 0x00010000)) {
		value |= 0x00010000;
		asm volatile("mov %0,%%cr0": : "r" (value));
	}
}

static int __init init_hello(void) {
	printk(KERN_ALERT "MODULE INSERTED\n");

	sys_call_table = kallsyms_lookup_name("sys_call_table"); // maybe returned address of sys_call_table

	disable_page_protection();
	//printk("original_open : %d\n", *(int*)original_open);
	//EnablePageWriting();
	{
		original_open = sys_call_table[__NR_open];
		//original_read = sys_call_table[__NR_read];
		//original_write = sys_call_table[__NR_write];
		original_creat = sys_call_table[__NR_creat];
		original_rename = sys_call_table[__NR_rename];
		original_unlink = sys_call_table[__NR_unlink];
		//original_close = sys_call_table[__NR_close];
		sys_call_table[__NR_open] = new_open;
		//sys_call_table[__NR_read] = new_read;
		//sys_call_table[__NR_write] = new_write;
		sys_call_table[__NR_creat] = new_creat;
		sys_call_table[__NR_rename] = new_rename;
		sys_call_table[__NR_unlink] = new_unlink;
		//sys_call_table[__NR_close] = new_close;
	}
	//DisablePageWriting();
	enable_page_protection();

	//count++;
	//fd_list = kmalloc(24*count, GFP_KERNEL);
	//fd_list->pathname = kmalloc(10, GFP_KERNEL);
	//strcpy(fd_list->pathname, "ABCDE");	
	//printk("%s\n", fd_list->pathname);
	return 0;
}

static void __exit exit_hello(void) {
	printk(KERN_ALERT "MODULE REMOVED\n");
	disable_page_protection();
	//EnablePageWriting();
	{
		sys_call_table[__NR_open] = original_open;
		//sys_call_table[__NR_read] = original_read;
		//sys_call_table[__NR_write] = original_write;
		sys_call_table[__NR_creat] = original_creat;
		sys_call_table[__NR_rename] = original_rename;
		sys_call_table[__NR_unlink] = original_unlink;
		//sys_call_table[__NR_close] = original_close;
	}
	//DisablePageWriting();
	enable_page_protection();
	//kfree(fd_list);
}

module_init(init_hello);
module_exit(exit_hello);
