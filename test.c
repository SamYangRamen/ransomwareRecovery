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
#include "signature.h"

// cat /usr/src/kernels/3.10.0-1062.el7.x86_64/include/linux/kallsyms.h | grep "kallsyms_lookup_name"
// find -name unistd_32.h

MODULE_LICENSE("GPL");

#define PATH_MAX 4096
#define BUF_SIZE 1024

char *start_dir = "/home/rnd/monitor/";
char *backup_dir = "/home/rnd/fiotest/";
monitor_file *file_list;
monitor_flag *flag_list;
signature *signature_list;

void **sys_call_table;
int count;
int dummy_count;
int open_count;
int fd_count;
int fd, wd;

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
static void do_backup(const char *orig_path, int inode, monitor_file **file_list)
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
	strcpy(copy_path, backup_dir);
	time_cat(copy_path);
	strcat(copy_path, ".lsware");
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
	set_fs (oldfs);

	add_file(orig_path, copy_path, file_list, 0, inode);
	kfree(copy_path);

	printk("Backup Complete\n");
}

asmlinkage int (*original_open) (const char *, int, mode_t);
asmlinkage int new_open(const char *pathname, int flags, mode_t mode)
{
	if(!strstr(pathname, start_dir))
		return (*original_open)(pathname, flags, mode);

	struct kstat st;
	memset(&st, 0, sizeof(st));
	vfs_stat(pathname, &st);

	int is_sig = is_signature_in(pathname, signature_list, st.size);

	if(is_sig & EXT_O)
	{
		if(flags & O_CREAT)
		{
			if(!is_flag_in(O_CREAT, st.ino, flag_list))
			{
				add_flag(O_CREAT, st.ino, &flag_list);
			}
		}
		else if((flags & O_RDWR) || (flags & O_NOATIME))
		{
			if(is_flag_in(O_CREAT, st.ino, flag_list))
			{
				if((is_sig & SIG_O) && st.size != 0)
				{
					do_backup(pathname, st.ino, &file_list);
					//printk_flag_nodes(flag_list);
					del_flag(O_CREAT, st.ino, &flag_list);
				}
			}
			else
			{
				if((is_sig & SIG_O) && st.size != 0 && !is_file_in(pathname, file_list))
				{
					do_backup(pathname, st.ino, &file_list);
					//printk_file_nodes(file_list);
				}
			}
		}
	}

	//printk("-----------------------------\n");
	//printk("[inode : %d][fsize : %d][ctime : %d][mtime : %d]\n", st.ino, st.size, st.ctime, st.mtime);
	//do_backup(pathname);
	//printk("-----------------------------\n");

	return (*original_open)(pathname, flags, mode);
}

/*
asmlinkage ssize_t (*original_read) (int, void *, size_t);
asmlinkage ssize_t new_read(int fd, void *buf, size_t nbytes)
{
	return (*original_read)(fd, buf, nbytes);
}

asmlinkage ssize_t (*original_write) (int fd, void *buf, size_t n);
asmlinkage ssize_t new_write(int fd, void *buf, size_t n)
{
	return (*original_write)(fd, buf, n);
}

asmlinkage int (*original_creat) (const char *, mode_t);
asmlinkage int new_creat(const char *file, mode_t mode)
{
	return (*original_creat)(file, mode);
}
*/

asmlinkage int (*original_rename) (const char *, const char *);
asmlinkage int new_rename(const char *oldpath, const char *newpath)
{
	if(strstr(oldpath, start_dir) && strstr(newpath, start_dir))
	{
		printk(KERN_ALERT "RENAME : %s -> %s\n", oldpath, newpath);
		//do_backup(oldpath);
	}

	return (*original_rename)(oldpath, newpath);
}

asmlinkage int (*original_unlink) (const char *);
asmlinkage int new_unlink(const char *pathname)
{
	if(strstr(pathname, start_dir) || strstr(pathname, backup_dir))
	{
		//make_dummy_file(pathname);
		printk(KERN_ALERT "UNLINK : %s\n", pathname);
		if(is_file_in(pathname, file_list))
			del_file(pathname, &file_list);
		printk_file_nodes(file_list);
	}
	return (*original_unlink)(pathname);
}

/*
asmlinkage int (*original_close) (int fd);
asmlinkage int new_close(int fd)
{
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
	init_signature_list(&signature_list);
	//printk_signature_nodes(signature_list);

	sys_call_table = kallsyms_lookup_name("sys_call_table"); // maybe returned address of sys_call_table

	disable_page_protection();
	//EnablePageWriting();
	{
		original_open = sys_call_table[__NR_open];
		//original_read = sys_call_table[__NR_read];
		//original_write = sys_call_table[__NR_write];
		//original_creat = sys_call_table[__NR_creat];
		original_rename = sys_call_table[__NR_rename];
		original_unlink = sys_call_table[__NR_unlink];
		//original_close = sys_call_table[__NR_close];
		sys_call_table[__NR_open] = new_open;
		//sys_call_table[__NR_read] = new_read;
		//sys_call_table[__NR_write] = new_write;
		//sys_call_table[__NR_creat] = new_creat;
		sys_call_table[__NR_rename] = new_rename;
		sys_call_table[__NR_unlink] = new_unlink;
		//sys_call_table[__NR_close] = new_close;
	}
	//DisablePageWriting();
	enable_page_protection();

	printk(KERN_ALERT "MODULE INSERTED\n");
	return 0;
}

static void __exit exit_hello(void) {
	
	flush_signature_nodes(&signature_list);

	disable_page_protection();
	//EnablePageWriting();
	{
		sys_call_table[__NR_open] = original_open;
		//sys_call_table[__NR_read] = original_read;
		//sys_call_table[__NR_write] = original_write;
		//sys_call_table[__NR_creat] = original_creat;
		sys_call_table[__NR_rename] = original_rename;
		sys_call_table[__NR_unlink] = original_unlink;
		//sys_call_table[__NR_close] = original_close;
	}
	//DisablePageWriting();
	enable_page_protection();

	printk(KERN_ALERT "MODULE REMOVED\n");
}

module_init(init_hello);
module_exit(exit_hello);
