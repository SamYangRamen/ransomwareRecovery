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
#include <linux/cred.h>
#include <linux/dcache.h>

#include "file_handle.h"
#include "flag_handle.h"
#include "backup_handle.h"
#include "signature.h"
#include "define_value.h"

MODULE_LICENSE("GPL");

char *start_dir = "/home/rnd/monitor/";
char *backup_dir = "/rsbak/";

monitor_file *file_list;
monitor_flag *flag_list;
signature *signature_list;

void **sys_call_table;

long long int ransom_time;

void EnablePageWriting(void){
    write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
    write_cr0(read_cr0() | 0x10000);

}

asmlinkage int (*original_open) (const char *, int, mode_t);
asmlinkage int new_open(const char *pathname, int flags, mode_t mode)
{
	/* All system call occur in real time because of logging, etc.
	   So we need to limit the target monitoring files' boundary.
	   If pathname's location is not target, let it run */
	if(!strstr(pathname, start_dir))
		return (*original_open)(pathname, flags, mode);
	
	/* prevent removing backup files */
	if(strstr(pathname, backup_dir))
	{
		//printk("CANNOT OPEN THE BACKUP FILE\n");
		return (*original_open)(NULL, flags, mode);
	}

	print_open_status(pathname, flags);

	/* To get file's system status data
		1) umode_t mode;	// file type and permission
		2) unsigned int nlink;	// the number of hardlink
		3) uint32_t blksize;	// blocksize for file system I/O
		4) u64 ino;		// inode number
		5) dev_t dev;		// ID of device containing file
		6) dev_t rdev;		// device ID (if special file)
		7) kuid_t uid;		// owner of file
		8) kgid_t gid;		// group ID of owner
		9) loff_t size;		// file size (bytes)
		10) u64 blocks;		// number of 512B blocks allocated
		11) struct timespec64 atime;	// last access time
		12) struct timespec64 mtime;	// last modification time
		13) struct timespec64 ctime;	// last status change time
		14) struct timespec64 btime;	// file creation time */
	struct kstat st;
	memset(&st, 0, sizeof(st));
	vfs_stat(pathname, &st);

	/* To get file's signature status data
		1) #define IS_HAVING_TARGET_EXT 1	// To check if file has the target extension
		2) #define IS_EMPTY_FILE 2	// To check if file size is 0
		3) #define IS_TEMP_FILE 4	// To check if file name has the shape like ".~lock.[name].ext#" or ".[name].swx" or ".[name].swp"
		4) #define IS_INFECTED_EXT 8	// To check if file extension's shape is like ".doc.abc" or ".pptx.crypto" or etc.
		5) #define IS_INFECTED_SIG 16	// To check if file has the signature when the file is displayed in hexadecimal data */
	int sig_flag = check_signature(pathname, signature_list, st.size);

	/* If signs of infection occur, start recovery process */
	if((sig_flag & IS_HAVING_TARGET_EXT)
	&& (sig_flag & IS_INFECTED_EXT)
	|| (sig_flag & IS_INFECTED_SIG))
	{
		ransom_time = num_cur_time(RET_SECOND);
		backup(pathname, &file_list, BACKUP_BEFORE_RECOVERY);
		recover(pathname, &file_list);
		return (*original_open)("", O_RDONLY, mode);
	}

	/* When we handle a file through creating, opening, saveing, modifying, deleteing, moving, renaming, etc.,
	   in open system call, many flags occur, and these flags have some regularity.
	   If the O_CREAT flag appears and after a while the O_RDWR or O_WRONLY or O_NOATIME flag appears,
	   if the file's size is not 0 in this moment, the file is real after handling (in other words, changed file because of handling).
	   Therefore, in this moment we should backup the file */
	if( (sig_flag & IS_HAVING_TARGET_EXT)
	&& !(sig_flag & IS_INFECTED_EXT)
	&& !(sig_flag & IS_TEMP_FILE))
	{
		if(flags & O_CREAT)
		{
			if(!is_flag_in(O_CREAT, pathname, flag_list))
			{
				add_flag_node(O_CREAT, pathname, &flag_list);
			}
		}
		else if((flags & O_RDWR) || (flags & O_NOATIME))
		{
			if(is_flag_in(O_CREAT, pathname, flag_list))
			{
				if(!(sig_flag & IS_INFECTED_SIG)
				&& !(sig_flag & IS_EMPTY_FILE))
				{
					del_flag_node(O_CREAT, pathname, &flag_list);
					backup(pathname, &file_list, COMMON_BACKUP);
				}
			}
			else
			{
				/* But when it is the moment without O_CREAT flag,
				   If none of the backup file exist, we should backup the file */
				if(!(sig_flag & IS_INFECTED_SIG)
				&& !(sig_flag & IS_EMPTY_FILE)
				&& !is_file_in(pathname, file_list))
				{
					backup(pathname, &file_list, COMMON_BACKUP);
				}
			}
		}
	}

	/* If user's file handling (link opening, saving and modifying) is finished, flag list should be empty.
	   Buf if there is remaining nodes, the following function removes them */
	check_flag_path(&flag_list);
	return (*original_open)(pathname, flags, mode);
}

/*
asmlinkage ssize_t (*original_read) (int, void *, size_t);
asmlinkage ssize_t new_read(int fd, void *buf, size_t nbytes)
{
	//if(strstr(__FILE__, start_dir))
		printk("READ : %s\n", __FILE__);
	return (*original_read)(fd, buf, nbytes);
}
*/

/*
asmlinkage ssize_t (*original_write) (int fd, void *buf, size_t n);
asmlinkage ssize_t new_write(int fd, void *buf, size_t n)
{
	return (*original_write)(fd, buf, n);
}
*/

/*
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
		/* If signs of infection occur, start recovery process */
		if(check_signature(newpath, signature_list, NULL) & IS_INFECTED_EXT)
		{
			ransom_time = num_cur_time(RET_SECOND);
			backup(oldpath, &file_list, BACKUP_BEFORE_RECOVERY);
			recover(oldpath, &file_list);
			return (*original_rename)(NULL, NULL);
		}

		mod_file_path(oldpath, newpath, &file_list);		
		printk(KERN_ALERT "RENAME : %s -> %s\n", oldpath, newpath);
	}

	return (*original_rename)(oldpath, newpath);
}

asmlinkage int (*original_unlink) (const char *);
asmlinkage int new_unlink(const char *pathname)
{
	/* prevent removing backup files */
	if(strstr(pathname, backup_dir))
	{
		printk("CANNOT DELETE THE BACKUP FILE\n");
		return (*original_unlink)(NULL);
	}

	/* prevent removing target files when ransomware occur */
	if(strstr(pathname, start_dir) && is_file_in(pathname, file_list))
	{
		if(num_cur_time(RET_SECOND) - ransom_time < PROTECT_TERM)
		{
			printk("CANNOT DELETE THE FILE\n");
			return (*original_unlink)(NULL);
		}
		else
		{
			del_file_node(pathname, &file_list);
			printk(KERN_ALERT "UNLINK : %s\n", pathname);
		}
	}
	
	return (*original_unlink)(pathname);
}
//
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
	ransom_time = 0;

	sys_call_table = kallsyms_lookup_name("sys_call_table"); // returned address of sys_call_table

	disable_page_protection(); // enable to write the sys_call_table's address area
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
	enable_page_protection(); // disable to write the sys_call_table's address area

	printk(KERN_ALERT "MODULE INSERTED\n");
	return 0;
}

static void __exit exit_hello(void) {
	flush_signature_nodes(&signature_list);
	flush_file_nodes(&file_list);

	disable_page_protection(); // enable to write the sys_call_table's address area
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
	enable_page_protection(); // disable to write the sys_call_table's address area

	printk(KERN_ALERT "MODULE REMOVED\n");
}

module_init(init_hello);
module_exit(exit_hello);
