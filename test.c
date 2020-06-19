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
#include <linux/dcache.h>
#include <linux/timer.h>
#include <linux/delay.h>
#include <linux/kthread.h>

#include "file_handle.h"
#include "flag_handle.h"
#include "backup_handle.h"
#include "signature.h"
#include "define_value.h"

// cat /usr/src/kernels/3.10.0-1062.el7.x86_64/include/linux/kallsyms.h | grep "kallsyms_lookup_name"
// find -name unistd_32.h

MODULE_LICENSE("GPL");

#define PATH_MAX 4096
#define BUF_SIZE 1024

char *start_dir = "/home/rnd/monitor/";
char *backup_dir = "/rsbak/";

char **infected_file_list;

monitor_file *file_list;
monitor_flag *flag_list;
//monitor_ransom *ransom_list;
signature *signature_list;

void **sys_call_table;
struct task_struct *ts;
void EnablePageWriting(void){
    write_cr0(read_cr0() & (~0x10000));

} 
void DisablePageWriting(void){
    write_cr0(read_cr0() | 0x10000);

}

/*
static int check_dir(struct dir_context *ctx, const char *name, int namelen, loff_t offset, u64 ino, unsigned int d_type) {
	char name_[NAME_MAX];
	memset(name_, 0, sizeof(name_));
	strncpy(name_, name, namelen);
	//printk("name : %s\n", name_);

	if(!is_signature_in(name_, signature_list, 0))
	{
		monitor_file *ptr = file_list;

		while(ptr != NULL)
		{
			int i;
			for(i = strlen(ptr->orig_path) - 1; ptr->orig_path[i] != '/'; i--);
			if(strstr(name_, ptr->orig_path + i) && strcmp(name_, ptr->orig_path + i))
			{
				
			}
		}
	}
	return 0;
}
*/

asmlinkage int (*original_open) (const char *, int, mode_t);
asmlinkage int new_open(const char *pathname, int flags, mode_t mode)
{
	if(!strstr(pathname, start_dir))
		return (*original_open)(pathname, flags, mode);
	
	struct kstat st;
	memset(&st, 0, sizeof(st));
	vfs_stat(pathname, &st);

	int sig_flag = is_signature_in(pathname, signature_list, st.size);

	/*
	printk("%s\n", pathname);
	printk("[%s]", sig_flag & IS_TARGET_FILE? "TARGET" : "NON_TARGET");
	printk("[%s]", sig_flag & IS_EMPTY_FILE? "EMPTY" : "NON_EMPTY");
	printk("[%s]", sig_flag & IS_TEMP_FILE? "TEMP" : "NON_TEMP");
	printk("[%s]", sig_flag & IS_INFECTED_EXT? "INFEXT" : "NON_INFEXT");
	printk("[%s]", sig_flag & IS_INFECTED_SIG? "INFSIG" : "NON_INFSIG");
	printk("\n-------------------------------\n");
	*/

	if((sig_flag & IS_TARGET_FILE)
	&& (sig_flag & IS_INFECTED_EXT) || (sig_flag & IS_INFECTED_SIG))
	{
		recover(pathname, &file_list);
		return (*original_open)("", O_RDONLY, mode);
	}
	//print_flags(flags); // prints for test
	//printk("PATHNAME : %s\n", pathname); // prints for test

	if( (sig_flag & IS_TARGET_FILE)
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
				if(!(sig_flag & IS_INFECTED_SIG)
				&& !(sig_flag & IS_EMPTY_FILE)
				&& !is_file_in(pathname, file_list))
				{
					backup(pathname, &file_list, COMMON_BACKUP);
				}
			}
		}
	}

	//printk("-----------------------------\n");
	//printk("[inode : %d][fsize : %d][ctime : %d][mtime : %d]\n", st.ino, st.size, st.ctime, st.mtime);
	//printk("-----------------------------\n");
	
	//printk_flag_nodes(flag_list);
	check_flag_path(&flag_list);
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
*/

/*
asmlinkage int (*original_creat) (const char *, mode_t);
asmlinkage int new_creat(const char *file, mode_t mode)
{
		printk("CREAT : %s\n", file);
	return (*original_creat)(file, mode);
}
*/

asmlinkage int (*original_rename) (const char *, const char *);
asmlinkage int new_rename(const char *oldpath, const char *newpath)
{
	if(strstr(oldpath, start_dir) && strstr(newpath, start_dir))
	{
		//if(is_ransom_ext(newpath, signature_list))
		if(is_signature_in(newpath, signature_list, NULL) & IS_INFECTED_EXT)
		{
			recover(oldpath, &file_list);
			return (*original_rename)(NULL, NULL);
		}

		printk(KERN_ALERT "RENAME : %s -> %s\n", oldpath, newpath);
	}

	return (*original_rename)(oldpath, newpath);
}

asmlinkage int (*original_unlink) (const char *);
asmlinkage int new_unlink(const char *pathname)
{
	if(strstr(pathname, backup_dir))
	{
		printk("CANNOT DELETE THE BACKUP FILE\n");
		return (*original_unlink)(NULL);
	}

	if(strstr(pathname, start_dir))
	{
		if(is_file_in(pathname, file_list))
		{/*
			int i;
			char location[PATH_MAX];

			struct kstat st;
			memset(&st, 0, sizeof(st));
			vfs_stat(pathname, &st);

			for(i = strlen(pathname) - 1; pathname[i] != '/'; i--);
			strncpy(location, pathname, i + 1);
			location[i] = '\0';

			struct file *fp = filp_open(location, O_RDONLY, 0);

			struct dir_context ctx = {.actor = &check_dir};
			iterate_dir(fp, &ctx);

			del_file_node(pathname, &file_list);*/

			printk("CANNOT DELETE THE BACKUP FILE\n");
			return (*original_unlink)(NULL);
		}
		printk(KERN_ALERT "UNLINK : %s\n", pathname);
		//printk_file_nodes(file_list);
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

int check(void *data)
{
	while(1)
	{
		if(kthread_should_stop())
			break;

		struct file *filp = filp_open("/home/rnd/monitor/ttt.ttt", O_RDONLY, 0);
		if(IS_ERR(filp))
			continue;
		//fcheck(fd);
		struct inode *parent_inode = filp->f_path.dentry->d_parent->d_inode;
		inode_lock(parent_inode);
		vfs_unlink(parent_inode, filp->f_path.dentry, NULL);    
		inode_unlock(parent_inode);

		msleep(1000);
	}

	return 0;
}

static int __init init_hello(void) {
	init_signature_list(&signature_list);
	//printk_signature_nodes(signature_list);

	ts = kthread_run(check, NULL, "kthread");

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
/*
	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());


	int fd = get_unused_fd();
	struct file *fp = filp_open(start_dir, O_RDONLY, 0);
	fd_install(fd, fp);
	putname(start_dir);
	
	struct linux_dirent64 dent;

	int get_dnts = vfs_readdir(fd, &dent, sizeof(struct linux_dirent));
	printk("d_name : %s\n", dent.d_name);
	set_fs(oldfs);
*/

	//struct dentry *dent = d_alloc_name(NULL, start_dir);

	//struct file *start_fp = filp_open("/home/rnd/monitor/abcde/abc/", O_RDONLY, 0);
	/*
	if(start_fp)
	{
		int i;
		struct dentry *rt = start_fp->f_path.dentry;//->d_sb->s_root;
		//for(i = 0; strcmp(rt[i].d_iname, NULL); i++)
			//printk("NAME : %s\n", rt[i].d_iname);
		printk("NAME : %s\n", rt[0].d_iname);
		printk("NAME : %s\n", rt[1].d_iname);
		printk("NAME : %s\n", rt[2].d_iname);
		printk("NAME : %s\n", rt[3].d_iname);
		printk("NAME : %s\n", rt[4].d_iname);
		printk("NAME : %s\n", rt[5].d_iname);
		printk("NAME : %s\n", rt[6].d_iname);
		printk("NAME : %s\n", rt[7].d_iname);
		printk("NAME : %s\n", rt[8].d_iname);
		printk("NAME : %s\n", rt[9].d_iname);
		printk("NAME : %s\n", rt[10].d_iname);
		printk("NAME : %s\n", rt[11].d_iname);
		printk("NAME : %s\n", rt[12].d_iname);
		printk("NAME : %s\n", rt[13].d_iname);
		printk("NAME : %s\n", rt[14].d_iname);
		printk("NAME : %s\n", rt[15].d_iname);
		printk("NAME : %s\n", rt[16].d_iname);
		printk("NAME : %s\n", rt[17].d_iname);
		printk("NAME : %s\n", rt[18].d_iname);
		printk("NAME : %s\n", rt[19].d_iname);
		printk("NAME : %s\n", rt[20].d_iname);
		printk("NAME : %s\n", rt[21].d_iname);
		printk("NAME : %s\n", rt[22].d_iname);
		printk("NAME : %s\n", rt[23].d_iname);
	}*/
	//struct dentry *dent = d_obtain_root(start_fp->f_inode);

	//int i;
	
/*
	printk("NAME : %s\n", dent[0].d_name.name);
	printk("NAME : %s\n", dent[1].d_name.name);
	printk("NAME : %s\n", dent[2].d_name.name);
	printk("NAME : %s\n", dent[3].d_name.name);
	printk("NAME : %s\n", dent[4].d_name.name);
	printk("NAME : %s\n", dent[5].d_name.name);
	printk("NAME : %s\n", dent[6].d_name.name);
	printk("NAME : %s\n", dent[7].d_name.name);
	printk("NAME : %s\n", dent[8].d_name.name);
	printk("NAME : %s\n", dent[9].d_name.name);
	printk("NAME : %s\n", dent[10].d_name.name);
*/

/*
	struct dentry *sample_dentry = NULL;
	struct inode *tmp_inode = start_fp->f_inode;	
	struct list_head *tmp_list = NULL;

	// &start_fp->f_path.dentry->d_subdirs
	// start_fp->f_path.dentry->d_inode->i_dentry.first (X)


	list_for_each(tmp_list, &start_fp->f_path.dentry->d_subdirs)
	{
		sample_dentry = list_entry(tmp_list, struct dentry, d_alias);
		int i;
		printk("filename : ");
		for(i = 0; i < 10; i++)
			printk(" %x ", sample_dentry[1].d_iname[i]);
		printk("\n");
	}
*/

/*
	struct dentry *d_parent_ptr = start_fp->f_path.dentry;
	struct dentry *d_child_ptr = find_next_child(d_parent_ptr, NULL);

	while(d_child_ptr != NULL)
	{
		d_child_ptr = find_next_child(d_parent_ptr, d_child_ptr);
	}
*/

	/*
	char *temp_dir = "/home/rnd/monitor/abcde/";
	struct file *start_fp = filp_open(temp_dir, O_RDONLY, 0);
	struct dir_context ctx = {.actor = &printdir};
	iterate_dir(start_fp, &ctx);*/

	return 0;
}

static void __exit exit_hello(void) {
	
	flush_signature_nodes(&signature_list);
	kthread_stop(ts);

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
