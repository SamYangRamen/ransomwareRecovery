#include "backup_handle.h"

char *common_backup_dir = "/rsbak/";
char *backup_before_recovery_dir = "/rsbak/backedup/";

void backup(char *orig_path, monitor_file **file_list, char backup_type_flag)
{
	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());

	struct file *orig_fp, *copy_fp, *backup_fp;
	struct kstat orig_st;
	struct cred *old_cred;

	char copy_path[PATH_MAX], file_name[NAME_MAX], ext[5], time_str[26], *backup_dir = NULL;	
	unsigned char buf[BUF_SIZE];
	unsigned int quotient, remainder, i, j;

	if(backup_type_flag == COMMON_BACKUP)
	{
		backup_dir = common_backup_dir;
	}
	else if(backup_type_flag == BACKUP_BEFORE_RECOVERY)
	{
		backup_dir = backup_before_recovery_dir;
	}
	
	/* get root permission */
	old_cred = get_current_cred();
	commit_creds(prepare_kernel_cred(0));

	backup_fp = filp_open(backup_dir, O_DIRECTORY|O_RDONLY, 0);
	
	if (IS_ERR(backup_fp))
	{
		printk("Backup directory %s was not made.\n", backup_dir);
		return;
	}

	// 1) remove ext because of file security and add another dummy signature ext
	// 2) check the file name because of making backup file
	for(i = strlen(orig_path) - 1; orig_path[i] != '.'; i--);
	strcpy(ext, orig_path + i);
	for(j = i; orig_path[j] != '/'; j--);
	strcpy(file_name, orig_path + j);

	memset(copy_path, 0, PATH_MAX);
	strcpy(copy_path, backup_dir);
	cur_time(time_str);
	strcat(copy_path, time_str);
	strcat(copy_path, "_");

	strncat(copy_path, orig_path + j + 1, i - j); // cat [file_name].
	strcat(copy_path, "lsware");

	orig_fp = filp_open(orig_path, O_RDONLY, 0);
	copy_fp = filp_open(copy_path, O_WRONLY|O_CREAT|O_TRUNC, 0777);

	memset(&orig_st, 0, sizeof(orig_st));
	vfs_stat(orig_path, &orig_st);
	
	if(IS_ERR(orig_fp) || IS_ERR(copy_fp))
	{
		printk("Error is occur, Cannot backup.\n");
		return;
	}

	else if(orig_st.size == 0)
	{
		printk("Target File's size is 0, Cannot backup.\n");
		filp_close(orig_fp, NULL);
		filp_close(copy_fp, NULL);
		return;
	}

	quotient = orig_st.size / BUF_SIZE;
	remainder = orig_st.size % BUF_SIZE;

	if (quotient > 0)
		for (i = 0; i < quotient; i++)
		{
			vfs_read(orig_fp, buf, BUF_SIZE, &orig_fp->f_pos);
			vfs_write(copy_fp, buf, BUF_SIZE, &copy_fp->f_pos);
		}
	if (remainder > 0)
	{
		int padding = 8 - orig_st.size % 8;

		vfs_read(orig_fp, buf, remainder, &orig_fp->f_pos);
		memset(buf + remainder, (unsigned char)padding, padding * sizeof(unsigned char));
		vfs_write(copy_fp, buf, remainder + padding, &copy_fp->f_pos);
	}

	filp_close(orig_fp, NULL);
	filp_close(copy_fp, NULL);

	add_file(orig_path, copy_path, file_list, num_cur_time_second(time_str));
	printk("Backup the file %s Complete\n", orig_path);
	//printk_file_nodes(*file_list);
	commit_creds(old_cred);
	set_fs(oldfs);
}
