#include "backup_handle.h"

char *common_backup_dir = "/rsbak/";
char *backup_before_recovery_dir = "/rsbak/backedup/";

void backup(char *orig_path, monitor_file **file_list, char backup_type_flag)
{
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
	
	/* To use file function, unlock the kernel memory permission */
	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());

	/* To use file function, get root permission */
	old_cred = get_current_cred();
	commit_creds(prepare_kernel_cred(0));

	backup_fp = filp_open(backup_dir, O_DIRECTORY|O_RDONLY, 0);
	if (IS_ERR(backup_fp))
	{
		printk("Backup directory %s was not made.\n", backup_dir);
		return;
	}

	/* 1) remove ext because of file security and add another dummy signature ext
	   2) check the file name because of making backup file */
	for(i = strlen(orig_path) - 1; orig_path[i] != '.'; i--);
	strcpy(ext, orig_path + i);
	for(j = i; orig_path[j] != '/'; j--);
	strcpy(file_name, orig_path + j);

	/* make the backup file's path
	   rsbak directory is the backup file's location */
	memset(copy_path, 0, PATH_MAX);
	strcpy(copy_path, backup_dir);			//	"/rsbak/"
	cur_time(time_str);
	strcat(copy_path, time_str);			//	"/rsbak/200623123456789012"
	strcat(copy_path, "_");				//	"/rsbak/200623123456789012_"
	strncat(copy_path, orig_path + j + 1, i - j); 	// 	"/rsbak/200623123456789012_filename"
	strcat(copy_path, "lsware");			// 	"/rsbak/200623123456789012_filename.lsware"

	orig_fp = filp_open(orig_path, O_RDONLY, 0);
	copy_fp = filp_open(copy_path, O_WRONLY|O_CREAT|O_TRUNC, 0777);

	if(IS_ERR(orig_fp) || IS_ERR(copy_fp))
	{
		printk("Error is occur, Cannot backup.\n");
		return;
	}

	/* To get file's system status data */
	memset(&orig_st, 0, sizeof(orig_st));
	vfs_stat(orig_path, &orig_st);

	if(orig_st.size == 0)
	{
		printk("Target File's size is 0, Cannot backup.\n");
		filp_close(orig_fp, NULL);
		filp_close(copy_fp, NULL);
		return;
	}

	/* The original file's path is stored at the beginning of the backup file */
	vfs_write(copy_fp, orig_path, PATH_MAX, &copy_fp->f_pos);

	/* Backup the contents of the original file */
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

	if(backup_type_flag == COMMON_BACKUP)
	{
		/* Designate as a monitoring target */
		add_file_node(orig_path, copy_path, file_list, num_cur_time(RET_SECOND));
	}
	
	//printk("Backup the file %s Complete\n", orig_path);

	/* Revert to the previous permission */
	commit_creds(old_cred);

	/* Lock the kernel memory permission */
	set_fs(oldfs);
}

void recover(char *infected_path, monitor_file **file_list)
{
	monitor_file *ptr = *file_list;

	/* 1) Remove the infected file
	   2) Recovered file will be replaced in its place when recover_process is executed */
	remove_real_file(infected_path);

	while(ptr != NULL)
	{
		if(strstr(infected_path, ptr->orig_path))
		{
			/* When the monitoring target is matched, start recovery process */ 
			recover_process(infected_path, ptr->copy_path, file_list);
			break;
		}
		ptr = ptr->next;
	}
}

void recover_process(char *infected_path, char *copy_path, monitor_file **file_list)
{
	struct file *copy_fp, *orig_fp;
	struct kstat copy_st;
	struct cred *old_cred;

	char buf[BUF_SIZE], result[8];
	char recover_path[PATH_MAX], name[NAME_MAX], ext[5];

	int file_size, quotient, remainder, i, j;

	/* To use file function, unlock the kernel memory permission */
	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());

	/* To use file function, get root permission */
	old_cred = get_current_cred();
	commit_creds(prepare_kernel_cred(0));

	copy_fp = filp_open(copy_path, O_RDONLY, 0);
	if(IS_ERR(copy_fp))
		return;

	memset(&copy_st, 0, sizeof(copy_st));
	vfs_stat(copy_path, &copy_st);
	if(copy_st.size == 0)
	{
		filp_close(copy_fp, NULL);
		return;
	}

	/* 1) Extract the original path at the beginning of the backup file
	   2) Recovered file will be replaced in this path */
	vfs_read(copy_fp, recover_path, PATH_MAX, &copy_fp->f_pos);
	orig_fp = filp_open(recover_path, O_WRONLY|O_CREAT|O_TRUNC, 0777);

	quotient = copy_st.size / BUF_SIZE;
	remainder = copy_st.size % BUF_SIZE;

	/* Recover the contents from the copy file */
	if(quotient > 0)
		for (i = 0; i < quotient; i++) {
			vfs_read(copy_fp, buf, BUF_SIZE, &copy_fp->f_pos);

			//for (j = 0; j < BUF_SIZE/8; j++) {
			//	process_message(buf+(j*8), result, key_sets, ENCRYPTION_MODE);
			//	memcpy(buf+(j*8), result, 8);
			//}

			vfs_write(orig_fp, buf, BUF_SIZE, &orig_fp->f_pos);
		}
	if (remainder > 0) {
		int padding = 8 - copy_st.size % 8;

		vfs_read(copy_fp, buf, BUF_SIZE, &copy_fp->f_pos);
		memset(buf+remainder, (unsigned)padding, padding*sizeof(unsigned char));

		//for(i = 0; i < (remainder+padding)/8; i++) {
		//	process_message(buf+(i*8), result, key_sets, ENCRYPTION_MODE);
		//	memcpy(buf+(i*8), result, 8);
		//}

		vfs_write(orig_fp, buf, BUF_SIZE, &orig_fp->f_pos);
	}

	filp_close(copy_fp, NULL);
	filp_close(orig_fp, NULL);

	/* Revert to the previous permission */
	commit_creds(old_cred);

	/* Lock the kernel memory permission */
	set_fs(oldfs);
}
