#include "file_handle.h"

monitor_file *make_file_node(char *orig_path, char *copy_path, long long int new_backup_time)
{
	monitor_file *new_file = kmalloc(sizeof(monitor_file), GFP_KERNEL);
	new_file->orig_path = kmalloc(sizeof(char) * (strlen(orig_path) + 1), GFP_KERNEL);
	memset(new_file->orig_path, 0, sizeof(new_file->orig_path));
	new_file->copy_path = kmalloc(sizeof(char) * (strlen(copy_path) + 1), GFP_KERNEL);
	memset(new_file->copy_path, 0, sizeof(new_file->copy_path));
	strcpy(new_file->orig_path, orig_path);
	strcpy(new_file->copy_path, copy_path);
	new_file->backup_time = new_backup_time;
	new_file->is_last = 1;
	new_file->prev = NULL;
	new_file->next = NULL;
	
	return new_file;
}

void add_file_node(char *orig_path, char *copy_path, monitor_file **head, long long int new_backup_time)
{
	monitor_file *ptr = *head;

	if(ptr != NULL)
	{
		while(ptr->next != NULL)
		{
			if(!strcmp(ptr->orig_path, orig_path))
				ptr->is_last = 0;

			if(ptr->is_last == 0 && new_backup_time - ptr->backup_time >= DEL_TERM)
			{
				/* remove old backup file because backup disk capacity is not infinite */
				remove_real_file(ptr->copy_path);
				ptr = ptr->next;
				del_file_node(ptr->prev->copy_path, head);
			}
			else if(!strcmp(ptr->orig_path, orig_path))
			{
				ptr->is_last = 0;
				ptr = ptr->next;
			}
			else
				ptr = ptr->next;
		}

		if(!strcmp(ptr->orig_path, orig_path))
			ptr->is_last = 0;

		if(ptr->is_last == 0 && new_backup_time - ptr->backup_time >= DEL_TERM)
		{
			/* remove old backup file because backup disk capacity is not infinite */
			monitor_file *temp = ptr->prev;
			remove_real_file(ptr->copy_path);
			del_file_node(ptr->copy_path, head);
			ptr = temp;
		}
	}

	if(ptr == NULL)
	{
		*head = make_file_node(orig_path, copy_path, new_backup_time);
		return;
	}

	ptr->next = make_file_node(orig_path, copy_path, new_backup_time);
	ptr->next->prev = ptr;
}

void del_file_node(char *del_path, monitor_file **head)
{
	/* If the del_path is one of the monitoring target, remove the node from the linked list */

	monitor_file *ptr = *head;

	if(ptr == NULL)
		return;

	while(ptr != NULL)
	{
		if(!strcmp(ptr->orig_path, del_path))
		{
			remove_real_file(ptr->copy_path);

			monitor_file *temp = ptr;
			ptr = ptr->next;

			if(temp == *head)
			{
				*head = (*head)->next;
				if(*head != NULL)
					(*head)->prev = NULL;
			}
			else
			{
				if(temp->prev != NULL)
					temp->prev->next = temp->next;

				if(temp->next != NULL)
					temp->next->prev = temp->prev;
			}

			kfree(temp);
		}
		else
			ptr = ptr->next;
	}
}

void printk_file_nodes(monitor_file *head)
{
	/* I used this function to test or debug */

	printk("----------------------------monitored file list----------------------------\n");
	if(head == NULL)
		printk("NULL\n");

	monitor_file *ptr = head;
	
	while(ptr != NULL)
	{
		printk("%s %s\n", ptr->orig_path, ptr->copy_path);
		ptr = ptr->next;
	}
	printk("---------------------------------------------------------------------------\n");
}

void flush_file_nodes(monitor_file **head)
{
	/* make linked list NULL */

	monitor_file *ptr;

	while(*head != NULL)
	{
		ptr = *head;
		*head = (*head)->next;
		kfree(ptr);
	}
}

void mod_file_path(char *before_path, char *after_path, monitor_file **head)
{
	/* Change the file's path in the linked lists of target monitoring file
				     and the path at the beginning of the backup file */

	monitor_file *ptr = *head;

	while(ptr != NULL)
	{
		if(!strcmp(ptr->orig_path, before_path))
		{
			/* To use file function, unlock the kernel memory permission */
			mm_segment_t oldfs = get_fs();
			set_fs(get_ds());

			/* To use file function, get root permission */
			struct cred *old_cred;
			old_cred = get_current_cred();
			commit_creds(prepare_kernel_cred(0));

			/* Change the original file's path stored at the beginning of the backup file */
			struct file *copy_fp = filp_open(ptr->copy_path, O_RDWR, 0777);
			vfs_write(copy_fp, after_path, PATH_MAX, &copy_fp->f_pos);
			filp_close(copy_fp, NULL);	

			/* Revert to the previous permission */
			commit_creds(old_cred);

			/* Lock the kernel memory permission */
			set_fs(oldfs);

			/* Change the original file's path stored at the linked lists of target monitoring file */
			kfree(ptr->orig_path);
			ptr->orig_path = kmalloc(sizeof(char) * (strlen(after_path) + 1), GFP_KERNEL);
			strcpy(ptr->orig_path, after_path);
		}

		ptr = ptr->next;
	}
}

int is_file_in(char *file_path, monitor_file *head)
{
	/* If the file_path is one of the monitoring target, return 1. If not, return 0 */

	monitor_file *ptr = head;
	
	while(ptr != NULL)
	{
		if(!strcmp(file_path, ptr->orig_path) || !strcmp(file_path, ptr->copy_path))
			return 1;
		ptr = ptr->next;
	}

	return 0;
}

void make_real_file_name(char *before_name, char *after_name)
{
	/*
	   1) "~.lock.abcd.doc#", ".abcd.swx" and ".abcd.swp" are temporary file
	   2) If before_name is "~.lock.abcd.doc#" or ".abcd.swx" or ".abcd.swp", after_name will be "abcd.doc"
	   3) ~.lock.filename.ext# shape appears in openning or saving the file using office program
	   4) .filename.swx and .filename.swp appear in openning or saving the file using vi editor */

	int before_name_len = strlen(before_name);
	if(!strncmp(before_name, ".~lock.", 7) && before_name[before_name_len - 1] == '#')
	{
		strncpy(after_name, before_name + 7, before_name_len - 8);
		after_name[before_name_len - 8] = '\0';
	}
	else if(before_name[0] == '.' && (!strcmp(before_name + before_name_len - 4, ".swx") || !strcmp(before_name + before_name_len - 4, ".swp")))
	{
		strncpy(after_name, before_name + 1, before_name_len - 5);
		after_name[before_name_len - 5] = '\0';
	}
	else
		strcpy(after_name, before_name);
}

int is_temp_file(char *name)
{
	/* If name is temporary file, return 1. If not, return 0 */
	int name_len = strlen(name);

	if(!strncmp(name, ".~lock.", 7) && name[name_len - 1] == '#')
		return 1;
	if(name[0] == '.' && (!strcmp(name + name_len - 4, ".swx") || !strcmp(name + name_len - 4, ".swp")))
		return 1;
	return 0;
}

void remove_real_file(char *file_path)
{
	/* To use file function, unlock the kernel memory permission */
	mm_segment_t oldfs = get_fs();
	set_fs(get_ds());

	/* To use file function, get root permission */
	struct cred *old_cred;
	old_cred = get_current_cred();
	commit_creds(prepare_kernel_cred(0));

	struct file *del_fp = filp_open(file_path, O_RDONLY, 0);
	if(!IS_ERR(del_fp))
	{
		struct inode *parent_inode = del_fp->f_path.dentry->d_parent->d_inode;

		/* Ignore the organic linkage of multiple inodes,
		   and target only one inode that we want to delete */
		inode_lock(parent_inode);

		/* Delete the file */
		vfs_unlink(parent_inode, del_fp->f_path.dentry, NULL);  

		/* Revert to the previous inode state */  
		inode_unlock(parent_inode);
	}

	/* Revert to the previous permission */
	commit_creds(old_cred);

	/* Lock the kernel memory permission */
	set_fs(oldfs);
}
