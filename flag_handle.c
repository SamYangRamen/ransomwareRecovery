#include "flag_handle.h"

monitor_flag *make_flag_node(int flag, char *file_path)
{
	monitor_flag *new_flag = kmalloc(sizeof(monitor_flag), GFP_KERNEL);
	new_flag->flag = flag;
	new_flag->file_path = kmalloc(sizeof(char) * (strlen(file_path) + 1), GFP_KERNEL);
	strcpy(new_flag->file_path, file_path);
	new_flag->prev = NULL;
	new_flag->next = NULL;
	
	return new_flag;
}

void add_flag_node(int flag, char *file_path, monitor_flag **head)
{
	monitor_flag *ptr = *head;
	
	if(ptr == NULL)
	{
		*head = make_flag_node(flag, file_path);
		return;
	}
	
	while(ptr->next != NULL)
		ptr = ptr->next;

	ptr->next = make_flag_node(flag, file_path);
	ptr->next->prev = ptr;
}

void printk_flag_nodes(monitor_flag *head)
{
	printk("----------------------------monitored flag list----------------------------\n");
	if(head == NULL)
		printk("NULL\n");

	monitor_flag *ptr = head;
	
	while(ptr != NULL)
	{
		printk("%s", ptr->file_path);
		print_flags(ptr->flag);
		ptr = ptr->next;
	}
	printk("---------------------------------------------------------------------------\n");
}

void del_flag_node(int flag, char *file_path, monitor_flag **head)
{
	monitor_flag *ptr = *head;

	if(ptr == NULL)
		return;

	while(ptr != NULL)
	{
		if((ptr->flag & flag) && !strcmp(ptr->file_path, file_path))
		{
			monitor_flag *temp = ptr;
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

int is_flag_in(int flag, char *file_path, monitor_flag *head)
{
	monitor_flag *ptr = head;

	while(ptr != NULL)
	{
		if((ptr->flag & flag) && !strcmp(ptr->file_path, file_path))
			return 1;
		
		ptr = ptr->next;
	}

	return 0;
}

void check_flag_path(monitor_flag **head)
{
	monitor_flag *ptr = *head;

	if(ptr == NULL)
		return;

	while(ptr != NULL)
	{
		struct file *fp = filp_open(ptr->file_path, O_RDONLY, 0);
		if(IS_ERR(fp))
			del_flag_node(ptr->flag, ptr->file_path, head);
		else
			filp_close(fp, NULL);

		ptr = ptr->next;
	}
}

void print_flags(int flags)
{
	if(flags & O_RDONLY)
		printk("[O_RDONLY]");
	if(flags & O_WRONLY)
		printk("[O_WRONLY]");
	if(flags & O_RDWR)
		printk("[O_RDWR]");
	if(flags & O_CREAT)
		printk("[O_CREAT]");
	if(flags & O_EXCL)
		printk("[O_EXCL]");
	if(flags & O_TRUNC)
		printk("[O_TRUNC]");
	if(flags & O_APPEND)
		printk("[O_APPEND]");
	if(flags & O_NOCTTY)
		printk("[O_NOCTTY]");
	if(flags & O_NONBLOCK)
		printk("[O_NONBLOCK]");
	if(flags & O_NDELAY)
		printk("[O_NDELAY]");
	if(flags & O_SYNC)
		printk("[O_SYNC]");
	if(flags & O_DSYNC)
		printk("[O_DSYNC]");
	//if(flags & O_ASYNC)
		//printk("[O_ASYNC]");
	if(flags & O_CLOEXEC)
		printk("[O_CLOEXEC]");
	if(flags & O_DIRECT)
		printk("[O_DIRECT]");
	if(flags & O_DIRECTORY)
		printk("[O_DIRECTORY]");
	if(flags & O_PATH)
		printk("[O_PATH]");
	if(flags & O_TMPFILE)
		printk("[O_TMPFILE]");
	if(flags & O_NOFOLLOW)
		printk("[O_NOFOLLOW]");
	if(flags & O_LARGEFILE)
		printk("[O_LARGEFILE]");
	if(flags & O_NOATIME)
		printk("[O_NOATIME]");
	if(flags & O_TMPFILE)
		printk("[O_TMPFILE]");
	printk("\n");
}
