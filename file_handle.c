#include "file_handle.h"

monitor_file *make_file_node(char *orig_path, char *copy_path, long long int time_to_check, int i_node)
{
	monitor_file *new_file = kmalloc(sizeof(monitor_file), GFP_KERNEL);
	new_file->orig_path = kmalloc(sizeof(char) * (strlen(orig_path) + 1), GFP_KERNEL);
	memset(new_file->orig_path, 0, sizeof(new_file->orig_path));
	new_file->copy_path = kmalloc(sizeof(char) * (strlen(copy_path) + 1), GFP_KERNEL);
	memset(new_file->copy_path, 0, sizeof(new_file->copy_path));
	strcpy(new_file->orig_path, orig_path);
	strcpy(new_file->copy_path, copy_path);
	new_file->backup_time = time_to_check;
	new_file->i_node = i_node;
	new_file->is_last = 1;
	new_file->prev = NULL;
	new_file->next = NULL;
	
	return new_file;
}

void add_file(char *orig_path, char *copy_path, monitor_file **head, long long int time_to_check, int i_node)
{
	monitor_file *ptr = *head;
	
	if(ptr == NULL)
	{
		*head = make_file_node(orig_path, copy_path, time_to_check, i_node);
		return;
	}
	
	while(ptr->next != NULL)
	{
		if(!strcmp(ptr->orig_path, orig_path))
			ptr->is_last = 0;
		ptr = ptr->next;
	}
	if(!strcmp(ptr->orig_path, orig_path))
		ptr->is_last = 0;

	ptr->next = make_file_node(orig_path, copy_path, time_to_check, i_node);
	ptr->next->prev = ptr;
}

void del_file(char *del_path, monitor_file **head)
{
	monitor_file *ptr = *head;

	if(ptr == NULL)
		return;

	while(ptr != NULL)
	{
		if(!strcmp(ptr->orig_path, del_path) || !strcmp(ptr->copy_path, del_path))
		{
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
	monitor_file *ptr = *head;

	while(ptr != NULL)
	{
		if(!strcmp(ptr->orig_path, before_path))
		{
			kfree(ptr->orig_path);
			ptr->orig_path = kmalloc(sizeof(char) * (strlen(after_path) + 1), GFP_KERNEL);
			strcpy(ptr->orig_path, after_path);
		}

		ptr = ptr->next;
	}
}

int is_file_in(char *file_path, monitor_file *head)
{
	monitor_file *ptr = head;
	
	while(ptr != NULL)
	{
		if(!strcmp(file_path, ptr->orig_path))
			return 1;
		ptr = ptr->next;
	}

	return 0;
}

void make_real_file_name(char *before_name, char *after_name)
{
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
	int name_len = strlen(name);

	if(!strncmp(name, ".~lock.", 7) && name[name_len - 1] == '#')
		return 1;
	if(name[0] == '.' && (!strcmp(name + name_len - 4, ".swx") || !strcmp(name + name_len - 4, ".swp")))
		return 1;
	return 0;
}

void foo()
{
	printk("ABCDE\n");
}
