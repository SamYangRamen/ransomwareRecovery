#include "flag_handle.h"

monitor_flag *make_flag_node(int flag, int inode)
{
	monitor_flag *new_flag = kmalloc(sizeof(monitor_flag), GFP_KERNEL);
	new_flag->flag = flag;
	new_flag->inode = inode;
	new_flag->prev = NULL;
	new_flag->next = NULL;
	
	return new_flag;
}

void add_flag(int flag, int inode, monitor_flag **head)
{
	monitor_flag *ptr = *head;
	
	if(ptr == NULL)
	{
		*head = make_flag_node(flag, inode);
		return;
	}
	
	while(ptr->next != NULL)
		ptr = ptr->next;

	ptr->next = make_flag_node(flag, inode);
	ptr->next->prev = ptr;
}

void del_flag(int flag, int inode, monitor_flag **head)
{
	monitor_flag *ptr = *head;

	if(ptr == NULL)
		return;

	while(ptr != NULL)
	{
		if((ptr->flag & flag) && ptr->inode == inode)
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

int is_flag_in(int flag, int inode, monitor_flag *head)
{
	monitor_flag *ptr = head;

	while(ptr != NULL)
	{
		if((ptr->flag & flag) && ptr->inode == inode)
			return 1;
		
		ptr = ptr->next;
	}

	return 0;
}
