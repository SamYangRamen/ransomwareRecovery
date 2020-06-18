#include "ransom_handle.h"

monitor_ransom *make_ransom_node(char *orig_name, char *infected_name);
{
	monitor_ransom *new_ransom = kmalloc(sizeof(monitor_ransom), GFP_KERNEL);
	new_ransom->orig_name = kmalloc(sizeof(char) * (strlen(orig_name) + 1), GFP_KERNEL);
	memset(new_ransom->orig_name, 0, sizeof(new_ransom->orig_name));
	new_ransom->infected_name = kmalloc(sizeof(char) * (strlen(infected_name) + 1), GFP_KERNEL);
	memset(new_ransom->infected_name, 0, sizeof(new_ransom->infected_name));
	strcpy(new_ransom->orig_name, orig_name);
	strcpy(new_ransom->infected_name, infected_name);
	new_ransom->prev = NULL;
	new_ransom->next = NULL;
	
	return new_ransom;
}

void add_ransom(char *orig_name, char *infected_name, monitor_ransom **head)
{
	monitor_ransom *ptr = *head;
	
	if(ptr == NULL)
	{
		*head = make_ransom_node(orig_name, infected_name, time_to_check);
		return;
	}
	
	while(ptr->next != NULL)
		ptr = ptr->next;

	ptr->next = make_ransom_node(orig_name, infected_name, time_to_check);
	ptr->next->prev = ptr;
}

void del_ransom(char *del_name, monitor_ransom **head)
{
	monitor_ransom *ptr = *head;

	if(ptr == NULL)
		return;

	while(ptr != NULL)
	{
		if(!strcmp(ptr->orig_name, del_name) || !strcmp(ptr->infected_name, del_name))
		{
			monitor_ransom *temp = ptr;
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

void flush_ransom_nodes(monitor_ransom **head)
{
	monitor_ransom *ptr;

	while(*head != NULL)
	{
		ptr = *head;
		*head = (*head)->next;
		kfree(ptr);
	}
}

int is_ransom_in(char *file_name, monitor_ransom *head)
{
	monitor_ransom *ptr = head;
	
	while(ptr != NULL)
	{
		if(!strcmp(file_name, ptr->orig_name) || !strcmp(file_name, ptr->infected_name))
			return 1;
		ptr = ptr->next;
	}

	return 0;
}
