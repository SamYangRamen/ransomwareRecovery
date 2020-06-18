#ifndef _RANSOM_HANDLE_H_
#define _RANSOM_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>

typedef struct monitor_ransom {
	char *orig_name, *infected_name;
	struct monitor_ransom *prev, *next;
} monitor_ransom;

monitor_ransom *make_ransom_node(char *orig_name, char *copy_name);
void add_ransom(char *orig_name, char *copy_name, monitor_ransom **head);
void del_ransom(char *del_name, monitor_file **head);
void flush_ransom_nodes(monitor_file **head);
int is_ransom_in(char *file_path, monitor_file *head);

#endif
