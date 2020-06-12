#ifndef _FILE_HANDLE_H_
#define _FILE_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>

typedef struct monitor_file {
	char *orig_path;
	char *copy_path;
	int inode;
	long long int backup_time;
	char is_last;
	struct monitor_file *prev, *next;
} monitor_file;

monitor_file *make_file_node(char *orig_path, char *copy_path, long long int time_to_check, int inode);
void add_file(char *orig_path, char *copy_path, monitor_file **head, long long int time_to_check, int i_node);
void del_file(char *del_path, monitor_file **head);
void printk_file_nodes(monitor_file *head);
void flush_file_nodes(monitor_file **head);
void mod_file_path(char *before_path, char *after_path, monitor_file **head);
int is_file_in(char *file_path, monitor_file *head);
void make_real_file_name(char *before_name, char *after_name);
int is_temp_file(char *name);

#endif
