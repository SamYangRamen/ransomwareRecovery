#ifndef _FILE_HANDLE_H_
#define _FILE_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/fcntl.h>
#include <linux/uaccess.h>
#include <linux/cred.h>

#include "define_value.h"

typedef struct monitor_file {
	char *orig_path;
	char *copy_path;
	long long int backup_time;
	char is_last;
	struct monitor_file *prev, *next;
} monitor_file;

monitor_file *make_file_node(char *orig_path, char *copy_path, long long int time_to_check);
void add_file_node(char *orig_path, char *copy_path, monitor_file **head, long long int time_to_check);
void del_file_node(char *del_path, monitor_file **head);
void printk_file_nodes(monitor_file *head);
void flush_file_nodes(monitor_file **head);
void mod_file_path(char *before_path, char *after_path, monitor_file **head);
int is_file_in(char *file_path, monitor_file *head);
void make_real_file_name(char *before_name, char *after_name);
int is_temp_file(char *name);
void remove_real_file(char *file_path);

#endif
