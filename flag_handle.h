#ifndef _FLAG_HANDLE_H_
#define _FLAG_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>

typedef struct monitor_flag {
	int flag;
	char *file_path;
	struct monitor_flag *next, *prev;
} monitor_flag;

monitor_flag *make_flag_node(int flag, char *file_path);
void add_flag_node(int flag, char *file_path, monitor_flag **head);
void printk_flag_nodes(monitor_flag *head);
void del_flag_node(int flag, char *file_path, monitor_flag **head);
int is_flag_in(int flag, char *file_path, monitor_flag *head);
void check_flag_path(monitor_flag **head);
void print_flags(int flags);

#endif
