#ifndef _FLAG_HANDLE_H_
#define _FLAG_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>

typedef struct monitor_flag {
	int flag, i_node;
	struct monitor_flag *next, *prev;
} monitor_flag;

monitor_flag *make_flag_node(int flag, int i_node);
void add_flag(int flag, int i_node, monitor_flag **head);
void del_flag(int flag, int i_node, monitor_flag **head);
int is_flag_in(int flag, int i_node, monitor_flag *head);

#endif
