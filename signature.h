#ifndef _SIGNATURE_H_
#define _SIGNATURE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/uaccess.h>

#include "define_value.h"
#include "file_handle.h"

typedef struct signature {
	char ext[5];
	unsigned char *data;
	int size;	
	unsigned long offset;
	struct signature *prev, *next;
} signature;

void init_signature_list(signature **signature_list);
signature *make_signature_node(char ext[5], char *sig_shape_str, int sig_shape_str_size, int offset);
void flush_signature_nodes(signature **head);
void add_signature_node(signature **head, char ext[5], char *sig_shape_str, int sig_shape_str_size, int offset);
unsigned char parsing_hex(char ch);
void printk_signature_nodes(signature *head);
unsigned char *parsing_signature(char *sig_shape_str, int sig_shape_str_size);
int check_signature(char *file_path, signature *signature_list, int size);
void print_sig_state(int sig_flag);

#endif
