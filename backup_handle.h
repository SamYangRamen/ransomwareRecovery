#ifndef _BACKUP_HANDLE_H_
#define _BACKUP_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/fs.h>
#include <linux/cred.h>

#include "file_handle.h"
#include "time_handle.h"
#include "signature.h"
#include "define_value.h"

void backup(char *orig_path, monitor_file **file_list, char backup_type_flag);
void recover(char *infected_path, monitor_file **file_list);
void recover_process(char *infected_path, char *copy_path, monitor_file **file_list);
//
#endif
