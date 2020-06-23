#ifndef _TIME_HANDLE_H_
#define _TIME_HANDLE_H_

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/time.h>

#include "define_value.h"

void cur_time(char *time_str);
void cur_time_readable(char *time_str);
long long int num_cur_time(int flag);

#endif

