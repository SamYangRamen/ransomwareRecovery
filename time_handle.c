#include "time_handle.h"

void cur_time(char *time_str)
{
	struct timespec tv;
	getnstimeofday(&tv);

	struct tm cur_tm;
	time_t time_tmp;
	int p = 0;

	time_tmp = tv.tv_sec + 32400;
	time_to_tm(time_tmp, 0, &cur_tm);
	
	p += snprintf(time_str, sizeof(cur_tm.tm_year)+1, "%.2lu", cur_tm.tm_year-100);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_mon)+1, "%.2d", cur_tm.tm_mon+1);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_mday)+1, "%.2d", cur_tm.tm_mday);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_hour)+1, "%.2d", cur_tm.tm_hour);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_min)+1, "%.2d", cur_tm.tm_min);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_sec)+1, "%.2d", cur_tm.tm_sec);
	p += snprintf(time_str+p, sizeof(tv.tv_nsec), "%.6ld", tv.tv_nsec / 1000);
}

void cur_time_readable(char *time_str)
{
	struct timespec tv;
	getnstimeofday(&tv);

	struct tm cur_tm;
	time_t time_tmp;
	int p = 0;

	time_tmp = tv.tv_sec + 32400;
	time_to_tm(time_tmp, 0, &cur_tm);
	
	p += snprintf(time_str, sizeof(cur_tm.tm_year)+1, "%.2lu/", cur_tm.tm_year-100);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_mon)+1, "%.2d/", cur_tm.tm_mon+1);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_mday)+1, "%.2d ", cur_tm.tm_mday);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_hour)+1, "%.2d:", cur_tm.tm_hour);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_min)+1, "%.2d:", cur_tm.tm_min);
	p += snprintf(time_str+p, sizeof(cur_tm.tm_sec)+1, "%.2d.", cur_tm.tm_sec);
	p += snprintf(time_str+p, sizeof(tv.tv_nsec), "%.6ld", tv.tv_nsec / 1000);
}

long long int num_cur_time_hour(char *time_str)
{
	int i, ret = 0, pow = 1;
/*
	char time_str[19];
	
	cur_time(time_str);

	for(i = 1; i <= 10; i++)
		time_str[18 - i] = '\0';
*/
	for(i = 11; i <= 18; i++)
	{
		ret += (time_str[18 - i] - 48) * pow;
		pow *= 10;
	}

	return ret;
}

long long int num_cur_time_second(char *time_str)
{
	int i, ret = 0, pow = 1;

	for(i = 7; i <= 18; i++)
	{
		ret += (time_str[18 - i] - 48) * pow;
		pow *= 10;		
	}

	return ret;
}
