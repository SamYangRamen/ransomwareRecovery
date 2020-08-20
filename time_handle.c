#include "time_handle.h"

void cur_time(char *time_str)
{
	/* time_str will be "200623123456789012"
			     YYMMDDHHMMSSmsmsms */

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
	/* time_str will be "20/06/23 12:34:56.789012"
			     YY/MM/DD HH/MM/SS.msmsms */

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

long long int num_cur_time(int flag)
{
	char time_str[26];
	memset(time_str, 0, sizeof(time_str));
	cur_time(time_str);

	int ret = 0, Ytemp, Mtemp, Dtemp, htemp, mtemp, stemp;

	Ytemp = (time_str[0] - 48) * 10 + (time_str[1] - 48);
	Mtemp = (time_str[2] - 48) * 10 + (time_str[3] - 48);
	Dtemp = (time_str[4] - 48) * 10 + (time_str[5] - 48);
	htemp = (time_str[6] - 48) * 10 + (time_str[7] - 48);
	mtemp = (time_str[8] - 48) * 10 + (time_str[9] - 48);
	stemp = (time_str[10] - 48) * 10 + (time_str[11] - 48);

	if(flag & RET_YEAR)
		return Ytemp;

	if(flag & RET_MONTH)
		return Ytemp * 12 + Mtemp;

	ret += Ytemp * 365 + Ytemp / 4;

	switch(Mtemp)
	{
		case 12: ret += 30;
		case 11: ret += 31;
		case 10: ret += 30;
		case 9:  ret += 31;
		case 8:  ret += 31;
		case 7:  ret += 30;
		case 6:  ret += 31;
		case 5:  ret += 30;
		case 4:  ret += 31;
		case 3:  ret += Mtemp % 4 == 0? 29 : 28;
		case 2:  ret += 31;
		case 1:  ret += Dtemp;
		break;
	}

	if(flag & RET_DAY)
		return ret;

	ret = ret * 24 + htemp;

	if(flag & RET_HOUR)
		return ret;

	ret = ret * 60 + mtemp;

	if(flag & RET_MINUTE)
		return ret;

	ret = ret * 60 + stemp;

	if(flag & RET_SECOND)
		return ret;

	return -1;
}

//
