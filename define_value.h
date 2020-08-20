#ifndef _DEFINE_VALUE_H_
#define _DEFINE_VALUE_H_

//#define NAME_MAX 256
#define PATH_MAX 4096
#define BUF_SIZE 1024
#define MAX_SIG_SHAPE_SIZE 20

// 86400 second is 24 hour
#define DEL_TERM 10	 	// Indicates how much time has passed since the backup
#define PROTECT_TERM 20	 	// Indicates how much time has passed since the ransomware occur
				// after this time we can delete the target file
#define COMMON_BACKUP 0
#define BACKUP_BEFORE_RECOVERY 1

#define IS_HAVING_TARGET_EXT 1		// Does file has the target extension?
#define IS_EMPTY_FILE 2		// Is file size 0?
#define IS_TEMP_FILE 4		// Does file name has the shape like ".~lock.[name].ext#" or ".[name].swx" or ".[name].swp"?
#define IS_INFECTED_EXT 8	// Is file extension's shape like ".doc.abc" or ".pptx.crypto" or etc.?
#define IS_INFECTED_SIG 16	// Does file has the signature when the file is displayed in hexadecimal data?

#define RET_YEAR 1
#define RET_MONTH 2
#define RET_DAY 4
#define RET_HOUR 8
#define RET_MINUTE 16
#define RET_SECOND 32

#endif

//
