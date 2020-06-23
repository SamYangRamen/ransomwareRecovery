#ifndef _DEFINE_VALUE_H_
#define _DEFINE_VALUE_H_

//#define NAME_MAX 256
#define PATH_MAX 4096
#define PADDING_SIZE 6
#define BUF_SIZE 1024
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#define MAX_SIG_SHAPE_SIZE 20

#define COMMON_BACKUP 0
#define BACKUP_BEFORE_RECOVERY 1

#define OLD_BACKUP_DEL_TIME 10 // 86400 second is 24 hour

#define EXT_O 1
#define SIG_O 2

#define IS_TARGET_FILE 1	// To check if file has the target extension
#define IS_EMPTY_FILE 2		// To check if file size is 0
#define IS_TEMP_FILE 4		// To check if file name has the shape like ".~lock.[name].ext#" or ".[name].swx" or ".[name].swp"
#define IS_INFECTED_EXT 8	// To check if file extension's shape is like ".doc.abc" or ".pptx.crypto" or etc.
#define IS_INFECTED_SIG 16	// To check if file has the signature when the file is displayed in hexadecimal data

#define RET_YEAR 1
#define RET_MONTH 2
#define RET_DAY 4
#define RET_HOUR 8
#define RET_MINUTE 16
#define RET_SECOND 32

#define ORIG_IN 1
#define COPY_IN 2

#endif


