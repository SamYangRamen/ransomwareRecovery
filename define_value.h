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

#define IS_TARGET_FILE 1
#define IS_EMPTY_FILE 2
#define IS_TEMP_FILE 4
#define IS_INFECTED_EXT 8
#define IS_INFECTED_SIG 16

#define ORIG_IN 1
#define COPY_IN 2

#endif


