
#ifndef __COMMON_H__
#define __COMMON_H__

#define MAX_SPLIT_PARTS 64
#define MAX_LINE_LENGTH 65536

int parse_stdin(int (*cb)(char *parts[MAX_LINE_LENGTH]), size_t parts_count);

#endif
