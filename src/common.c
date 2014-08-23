
#include <stdio.h>
#include <string.h>

#include "common.h"

static char *
chomp(char *str)
{
    char *ptr = str;

    while (*ptr != 0) {
        ptr++;
    }
    while (ptr != str) {
        ptr--;
        if (*ptr != '\r' && *ptr != '\n') {
            break;
        }
        *ptr = 0;
    }
    return str;
}

static int
split(char *parts[MAX_SPLIT_PARTS], char *str, size_t expected_count)
{
    char   *part;
    size_t  i;

    i = (size_t) 0U;
    chomp(str);
    while ((part = strsep(&str, " \t")) != NULL) {
        parts[i] = part;
        i++;
    }
    if (expected_count != i) {
        fprintf(stderr, "Expected %zu parts, found %zu\n",
                expected_count, i);
        return -1;
    }
    return 0;
}

static int
parse_line(char *parts[MAX_SPLIT_PARTS], FILE *fp, size_t parts_count)
{
    char line[MAX_LINE_LENGTH];

    if (fgets(line, sizeof line, fp) == NULL) {
        return 1;
    }
    if (split(parts, line, parts_count) != 0) {
        return -1;
    }
    return 0;
}

int
parse_stdin(int (*cb)(char *parts[MAX_LINE_LENGTH]), size_t parts_count)
{
    char          *parts[MAX_LINE_LENGTH];
    unsigned long  counter = 0UL;

    while (parse_line(parts, stdin, parts_count) == 0) {
        counter++;
        if (cb(parts) != 0) {
            fprintf(stderr, "Test vector #%lu didn't verify\n", counter);
        }
    }
    return 0;
}
