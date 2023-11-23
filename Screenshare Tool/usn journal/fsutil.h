#ifndef FSUTIL_H
#define FSUTIL_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <tchar.h>
#include <Windows.h>

#define MAX_LINE_SIZE 1024

typedef struct {
    char time[MAX_LINE_SIZE];
    char fileName[MAX_LINE_SIZE];
} FileData;

void USNJournal();

#ifdef __cplusplus
}
#endif

#endif