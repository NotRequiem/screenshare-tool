#ifndef FSUTIL_H
#define FSUTIL_H

#include <Windows.h>
#include <stdio.h>
#include <tchar.h>
#include <filesystem>

constexpr auto MAX_LINE_SIZE = 1024;

typedef struct {
    char time[MAX_LINE_SIZE];
    char fileName[MAX_LINE_SIZE];
} FileData;

void USNJournal();

#endif