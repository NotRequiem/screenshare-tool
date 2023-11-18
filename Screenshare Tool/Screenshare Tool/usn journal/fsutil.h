#ifndef FSUTIL_H
#define FSUTIL_H

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

void processLogFileComparison(void);

bool IsTextFileEmpty(const TCHAR* filename);

void RunCommand(TCHAR driveLetter);

void fsutil();

void buildHashTable(FILE* file, FileData*** hashTable, int* tableSize, SYSTEMTIME lastBootTime);

void compareHashTables(FileData** hashTable1, int tableSize1, FileData** hashTable2, int tableSize2);

void LastBootTime();

void processLogFileComparison();

#endif