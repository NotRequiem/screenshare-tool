#ifndef QUERY_H
#define QUERY_H

#include <tchar.h>
#include <stdbool.h>
#include <windows.h>
#include <cstdio>

void RunCommand(TCHAR driveLetter);
bool IsTextFileEmpty(const TCHAR* filename);

#endif