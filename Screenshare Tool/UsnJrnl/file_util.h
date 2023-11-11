#ifndef FILE_UTIL_H
#define FILE_UTIL_H

#include <tchar.h>
#include <stdio.h>

void CompareFilesAndWriteResult(const TCHAR* oldFilePath, const TCHAR* newFilePath, const TCHAR* resultFilePath);

#endif