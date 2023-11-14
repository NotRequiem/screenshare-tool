#ifndef MODS_H
#define MODS_H

#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

void CheckLastModifiedTime(const TCHAR* directoryPath, const SYSTEMTIME* processStartTime);
void GetProcessStartTime(const TCHAR* processName, SYSTEMTIME* processStartTime);

#endif
