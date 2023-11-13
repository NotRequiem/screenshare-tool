#ifndef DISK_CHK_H
#define DISK_CHK_H

#include <iostream>
#include <Windows.h>
#include <vector>
#include <string>
#include <ctime>
#include <iomanip>
#include <comdef.h>
#include <Wbemidl.h>
#include <Shlwapi.h>

#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "Shlwapi.lib")

bool FileExists(const std::wstring& filePath);

time_t GetLastBootTime();

time_t GetLastModifiedTime(const std::wstring& filePath);

void CheckDiskInstallation();

#endif
