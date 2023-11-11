#ifndef NTFS_DRIVE_UTILS_HPP
#define NTFS_DRIVE_UTILS_HPP

#include <windows.h>
#include <vector>
#include <string>

bool isNTFSDrive(const std::wstring& drive);
void runMFTECmd(const std::wstring& mfteCmdPath, const std::wstring& arguments, const std::wstring& drive);
std::vector<std::wstring> getNTFSDrives();

#endif
