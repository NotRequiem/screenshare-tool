#ifndef DYNAMIC_LINK_LIBRARY_HPP
#define DYNAMIC_LINK_LIBRARY_HPP

#include <windows.h>
#include <tchar.h>
#include <iostream>

bool IsFileOnFatDrive(const std::wstring& filePath);
bool IsFileSignatureValid(const std::wstring& filePath);
void ScanDllFiles(const std::wstring& drive);
void DetectUnsignedDLLs();

#endif
