#pragma once

#include <stdbool.h>

extern wchar_t username[MAX_PATH];

void ReplaceUsername(wchar_t* filePath, int maxPathLength, const wchar_t* username);
bool IsFileRecentlyModified(const wchar_t* filePath);
void CheckFilesInFolder(const wchar_t* folderPath, const wchar_t* extension);
void CheckRecentFileModifications();
