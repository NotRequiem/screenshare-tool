#pragma once

#include <Windows.h>
#include <sstream>
#include <unordered_set>
#include <map>

std::map<std::wstring, std::wstring> GetDosPathDevicePathMap();

std::wstring ConvertDevicePathToFilePath(const std::wstring& devicePath);