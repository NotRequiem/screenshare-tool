#pragma once

#include <iostream>
#include <Windows.h>
#include <sstream>
#include <set>
#include <unordered_set>
#include <map>
#include <filesystem>
#include <psapi.h>
#include <regex>

#include "..\..\miscellaneous\files\filetracker.hpp"
#include "..\..\miscellaneous\wmi\wmi.hpp"
#include "..\..\miscellaneous\gui\color.h"
#include "..\..\miscellaneous\digital signature\trustverify.hpp"
#include "..\..\miscellaneous\device\device.hpp"

namespace fs = std::filesystem;

static std::vector<std::string> extensions = { ".exe", ".dll", ".jar", ".bat", ".vbs", ".py", ".ps1", ".go" };

void ExecutedFiles(bool imp);
