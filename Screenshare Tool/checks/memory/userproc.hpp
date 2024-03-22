#pragma once

#include <iostream>
#include <Windows.h>
#include <sstream>
#include <set>
#include <unordered_set>
#include <map>
#include <filesystem>
#include <psapi.h>

#include "..\..\miscellaneous\wmi\wmi.hpp"
#include "..\..\miscellaneous\gui\color.h"
#include "..\..\miscellaneous\digital signature\trustverify.hpp"
#include "..\..\miscellaneous\device\device.hpp"

namespace fs = std::filesystem;

void ExecutedFiles(bool imp);
