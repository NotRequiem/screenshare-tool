#pragma once

#include <windows.h>
#include <shlwapi.h>
#include <tchar.h>
#include <ShlObj.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "Shlwapi.lib")

#include "..\..\miscellaneous\files\filetracker.hpp"
#include "..\..\miscellaneous\gui\color.h"
#include "..\..\miscellaneous\boot\boot.hpp"

void RecentFiles(bool imp);