#pragma once

#include <iostream>
#include <Windows.h>
#include <sstream>
#include <set>
#include <unordered_set>
#include <map>

#include "..\..\miscellaneous\wmi\wmi.hpp"
#include "..\..\miscellaneous\gui\color.h"
#include "..\..\miscellaneous\digital signature\trustverify.hpp"
#include "..\..\miscellaneous\device\device.hpp"

std::unordered_set<std::wstring> printedLines;

void ExecutedFiles(bool imp);
