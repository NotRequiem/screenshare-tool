#ifndef SCHEDULER_HPP
#define SCHEDULER_HPP

#include <windows.h>
#include <iostream>
#include <psapi.h>
#include <tlhelp32.h>
#include <iomanip>
#include <regex>
#include <fstream>
#include <cctype>
#include <algorithm>
#include <set>

using std::min;

extern std::set<std::wstring> printedStrings;

template <typename CharType>
bool isValidChar(CharType ch);

void DetectTaskScheduler(DWORD pid);

void RunTaskSchedulerChecks();

#endif
