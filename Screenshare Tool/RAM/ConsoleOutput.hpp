#pragma once

#include <string>
#include <iostream>
#include <fstream>
#include <unordered_set>
#include <memory>

#ifdef _WIN32
#define SET_TEXT_COLOR_BLUE() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 9)
#define SET_TEXT_COLOR_GREEN() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 10)
#define SET_TEXT_COLOR_RED() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 12)
#define SET_TEXT_COLOR_YELLOW() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 14)
#define RESET_TEXT_COLOR() SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 7)
#endif

void InitializeLowercaseConversionTable();
char ConvertToLowercase(char character);
