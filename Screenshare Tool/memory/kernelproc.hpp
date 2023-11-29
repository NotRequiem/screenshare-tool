#ifndef KERNEL_PROC_H
#define KERNEL_PROC_H

#include <iostream>
#include <fstream>
#include <regex>
#include <string>
#include <cwctype>
#include <filesystem>
#include <set>
#include <tchar.h>
#include <io.h>
#include <fcntl.h>

const int MAX_LINE_LENGTH = 400;

void csrss();

#endif