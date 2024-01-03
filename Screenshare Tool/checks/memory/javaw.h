#pragma once

#include "..\..\miscellaneous\gui\color.h"

#define MIN_STRING_LENGTH 5
#define OUTPUT_FILE_NAME "strings.txt"
#define BUFFER_SIZE 1050000

#ifdef __cplusplus
extern "C" {
#endif

	#include <stdio.h>
	#include <windows.h>
	#include <psapi.h>
	#include <tlhelp32.h>

	void Javaw();

#ifdef __cplusplus
}
#endif