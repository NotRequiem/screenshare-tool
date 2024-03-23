#pragma once

#define MIN_STRING_LENGTH 5
#define BUFFER_SIZE 1050000 // 1.00095 megabytes (MB)
#define TIMEOUT_DURATION 10000 // 10 seconds in milliseconds

#ifdef __cplusplus
extern "C" {
#endif

	#include <stdio.h>
	#include <windows.h>
	#include <psapi.h>
	#include <tlhelp32.h>

	#include "..\..\miscellaneous\gui\color.h"

	void Javaw();

#ifdef __cplusplus
}
#endif
