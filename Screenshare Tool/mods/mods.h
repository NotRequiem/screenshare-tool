#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <tchar.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>

#include "..\gui\color.h"

void SuspiciousMods();

#ifdef __cplusplus
}
#endif