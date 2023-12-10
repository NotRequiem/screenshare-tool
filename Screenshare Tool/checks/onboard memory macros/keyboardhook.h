#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>
#include <Windows.h>

void UninstallKeyboardHook();
bool InstallKeyboardHook();

#ifdef __cplusplus
}
#endif

