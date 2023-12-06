#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>
#include <Windows.h>

#include "..\gui\color.h"

bool InstallMouseHook();
void UninstallMouseHook();

#ifdef __cplusplus
}
#endif