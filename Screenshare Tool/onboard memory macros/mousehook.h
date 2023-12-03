#ifndef MOUSEHOOK_H
#define MOUSEHOOK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stdio.h>
#include <Windows.h>

bool InstallMouseHook();
void UninstallMouseHook();

#ifdef __cplusplus
}
#endif

#endif
