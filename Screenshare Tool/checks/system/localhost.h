#ifndef LOCAL_HOST_H
#define LOCAL_HOST_H

#ifdef __cplusplus
extern "C" {
#endif

#include <windows.h>
#include <winnetwk.h>
#include <stdio.h>
#include <wchar.h>

#include "..\..\miscellaneous\gui\color.h"

#pragma comment(lib, "Mpr.lib")

void LocalHost();

#ifdef __cplusplus
}
#endif

#endif
