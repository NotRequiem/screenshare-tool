#pragma once

#include <windows.h>
#include <winevt.h>
#include <iostream>

#include "..\gui\color.h"

#pragma comment(lib, "wevtapi.lib")

void SystemTimeChange();