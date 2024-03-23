#pragma once

#include <windows.h>
#include <winevt.h>
#include <iostream>
#include <vector>
#include <memory>

#include "..\..\miscellaneous\gui\color.h"

#pragma comment(lib, "wevtapi.lib")

void SystemTimeChange(bool imp);