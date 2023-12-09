#pragma once

#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wbemuuid.lib")

#include "..\..\miscellaneous\gui\color.h"
#include "..\..\miscellaneous\wmi\wmi.hpp"

void RestartedProcesses();