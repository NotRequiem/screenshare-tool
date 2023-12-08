#pragma once

#include <windows.h>
#include <iostream>
#include <TlHelp32.h>
#include <comdef.h>
#include <Wbemidl.h>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "wbemuuid.lib")

#include "..\gui\color.h"
#include "..\wmi\wmi.hpp"

void RestartedProcesses();