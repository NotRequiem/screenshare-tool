#pragma once

#include <windows.h>
#include <comdef.h>
#include <Wbemidl.h>

#pragma comment(lib, "wbemuuid.lib")

bool LogonTime(SYSTEMTIME& lastLogonTime);
