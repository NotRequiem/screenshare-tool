#ifndef EVENTLOG_H
#define EVENTLOG_H

#include <windows.h>
#include <winevt.h>
#include <iostream>

#pragma comment(lib, "wevtapi.lib")

void SystemTimeChange();

#endif