#pragma once

#include <Windows.h>
#include <iostream>
#include <memory>
#include <map>
#include <string>
#include <Wbemidl.h>
#include <comdef.h>
#include <iomanip>

#include "..\..\miscellaneous\digital signature\trustverify.hpp"
#include "..\..\miscellaneous\boot\boot.hpp"
#include "..\..\miscellaneous\string\string.hpp"
#include "..\..\miscellaneous\device\device.hpp"
#include "..\..\miscellaneous\gui\color.h"

#pragma comment(lib, "wbemuuid.lib")

void bam(bool imp);
