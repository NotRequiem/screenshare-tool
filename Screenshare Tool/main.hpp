#pragma once

#include <iostream>    
#include <fstream>      
#include <vector>       
#include <unordered_set> 
#include <set>
#include <Windows.h>

// VM detection headers
#include "vmaware.hpp"

// Process memory string scanning headers
#include "String Scanner\process_scanner.hpp"
#include "String Scanner\service_scanner.hpp"
#include "String Scanner\WMIUtils.hpp"

// RAM memory scanning headers
#include "RAM\TrustVerifyWrapper.hpp"
#include "RAM\StringProcessing.hpp"
#include "RAM\FilePathMapping.hpp"
#include "RAM\FileVerification.hpp"
#include "RAM\ConsoleOutput.hpp"

// USN Journal checks headers
#include "UsnJrnl\DriveOperations.hpp"
#include "UsnJrnl\fsutil.h"

// BAM (Background Activity Moderator)  headers
#include "BAM\BAMChecker.hpp"

// DLL Injection checks headers
#include "DLL Injections\NTFSDriveUtils.hpp"

// Macros and onboard memory macros related headers
#include "Macros\macros.h"
#include "OnboardMemMacros\MouseHook.h"
#include "OnboardMemMacros\KeyboardHook.h"
