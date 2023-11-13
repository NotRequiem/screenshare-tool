#ifndef SCREENSHARE_TOOL_H
#define SCREENSHARE_TOOL_H

#include <iostream>    
#include <fstream>      
#include <vector>       
#include <unordered_set> 
#include <set>
#include <Windows.h>

// Virtual Machine checks
#include "vmaware.hpp"

// Disk replaces checks
#include "Disk\diskchk.hpp"

// Background Activity Moderator checks
#include "BAM\bamchk.hpp"

// ImportCode checks
#include "ImportCode\importcode.hpp"

// Javaw checks
#include "javaw\mods.h"

// Digital signature checks
#include "Digital Signature\TrustVerifyWrapper.hpp"

// Process memory string scanning headers
#include "String Scanner\process_scanner.hpp"
#include "String Scanner\service_scanner.hpp"
#include "String Scanner\wmiutils.hpp"

// USN Journal processing headers
#include "UsnJrnl\journal.hpp"
#include "UsnJrnl\fsutil.h"

// DLL Injection checks
#include "DLL Injections\ntfsutils.hpp"
#include "DLL Injections\dynamic_link_library.hpp"
#include "DLL Injections\csrss.hpp"

// Macros and onboard memory macros checks
#include "Macros\macros.h"
#include "OnboardMemMacros\mousehook.h"
#include "OnboardMemMacros\keyboardhook.h"

#endif