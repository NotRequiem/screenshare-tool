#ifndef MAIN_H
#define MAIN_H

#include <iostream>    
#include <fstream>      
#include <vector>       
#include <unordered_set> 
#include <set>
#include <Windows.h>

// Virtual Machine checks
#include "vmaware.hpp"

// Disk replaces checks
#include "disk\diskchk.hpp"

// ImportCode checks
#include "import code\importcode.hpp"

// Javaw checks
#include "javaw\mods.h"

// Digital signature checks
#include "digital signature\trustverify.hpp"

// WMI related headers
#include "WMI\wmi.hpp"

// Process memory string scanning headers
#include "string scanner\process_scanner.hpp"
#include "string scanner\service_scanner.hpp"

// USN Journal processing headers
#include "usn journal\journal.hpp"

// DLL Injection checks
#include "dll injections\csrss.hpp"

// Macros and onboard memory macros checks
#include "macros\macros.h"
#include "onboard memory macros\mousehook.h"
#include "onboard memory macros\keyboardhook.h"

bool IsRunningAsAdmin() {
    // Check if the sreenshare tool has administrator privileges
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdminGroup;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &AdminGroup)) {
        if (!CheckTokenMembership(NULL, AdminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(AdminGroup);
    }
    return isAdmin;
}

#endif
