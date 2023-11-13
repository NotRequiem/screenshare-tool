#include "driverchk.hpp"
#include "servicechk.hpp"
#include "bamchk.hpp"

bool IsBAMRunning()
{
    // The driver name of BAM
    const wchar_t* driverName = L"bam";

    // The service name of BAM
    const wchar_t* serviceName = L"BackgroundActivityModerator";

    // Check if the driver or the service is running
    return IsDriverRunning(driverName) || IsServiceRunning(serviceName);
}