#include "DriverChecker.hpp"
#include "ServiceChecker.hpp"

bool IsBAMRunning()
{
    // The driver name of BAM
    const char* driverName = "bam";

    // The service name of BAM
    const char* serviceName = "BackgroundActivityModerator";

    // Check if the driver or the service is running
    return IsDriverRunning(driverName) || IsServiceRunning(serviceName);
}