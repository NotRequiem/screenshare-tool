#ifndef WMIUTILS_H
#define WMIUTILS_H

#include <comdef.h>
#include <Wbemidl.h>

HRESULT InitializeWMI(IWbemLocator*& pLoc, IWbemServices*& pSvc);
void UninitializeWMI(IWbemLocator* pLoc, IWbemServices* pSvc);
HRESULT ExecuteWMIQuery(IWbemServices* pSvc, const wchar_t* serviceName, VARIANT& processId);

#endif
