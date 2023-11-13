#ifndef WMISERV_H
#define WMISERV_H

#include <comdef.h>
#include <Wbemidl.h>
#include <sstream>

#pragma comment(lib, "wbemuuid.lib")

HRESULT InitializeWMI(IWbemLocator*& pLoc, IWbemServices*& pSvc);
void UninitializeWMI(IWbemLocator* pLoc, IWbemServices* pSvc);
HRESULT ExecuteWMIQuery(IWbemServices* pSvc, const wchar_t* serviceName, VARIANT& processId);

#endif
