#include "TrustVerifyWrapper.hpp"

DWORD TrustVerifyWrapper::verifyFromFile(const std::wstring& aPePath) {
    WINTRUST_FILE_INFO fileData;
    memset(&fileData, 0, sizeof(WINTRUST_FILE_INFO));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = aPePath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(WINTRUST_DATA));
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;

    return WinVerifyTrust(NULL, &guidAction, &winTrustData);
}

DWORD TrustVerifyWrapper::verifyFromCatalog(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo) {
    LONG lStatus = TRUST_E_NOSIGNATURE;
    GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
    HANDLE hFile;
    DWORD dwHash;
    BYTE bHash[100];
    HCATINFO hCatInfo = NULL;
    HCATADMIN hCatAdmin;

    hFile = CreateFileW(aPePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    if (!CryptCATAdminAcquireContext2(
        &hCatAdmin,
        &DriverActionGuid,
        aCatalogHashAlgo.c_str(),
        NULL,
        0)) {
        CloseHandle(hFile);
        return GetLastError();
    }

    dwHash = sizeof(bHash);
    if (!CryptCATAdminCalcHashFromFileHandle2(
        hCatAdmin,
        hFile,
        &dwHash,
        bHash,
        0)) {
        CloseHandle(hFile);
        return GetLastError();
    }

    auto lHashWstr = ByteHashIntoWstring(bHash, dwHash);

    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);

    if (!hCatInfo) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return GetLastError();
    }

    lStatus = verifyTrustFromCatObject(hCatInfo, aPePath, lHashWstr);

    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    CloseHandle(hFile);

    return lStatus;
}

DWORD TrustVerifyWrapper::verifyTrustFromCatObject(HCATINFO aCatInfo, const std::wstring& aFileName, const std::wstring& aHash) {
    GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    WINTRUST_DATA wd = { 0 };
    WINTRUST_CATALOG_INFO wci = { 0 };

    CATALOG_INFO ci = { 0 };
    CryptCATCatalogInfoFromContext(aCatInfo, &ci, 0);

    memset(&wci, 0, sizeof(wci));
    wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
    wci.pcwszMemberFilePath = aFileName.c_str();
    wci.pcwszMemberTag = aHash.c_str();

    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wd.pCatalog = &wci;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.dwUIContext = WTD_UICONTEXT_EXECUTE;
    wd.fdwRevocationChecks = WTD_STATEACTION_VERIFY;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = 0;
    wd.hWVTStateData = NULL;
    wd.pwszURLReference = NULL;
    wd.pPolicyCallbackData = NULL;
    wd.pSIPClientData = NULL;
    wd.dwUIContext = 0;

    return WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
}

std::wstring TrustVerifyWrapper::ByteHashIntoWstring(BYTE* aHash, size_t aHashLen) {
    if (!aHash || !aHashLen) {
        return L"";
    }

    auto lHashString = new WCHAR[aHashLen * 2 + 1];

    for (DWORD dw = 0; dw < aHashLen; ++dw) {
        wsprintfW(&lHashString[dw * 2], L"%02X", aHash[dw]);
    }

    std::wstring lHashWstr(lHashString);

    delete[] lHashString;

    return lHashWstr;
}
