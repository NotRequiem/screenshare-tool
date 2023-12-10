#include "trustverify.hpp"

// Verify the digital signature of a file.
bool TrustVerifyWrapper::VerifyFileSignature(const std::wstring& filePath) {
    // Call CheckFileSignature with the file path and a default hash algorithm ("SHA256").
    // Return true if the verification is successful (returns ERROR_SUCCESS), otherwise false.
    return CheckFileSignature(filePath, L"SHA256") == ERROR_SUCCESS;
}

// Check the digital signature of a file using a catalog file and hash algorithm.
DWORD TrustVerifyWrapper::CheckFileSignature(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo) {
    // If verification from file succeeds, return ERROR_SUCCESS.
    if (verifyFromFile(aPePath) == ERROR_SUCCESS) {
        return ERROR_SUCCESS;
    }

    // If verification from file fails, proceed with verification from catalog.
    // Return the result of the catalog verification process.
    return verifyFromCatalog(aPePath, aCatalogHashAlgo);
}

// Verify a PE file from a file path.
DWORD TrustVerifyWrapper::verifyFromFile(const std::wstring& aPePath) {
// Initialize data structures.
    WINTRUST_FILE_INFO fileData;
    memset(&fileData, 0, sizeof(WINTRUST_FILE_INFO));
    fileData.cbStruct = sizeof(WINTRUST_FILE_INFO);
    fileData.pcwszFilePath = aPePath.c_str();
    fileData.hFile = NULL;
    fileData.pgKnownSubject = NULL;

    // Specify the verification action.
    GUID guidAction = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    
    // Initialize the main WINTRUST_DATA structure.
    WINTRUST_DATA winTrustData;
    memset(&winTrustData, 0, sizeof(WINTRUST_DATA));
    winTrustData.cbStruct = sizeof(WINTRUST_DATA);
    winTrustData.dwUIChoice = WTD_UI_NONE;
    winTrustData.fdwRevocationChecks = WTD_REVOKE_NONE;
    winTrustData.dwUnionChoice = WTD_CHOICE_FILE;
    winTrustData.pFile = &fileData;

    // Perform the trust verification and return the result.
    return WinVerifyTrust(NULL, &guidAction, &winTrustData);
}

// Verify a PE file from a catalog file with a specified hash algorithm.
DWORD TrustVerifyWrapper::verifyFromCatalog(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo) {
    // Initialize variables and data structures.
    LONG lStatus = TRUST_E_NOSIGNATURE;
    GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    GUID DriverActionGuid = DRIVER_ACTION_VERIFY;
    HANDLE hFile;
    DWORD dwHash;
    BYTE bHash[100];
    HCATINFO hCatInfo = NULL;
    HCATADMIN hCatAdmin;

    // Open the PE file for reading.
    hFile = CreateFileW(aPePath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    // Acquire a catalog administrator context with the specified hash algorithm.
    if (!CryptCATAdminAcquireContext2(&hCatAdmin, &DriverActionGuid, aCatalogHashAlgo.c_str(), NULL, 0)) {
        CloseHandle(hFile);
        return GetLastError();
    }

    // Calculate the hash of the PE file.
    dwHash = sizeof(bHash);
    if (!CryptCATAdminCalcHashFromFileHandle2(hCatAdmin, hFile, &dwHash, bHash, 0)) {
        CloseHandle(hFile);
        return GetLastError();
    }

    // Convert the binary hash to a string.
    auto lHashWstr = ByteHashIntoWstring(bHash, dwHash);

    // Enumerate the catalog to find the corresponding entry.
    hCatInfo = CryptCATAdminEnumCatalogFromHash(hCatAdmin, bHash, dwHash, 0, NULL);

    // Verify trust using the catalog information and the PE file's hash.
    if (!hCatInfo) {
        CryptCATAdminReleaseContext(hCatAdmin, 0);
        CloseHandle(hFile);
        return GetLastError();
    }

    lStatus = verifyTrustFromCatObject(hCatInfo, aPePath, lHashWstr);

    // Release resources and return the verification status.
    CryptCATAdminReleaseCatalogContext(hCatAdmin, hCatInfo, 0);
    CryptCATAdminReleaseContext(hCatAdmin, 0);
    CloseHandle(hFile);

    return lStatus;
}

// Verify trust from a catalog object (entry) using its information.
DWORD TrustVerifyWrapper::verifyTrustFromCatObject(HCATINFO aCatInfo, const std::wstring& aFileName, const std::wstring& aHash) {
    // Initialize data structures for catalog verification.
    GUID WintrustVerifyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA wd = { 0 };
    WINTRUST_CATALOG_INFO wci = { 0 };
    
    // Get catalog information from the context.
    CATALOG_INFO ci = { 0 };
    CryptCATCatalogInfoFromContext(aCatInfo, &ci, 0);

    // Initialize the WINTRUST_CATALOG_INFO structure.
    memset(&wci, 0, sizeof(wci));
    wci.cbStruct = sizeof(WINTRUST_CATALOG_INFO);
    wci.pcwszCatalogFilePath = ci.wszCatalogFile;
    wci.pcwszMemberFilePath = aFileName.c_str();
    wci.pcwszMemberTag = aHash.c_str();

    // Initialize the WINTRUST_DATA structure for catalog verification.
    memset(&wd, 0, sizeof(wd));
    wd.cbStruct = sizeof(WINTRUST_DATA);
    wd.dwUnionChoice = WTD_CHOICE_CATALOG;
    wd.pCatalog = &wci;
    wd.dwUIChoice = WTD_UI_NONE;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;
    wd.dwProvFlags = 0;
    wd.hWVTStateData = NULL;
    wd.pwszURLReference = NULL;
    wd.pPolicyCallbackData = NULL;
    wd.pSIPClientData = NULL;
    wd.dwUIContext = 0;

    // Perform trust verification from the catalog and return the result.
    return WinVerifyTrust(NULL, &WintrustVerifyGuid, &wd);
}

// Convert a byte array hash into a wide string representation.
    std::wstring TrustVerifyWrapper::ByteHashIntoWstring(BYTE* aHash, size_t aHashLen) {
    if (!aHash || !aHashLen) {
        return L"";
    }

    // Allocate memory for the wide string representation.
    auto lHashString = new WCHAR[aHashLen * 2 + 1];

    // Convert the binary hash to a hexadecimal string.
    for (DWORD dw = 0; dw < aHashLen; ++dw) {
        wsprintfW(&lHashString[dw * 2], L"%02X", aHash[dw]);
    }

    // Create a wide string and release the memory.
    std::wstring lHashWstr(lHashString);
    delete[] lHashString;

    return lHashWstr;
}
