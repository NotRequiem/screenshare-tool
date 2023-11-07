#pragma once

#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <string>

#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

class TrustVerifyWrapper {
public:
    bool VerifyFileSignature(const std::wstring& filePath);
    DWORD CheckFileSignature(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo);

private:
    DWORD verifyFromFile(const std::wstring& aPePath);
    DWORD verifyFromCatalog(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo);
    DWORD verifyTrustFromCatObject(HCATINFO aCatInfo, const std::wstring& aFileName, const std::wstring& aHash);
    std::wstring ByteHashIntoWstring(BYTE* aHash, size_t aHashLen);
};

