#ifndef TRUST_VERIFY_H
#define TRUST_VERIFY_H

#include <windows.h>
#include <Softpub.h>
#include <wincrypt.h>
#include <mscat.h>
#include <string>

// Link the required libraries.
#pragma comment(lib, "Wintrust.lib")
#pragma comment(lib, "Crypt32.lib")

// TrustVerifyWrapper class for file signature verification.
class TrustVerifyWrapper {
public:

    /** 
        // Verify the digital signature of a file.
     * Parameters:
        filePath: The file path to be verified.
     * Returns:
       true if the file has a valid digital signature, false otherwise.
    */

    bool VerifyFileSignature(const std::wstring& filePath);

    /**
        // Check the digital signature of a file using a catalog file and hash algorithm.
    *  Parameters:
        aPePath: The file path to be verified.
        aCatalogHashAlgo: The hash algorithm used by the catalog.
    *  Returns:
        A Windows error code indicating the result of the verification process.
    */

    DWORD CheckFileSignature(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo);

private:

    /**
        // Verify the digital signature of a file.
    *  Parameters:
        aPePath: The file path to be verified.
    *  Returns:
        A Windows error code indicating the result of the verification process.
    */

    DWORD verifyFromFile(const std::wstring& aPePath);

    /**
        // Verify the digital signature of a file using a catalog file and hash algorithm.
    *  Parameters:
        aPePath: The file path to be verified.
        CatalogHashAlgo: The hash algorithm used by the catalog.
    *  Returns:
        A Windows error code indicating the result of the verification process.
    */

    DWORD verifyFromCatalog(const std::wstring& aPePath, const std::wstring& aCatalogHashAlgo);

    /** 
        // Verify trust from a catalog object (entry) using its information.
    * Parameters:
       aCatInfo: Handle to the catalog object.
       aFileName: The file name to be verified.
       aHash: The hash of the file as a wide string.
    * Returns:
       A Windows error code indicating the result of the verification process.
    */

    DWORD verifyTrustFromCatObject(HCATINFO aCatInfo, const std::wstring& aFileName, const std::wstring& aHash);

    /**
        // Convert a byte array hash into a wide string representation.
    * Parameters:
       aHash: The byte array hash to be converted.
       aHashLen: The length of the hash.
    * Returns:
       The hash as a wide string in hexadecimal format.
    */

    std::wstring ByteHashIntoWstring(BYTE* aHash, size_t aHashLen);
};

#endif