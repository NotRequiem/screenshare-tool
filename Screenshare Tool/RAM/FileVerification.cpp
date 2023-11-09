#include "FileVerification.hpp"
#include "TrustVerifyWrapper.hpp"

// Checks if the digital signature of a file is valid (official) or spoofed/not valid
bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}
