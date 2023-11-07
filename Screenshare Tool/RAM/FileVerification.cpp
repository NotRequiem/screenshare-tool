#include "FileVerification.hpp"
#include "TrustVerifyWrapper.hpp"

bool IsFileSignatureValid(const std::wstring& filePath) {
    TrustVerifyWrapper wrapper;
    return wrapper.VerifyFileSignature(filePath);
}
