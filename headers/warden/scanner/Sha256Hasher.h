#ifndef WARDEN_FREE_SCANNER_SHA256HASHER_H
#define WARDEN_FREE_SCANNER_SHA256HASHER_H

#include <cstdint>
#include <filesystem>
#include <string>

namespace warden::scanner {

struct HashResult {
    bool success {false};
    std::string hexDigest;
    std::uintmax_t bytesRead {0};
    std::string error;
};

class Sha256Hasher
{
public:
    HashResult hashFile(const std::filesystem::path &filePath) const;
};

} // namespace warden::scanner

#endif
