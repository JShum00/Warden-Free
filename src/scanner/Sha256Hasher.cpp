#include "warden/scanner/Sha256Hasher.h"

#include <array>
#include <fstream>
#include <iomanip>
#include <sstream>

#include <openssl/evp.h>

namespace warden::scanner {

HashResult Sha256Hasher::hashFile(const std::filesystem::path &filePath) const
{
    HashResult result;

    std::ifstream stream(filePath, std::ios::binary);
    if (!stream) {
        result.error = "Unable to open file for hashing: " + filePath.string();
        return result;
    }

    EVP_MD_CTX *context = EVP_MD_CTX_new();
    if (context == nullptr) {
        result.error = "OpenSSL failed to allocate a SHA-256 context.";
        return result;
    }

    if (EVP_DigestInit_ex(context, EVP_sha256(), nullptr) != 1) {
        EVP_MD_CTX_free(context);
        result.error = "OpenSSL failed to initialize SHA-256.";
        return result;
    }

    std::array<char, 64 * 1024> buffer {};
    while (stream.good()) {
        stream.read(buffer.data(), static_cast<std::streamsize>(buffer.size()));
        const std::streamsize bytesRead = stream.gcount();

        if (bytesRead > 0) {
            if (EVP_DigestUpdate(context, buffer.data(), static_cast<std::size_t>(bytesRead)) != 1) {
                EVP_MD_CTX_free(context);
                result.error = "OpenSSL failed while hashing " + filePath.string();
                return result;
            }

            result.bytesRead += static_cast<std::uintmax_t>(bytesRead);
        }
    }

    if (stream.bad()) {
        EVP_MD_CTX_free(context);
        result.error = "I/O error while hashing " + filePath.string();
        return result;
    }

    std::array<unsigned char, EVP_MAX_MD_SIZE> digest {};
    unsigned int digestLength = 0;
    if (EVP_DigestFinal_ex(context, digest.data(), &digestLength) != 1) {
        EVP_MD_CTX_free(context);
        result.error = "OpenSSL failed to finalize SHA-256 for " + filePath.string();
        return result;
    }

    EVP_MD_CTX_free(context);

    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned int index = 0; index < digestLength; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(digest[index]);
    }

    result.success = true;
    result.hexDigest = output.str();
    return result;
}

} // namespace warden::scanner
