#ifndef WARDEN_FREE_SCANNER_QUARANTINEMANAGER_H
#define WARDEN_FREE_SCANNER_QUARANTINEMANAGER_H

#include <filesystem>
#include <string>
#include <vector>

#include "warden/core/ScanTypes.h"

namespace warden::scanner {

struct QuarantineResult {
    bool success {false};
    std::filesystem::path quarantinedPath;
    std::filesystem::path metadataPath;
    std::string error;
};

struct QuarantineRestoreResult {
    bool success {false};
    std::filesystem::path restoredPath;
    std::string error;
};

struct QuarantineEntry {
    std::filesystem::path quarantinedPath;
    std::filesystem::path metadataPath;
    std::filesystem::path originalPath;
    std::string threatName;
    std::string sha256;
};

class QuarantineManager
{
public:
    explicit QuarantineManager(std::filesystem::path quarantineDirectory);

    QuarantineResult quarantine(const core::ThreatFinding &finding) const;
    std::vector<QuarantineEntry> listEntries() const;
    QuarantineRestoreResult restore(const std::filesystem::path &quarantinedPath,
                                    const std::filesystem::path &restorePath = {}) const;

private:
    std::filesystem::path m_quarantineDirectory;
};

} // namespace warden::scanner

#endif
