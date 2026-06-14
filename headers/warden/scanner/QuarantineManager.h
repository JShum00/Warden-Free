#ifndef WARDEN_FREE_SCANNER_QUARANTINEMANAGER_H
#define WARDEN_FREE_SCANNER_QUARANTINEMANAGER_H

#include <filesystem>
#include <string>

#include "warden/core/ScanTypes.h"

namespace warden::scanner {

struct QuarantineResult {
    bool success {false};
    std::filesystem::path quarantinedPath;
    std::filesystem::path metadataPath;
    std::string error;
};

class QuarantineManager
{
public:
    explicit QuarantineManager(std::filesystem::path quarantineDirectory);

    QuarantineResult quarantine(const core::ThreatFinding &finding) const;

private:
    std::filesystem::path m_quarantineDirectory;
};

} // namespace warden::scanner

#endif
