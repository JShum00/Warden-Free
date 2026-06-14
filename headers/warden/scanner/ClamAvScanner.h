#ifndef WARDEN_FREE_SCANNER_CLAMAVSCANNER_H
#define WARDEN_FREE_SCANNER_CLAMAVSCANNER_H

#include <filesystem>
#include <string>
#include <vector>

#include "warden/core/ScanTypes.h"

struct cl_engine;

namespace warden::scanner {

struct ClamAvLoadStatus {
    bool available {false};
    bool initialized {false};
    unsigned int signatures {0};
    std::string version;
    std::string databasePath;
    std::string error;
};

struct ClamAvScanResult {
    bool scanned {false};
    bool infected {false};
    unsigned long scannedObjects {0};
    std::vector<core::ThreatFinding> findings;
    std::string error;
};

class ClamAvScanner
{
public:
    ClamAvScanner();
    ~ClamAvScanner();

    bool initialize(const std::filesystem::path &databasePath);
    ClamAvScanResult scanFile(const std::filesystem::path &filePath,
                              const std::string &sha256) const;
    const ClamAvLoadStatus &status() const;

    static std::filesystem::path defaultDatabasePath();

private:
    cl_engine *m_engine;
    ClamAvLoadStatus m_status;
};

} // namespace warden::scanner

#endif
