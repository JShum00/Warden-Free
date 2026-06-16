#ifndef WARDEN_FREE_SCANNER_HEURISTICANALYZER_H
#define WARDEN_FREE_SCANNER_HEURISTICANALYZER_H

#include <filesystem>
#include <string>
#include <vector>

#include "warden/core/ScanTypes.h"

namespace warden::scanner {

struct HeuristicScanResult {
    std::vector<core::ThreatFinding> findings;
    double entropy {0.0};
    bool binaryLike {false};
    std::string error;
};

class HeuristicAnalyzer
{
public:
    HeuristicScanResult analyzeFile(const std::filesystem::path &filePath,
                                    const std::string &sha256,
                                    const core::ScanOptions &options) const;
};

} // namespace warden::scanner

#endif
