#ifndef WARDEN_FREE_SCANNER_SCANCOORDINATOR_H
#define WARDEN_FREE_SCANNER_SCANCOORDINATOR_H

#include <atomic>
#include <functional>
#include <memory>

#include "warden/core/ScanTypes.h"
#include "warden/scanner/ClamAvScanner.h"
#include "warden/scanner/HeuristicAnalyzer.h"
#include "warden/scanner/Sha256Hasher.h"

namespace warden::scanner {

using ScanProgressCallback = std::function<void(const core::ScanProgress &)>;
using ScanCancelFlag = std::shared_ptr<std::atomic_bool>;

class ScanCoordinator
{
public:
    core::ScanReport runScan(const core::ScanOptions &options,
                             const ScanProgressCallback &progressCallback = {},
                             const ScanCancelFlag &cancelRequested = {});

private:
    ClamAvScanner m_clamAvScanner;
    HeuristicAnalyzer m_heuristicAnalyzer;
    Sha256Hasher m_sha256Hasher;
};

} // namespace warden::scanner

#endif
