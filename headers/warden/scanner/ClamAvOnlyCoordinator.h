#ifndef WARDEN_FREE_SCANNER_CLAMAVONLYCOORDINATOR_H
#define WARDEN_FREE_SCANNER_CLAMAVONLYCOORDINATOR_H

#include "warden/core/ScanTypes.h"
#include "warden/scanner/ClamAvScanner.h"
#include "warden/scanner/Sha256Hasher.h"

namespace warden::scanner {

class ClamAvOnlyCoordinator
{
public:
    core::ScanReport runScan(const core::ScanOptions &options);

private:
    ClamAvScanner m_clamAvScanner;
    Sha256Hasher m_sha256Hasher;
};

} // namespace warden::scanner

#endif
