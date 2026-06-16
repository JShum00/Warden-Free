#ifndef WARDEN_FREE_CORE_THREATAGGREGATION_H
#define WARDEN_FREE_CORE_THREATAGGREGATION_H

#include <string>
#include <vector>

#include "warden/core/ScanTypes.h"

namespace warden::core {

std::string threatRecordId(const ThreatFinding &finding);
std::vector<ThreatRecord> aggregateThreatFindings(const std::vector<ThreatFinding> &findings);

} // namespace warden::core

#endif
