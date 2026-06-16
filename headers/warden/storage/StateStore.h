#ifndef WARDEN_FREE_STORAGE_STATESTORE_H
#define WARDEN_FREE_STORAGE_STATESTORE_H

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

#include "warden/core/ScanTypes.h"

namespace warden::storage {

struct ScanHistoryEntry {
    std::int64_t id {0};
    std::string scanKind;
    std::string profile;
    std::string startedAtUtc;
    std::string completedAtUtc;
    std::uint64_t durationMs {0};
    std::size_t itemCount {0};
    std::size_t threatCount {0};
    std::size_t warningCount {0};
    std::string actionsSummary;
    std::string summaryText;
    std::string findingsJson;
    std::string warningsJson;
};

struct ExclusionEntry {
    std::int64_t id {0};
    std::string matchType;
    std::string matchValue;
    std::string label;
    std::string createdAtUtc;
};

struct QuarantineCatalogEntry {
    std::int64_t id {0};
    std::string findingId;
    std::filesystem::path originalPath;
    std::filesystem::path quarantinedPath;
    std::filesystem::path metadataPath;
    std::string sha256;
    std::string threatName;
    std::string status;
    std::string createdAtUtc;
    std::string restoredAtUtc;
    std::filesystem::path restoredPath;
};

class StateStore
{
public:
    explicit StateStore(std::filesystem::path databasePath = {});

    bool initialize(std::string &errorMessage) const;

    std::int64_t recordScan(const ScanHistoryEntry &entry, std::string &errorMessage) const;
    std::vector<ScanHistoryEntry> listScanHistory(std::size_t limit = 50) const;
    bool recordScanAction(std::int64_t scanHistoryId,
                          const std::string &findingId,
                          const std::string &action,
                          const std::string &details,
                          std::string &errorMessage) const;

    bool addExclusion(const ExclusionEntry &entry, std::string &errorMessage) const;
    bool removeExclusion(std::int64_t exclusionId, std::string &errorMessage) const;
    std::vector<ExclusionEntry> listExclusions() const;
    bool isExcluded(const core::ThreatFinding &finding) const;
    std::vector<core::ThreatFinding> filterExcludedFindings(const std::vector<core::ThreatFinding> &findings) const;

    bool recordQuarantineEntry(const QuarantineCatalogEntry &entry, std::string &errorMessage) const;
    std::vector<QuarantineCatalogEntry> listQuarantineEntries() const;
    std::optional<QuarantineCatalogEntry> findQuarantineEntry(const std::filesystem::path &quarantinedPath) const;
    bool markQuarantineRestored(const std::filesystem::path &quarantinedPath,
                                const std::filesystem::path &restoredPath,
                                std::string &errorMessage) const;

    bool setStatusSnapshot(const std::string &key, const std::string &value, std::string &errorMessage) const;
    std::string statusSnapshotValue(const std::string &key) const;

    const std::filesystem::path &databasePath() const;

private:
    bool ensureDataDirectory(std::string &errorMessage) const;

    std::filesystem::path m_databasePath;
};

} // namespace warden::storage

#endif
