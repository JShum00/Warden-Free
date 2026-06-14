#ifndef WARDEN_FREE_CORE_SCANTYPES_H
#define WARDEN_FREE_CORE_SCANTYPES_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace warden::core {

enum class Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical
};

enum class ThreatType {
    ClamAvSignature,
    Quarantine,
    Unknown
};

enum class ScanMode {
    Quick,
    Full
};

inline std::string toLowerCopy(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char character) {
        return static_cast<char>(std::tolower(character));
    });
    return value;
}

inline std::string toString(const Severity severity)
{
    switch (severity) {
    case Severity::Informational:
        return "informational";
    case Severity::Low:
        return "low";
    case Severity::Medium:
        return "medium";
    case Severity::High:
        return "high";
    case Severity::Critical:
        return "critical";
    }

    return "unknown";
}

inline Severity severityFromString(const std::string &value)
{
    const std::string normalized = toLowerCopy(value);
    if (normalized == "informational" || normalized == "info") {
        return Severity::Informational;
    }
    if (normalized == "low") {
        return Severity::Low;
    }
    if (normalized == "medium") {
        return Severity::Medium;
    }
    if (normalized == "high") {
        return Severity::High;
    }
    if (normalized == "critical") {
        return Severity::Critical;
    }
    return Severity::Medium;
}

inline std::string toString(const ThreatType threatType)
{
    switch (threatType) {
    case ThreatType::ClamAvSignature:
        return "clamav-signature";
    case ThreatType::Quarantine:
        return "quarantine";
    case ThreatType::Unknown:
        return "unknown";
    }

    return "unknown";
}

struct ThreatFinding {
    std::string name;
    std::filesystem::path path;
    ThreatType threatType {ThreatType::Unknown};
    Severity severity {Severity::Medium};
    std::string source;
    std::string description;
    std::string recommendedAction;
    std::string sha256;
    std::uintmax_t fileSize {0};
    double entropy {0.0};
    std::vector<std::string> evidence;
};

struct ScanStats {
    std::size_t visitedDirectories {0};
    std::size_t visitedFiles {0};
    std::size_t scannedFiles {0};
    std::size_t threatsFound {0};
    std::size_t warningCount {0};
    std::uintmax_t bytesHashed {0};
    std::uintmax_t bytesScannedByClamAv {0};
};

struct ScanOptions {
    std::filesystem::path targetPath;
    std::filesystem::path clamAvDatabasePath;
    std::filesystem::path quarantineDirectory;
    bool recursive {true};
    bool includeHidden {false};
    std::uintmax_t maxFileSizeBytes {256ULL * 1024ULL * 1024ULL};
    ScanMode mode {ScanMode::Quick};
    bool enableClamAv {true};
};

struct ScanReport {
    ScanOptions options;
    ScanStats stats;
    std::vector<ThreatFinding> findings;
    std::vector<std::string> warnings;
    bool clamAvLoaded {false};
    unsigned int clamAvSignatures {0};
    std::string clamAvVersion;
};

} // namespace warden::core

#endif
