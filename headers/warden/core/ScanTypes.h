#ifndef WARDEN_FREE_CORE_SCANTYPES_H
#define WARDEN_FREE_CORE_SCANTYPES_H

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

#include <QMetaType>

namespace warden::core {

enum class Severity {
    Informational,
    Low,
    Medium,
    High,
    Critical
};

enum class ThreatType {
    Heuristic,
    ClamAvSignature,
    CustomDefinition,
    SuspiciousScript,
    BrowserHijacker,
    PotentiallyUnwantedProgram,
    Quarantine,
    Unknown
};

enum class ScanMode {
    Quick,
    Full,
    SignatureOnly,
    HeuristicOnly,
    Custom
};

enum class DetectionSource {
    Signature,
    Heuristic,
    ScriptAnalysis,
    Multiple,
    Unknown
};

enum class FindingCategory {
    Informational,
    Finding,
    Warning,
    PUP,
    Threat
};

enum class ScanPhase {
    Preparing,
    Discovering,
    LocalAnalysis,
    SignaturePass,
    Finalizing,
    Completed
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
    case ThreatType::Heuristic:
        return "heuristic";
    case ThreatType::ClamAvSignature:
        return "clamav-signature";
    case ThreatType::CustomDefinition:
        return "custom-definition";
    case ThreatType::SuspiciousScript:
        return "suspicious-script";
    case ThreatType::BrowserHijacker:
        return "browser-hijacker";
    case ThreatType::PotentiallyUnwantedProgram:
        return "pup";
    case ThreatType::Quarantine:
        return "quarantine";
    case ThreatType::Unknown:
        return "unknown";
    }

    return "unknown";
}

inline ThreatType threatTypeFromString(const std::string &value)
{
    const std::string normalized = toLowerCopy(value);

    if (normalized == "heuristic") {
        return ThreatType::Heuristic;
    }
    if (normalized == "clamav-signature" || normalized == "clamav" || normalized == "signature") {
        return ThreatType::ClamAvSignature;
    }
    if (normalized == "custom-definition" || normalized == "custom" || normalized == "warden-dat") {
        return ThreatType::CustomDefinition;
    }
    if (normalized == "suspicious-script" || normalized == "script" || normalized == "activex") {
        return ThreatType::SuspiciousScript;
    }
    if (normalized == "browser-hijacker" || normalized == "hijacker") {
        return ThreatType::BrowserHijacker;
    }
    if (normalized == "pup" || normalized == "potentially-unwanted-program") {
        return ThreatType::PotentiallyUnwantedProgram;
    }
    if (normalized == "quarantine") {
        return ThreatType::Quarantine;
    }

    return ThreatType::Unknown;
}

inline std::string toString(const DetectionSource detectionSource)
{
    switch (detectionSource) {
    case DetectionSource::Signature:
        return "Signature";
    case DetectionSource::Heuristic:
        return "Heuristic";
    case DetectionSource::ScriptAnalysis:
        return "Script Analysis";
    case DetectionSource::Multiple:
        return "Multiple";
    case DetectionSource::Unknown:
        return "Unknown";
    }

    return "Unknown";
}

inline DetectionSource detectionSourceFromString(const std::string &value)
{
    const std::string normalized = toLowerCopy(value);

    if (normalized == "signature") {
        return DetectionSource::Signature;
    }
    if (normalized == "heuristic") {
        return DetectionSource::Heuristic;
    }
    if (normalized == "script analysis" || normalized == "script-analysis" || normalized == "script") {
        return DetectionSource::ScriptAnalysis;
    }
    if (normalized == "multiple") {
        return DetectionSource::Multiple;
    }

    return DetectionSource::Unknown;
}

inline std::string toString(const FindingCategory category)
{
    switch (category) {
    case FindingCategory::Informational:
        return "Informational";
    case FindingCategory::Finding:
        return "Finding";
    case FindingCategory::Warning:
        return "Warning";
    case FindingCategory::PUP:
        return "PUP";
    case FindingCategory::Threat:
        return "Threat";
    }

    return "Finding";
}

inline FindingCategory findingCategoryFromString(const std::string &value)
{
    const std::string normalized = toLowerCopy(value);

    if (normalized == "informational" || normalized == "info") {
        return FindingCategory::Informational;
    }
    if (normalized == "finding") {
        return FindingCategory::Finding;
    }
    if (normalized == "warning") {
        return FindingCategory::Warning;
    }
    if (normalized == "pup") {
        return FindingCategory::PUP;
    }
    if (normalized == "threat") {
        return FindingCategory::Threat;
    }

    return FindingCategory::Finding;
}

inline int findingCategoryRank(const FindingCategory category)
{
    switch (category) {
    case FindingCategory::Informational:
        return 0;
    case FindingCategory::Finding:
        return 1;
    case FindingCategory::Warning:
        return 2;
    case FindingCategory::PUP:
        return 3;
    case FindingCategory::Threat:
        return 4;
    }

    return 1;
}

inline FindingCategory inferFindingCategory(const ThreatType threatType,
                                            const DetectionSource detectionSource,
                                            const Severity severity)
{
    if (threatType == ThreatType::PotentiallyUnwantedProgram ||
        threatType == ThreatType::BrowserHijacker) {
        return FindingCategory::PUP;
    }
    if (severity == Severity::Informational) {
        return FindingCategory::Informational;
    }
    if (detectionSource == DetectionSource::Signature ||
        detectionSource == DetectionSource::ScriptAnalysis) {
        return FindingCategory::Threat;
    }
    if (severity >= Severity::High) {
        return FindingCategory::Threat;
    }
    if (severity == Severity::Medium) {
        return FindingCategory::Warning;
    }

    return FindingCategory::Finding;
}

inline std::string toString(const ScanMode mode)
{
    switch (mode) {
    case ScanMode::Quick:
        return "Quick";
    case ScanMode::Full:
        return "Full";
    case ScanMode::SignatureOnly:
        return "Signature-Only";
    case ScanMode::HeuristicOnly:
        return "Heuristic-Only";
    case ScanMode::Custom:
        return "Custom";
    }

    return "Quick";
}

inline std::string toString(const ScanPhase phase)
{
    switch (phase) {
    case ScanPhase::Preparing:
        return "Preparing";
    case ScanPhase::Discovering:
        return "Discovering";
    case ScanPhase::LocalAnalysis:
        return "Local Analysis";
    case ScanPhase::SignaturePass:
        return "Signature Pass";
    case ScanPhase::Finalizing:
        return "Finalizing";
    case ScanPhase::Completed:
        return "Completed";
    }

    return "Preparing";
}

struct ThreatFinding {
    std::string name;
    std::filesystem::path path;
    ThreatType threatType {ThreatType::Unknown};
    FindingCategory classification {FindingCategory::Threat};
    Severity severity {Severity::Medium};
    std::string source;
    std::string detectionEngine;
    DetectionSource detectionSource {DetectionSource::Unknown};
    std::string description;
    std::string operatorSummary;
    std::string recommendedAction;
    std::string sha256;
    std::uintmax_t fileSize {0};
    double entropy {0.0};
    double confidenceScore {0.0};
    std::vector<std::string> triggeredRules;
    std::vector<std::string> evidence;
};

struct ThreatRecord {
    std::string id;
    std::string name;
    std::filesystem::path path;
    ThreatType threatType {ThreatType::Unknown};
    FindingCategory classification {FindingCategory::Threat};
    Severity severity {Severity::Medium};
    DetectionSource detectionSource {DetectionSource::Unknown};
    std::vector<std::string> detectionEngines;
    std::string detectionMethod;
    std::string description;
    std::string operatorSummary;
    std::string recommendedAction;
    std::string sha256;
    std::uintmax_t fileSize {0};
    double entropy {0.0};
    double confidenceScore {0.0};
    std::vector<std::string> triggeredRules;
    std::vector<std::string> evidence;
    std::vector<ThreatFinding> findings;
};

struct ScanStats {
    std::size_t visitedDirectories {0};
    std::size_t visitedFiles {0};
    std::size_t scannedFiles {0};
    std::size_t resultCount {0};
    std::size_t threatsFound {0};
    std::size_t uniqueFilesFlagged {0};
    std::size_t warningCount {0};
    std::uintmax_t bytesHashed {0};
    std::uintmax_t bytesScannedByClamAv {0};
};

struct ScanOptions {
    std::filesystem::path targetPath;
    std::filesystem::path clamAvDatabasePath;
    std::filesystem::path customDefinitionPath;
    std::filesystem::path quarantineDirectory;
    bool recursive {true};
    bool includeHidden {false};
    std::uintmax_t maxFileSizeBytes {256ULL * 1024ULL * 1024ULL};
    ScanMode mode {ScanMode::Quick};
    bool enableHeuristics {true};
    bool enableClamAv {true};
    bool enableCustomDat {false};
    bool enableScriptActivity {false};
    bool enablePupScan {false};
    bool scanDevelopmentEnvironments {false};
};

struct ScanProgress {
    ScanPhase phase {ScanPhase::Preparing};
    std::string phaseLabel;
    std::string currentItem;
    std::size_t scannedFiles {0};
    std::size_t totalFiles {0};
    std::size_t threatsFound {0};
    bool indeterminate {false};
    std::vector<std::string> activeEngines;
};

struct ScanReport {
    ScanOptions options;
    ScanStats stats;
    std::vector<ThreatFinding> findings;
    std::vector<ThreatRecord> records;
    std::vector<std::string> warnings;
    bool clamAvLoaded {false};
    unsigned int clamAvSignatures {0};
    std::string clamAvVersion;
    std::filesystem::path customDefinitionPath;
    std::size_t customDefinitionsLoaded {0};
    std::string startedAtUtc;
    std::string completedAtUtc;
    std::uint64_t durationMs {0};
    bool canceled {false};
    std::string cancelPhase;
};

} // namespace warden::core

Q_DECLARE_METATYPE(warden::core::ScanReport)

#endif
