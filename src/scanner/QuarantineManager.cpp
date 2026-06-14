#include "warden/scanner/QuarantineManager.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace {

std::string sanitizeFilename(std::string name)
{
    std::transform(name.begin(), name.end(), name.begin(), [](unsigned char character) {
        if (std::isalnum(character) != 0 || character == '.' || character == '_' || character == '-') {
            return static_cast<char>(character);
        }

        return '_';
    });

    if (name.empty()) {
        return "quarantined-file";
    }

    return name;
}

std::string currentTimestamp()
{
    const auto now = std::chrono::system_clock::now();
    const std::time_t nowTime = std::chrono::system_clock::to_time_t(now);
    std::tm timestamp {};
    localtime_r(&nowTime, &timestamp);

    std::ostringstream output;
    output << std::put_time(&timestamp, "%Y%m%d-%H%M%S");
    return output.str();
}

} // namespace

namespace warden::scanner {

QuarantineManager::QuarantineManager(std::filesystem::path quarantineDirectory)
    : m_quarantineDirectory(std::move(quarantineDirectory))
{
}

QuarantineResult QuarantineManager::quarantine(const core::ThreatFinding &finding) const
{
    QuarantineResult result;
    if (finding.path.empty()) {
        result.error = "Threat finding does not contain a file path to quarantine.";
        return result;
    }

    std::error_code errorCode;
    if (!std::filesystem::exists(finding.path, errorCode)) {
        result.error = "Source file does not exist: " + finding.path.string();
        return result;
    }

    if (!std::filesystem::create_directories(m_quarantineDirectory, errorCode) && errorCode) {
        result.error = "Unable to create quarantine directory: " + errorCode.message();
        return result;
    }

    const std::string hashPrefix = finding.sha256.empty() ? "nosha256" : finding.sha256.substr(0, 12);
    const std::string baseName = sanitizeFilename(finding.path.filename().string());
    const std::string destinationFileName = currentTimestamp() + "_" + hashPrefix + "_" + baseName + ".quarantine";

    result.quarantinedPath = m_quarantineDirectory / destinationFileName;
    std::filesystem::rename(finding.path, result.quarantinedPath, errorCode);
    if (errorCode) {
        errorCode.clear();
        std::filesystem::copy_file(finding.path, result.quarantinedPath, std::filesystem::copy_options::overwrite_existing, errorCode);
        if (errorCode) {
            result.error = "Unable to move or copy file into quarantine: " + errorCode.message();
            return result;
        }

        std::filesystem::remove(finding.path, errorCode);
        if (errorCode) {
            result.error = "File copied to quarantine but original could not be removed: " + errorCode.message();
            return result;
        }
    }

    result.metadataPath = result.quarantinedPath;
    result.metadataPath += ".meta";

    std::ofstream metadata(result.metadataPath);
    if (!metadata) {
        result.error = "File was quarantined, but metadata sidecar could not be written.";
        return result;
    }

    metadata << "name=" << finding.name << '\n';
    metadata << "original_path=" << finding.path.string() << '\n';
    metadata << "quarantined_path=" << result.quarantinedPath.string() << '\n';
    metadata << "threat_type=" << core::toString(finding.threatType) << '\n';
    metadata << "severity=" << core::toString(finding.severity) << '\n';
    metadata << "source=" << finding.source << '\n';
    metadata << "sha256=" << finding.sha256 << '\n';
    metadata << "recommended_action=" << finding.recommendedAction << '\n';

    result.success = true;
    return result;
}

} // namespace warden::scanner
