#include "warden/scanner/QuarantineManager.h"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
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

std::map<std::string, std::string> readMetadataFile(const std::filesystem::path &metadataPath)
{
    std::map<std::string, std::string> values;
    std::ifstream stream(metadataPath);
    if (!stream) {
        return values;
    }

    std::string line;
    while (std::getline(stream, line)) {
        const std::size_t separator = line.find('=');
        if (separator == std::string::npos) {
            continue;
        }

        values.emplace(line.substr(0, separator), line.substr(separator + 1));
    }

    return values;
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

std::vector<QuarantineEntry> QuarantineManager::listEntries() const
{
    std::vector<QuarantineEntry> entries;

    std::error_code errorCode;
    if (!std::filesystem::exists(m_quarantineDirectory, errorCode)) {
        return entries;
    }

    for (const auto &entry : std::filesystem::directory_iterator(m_quarantineDirectory, errorCode)) {
        if (errorCode) {
            break;
        }
        if (!entry.is_regular_file(errorCode)) {
            errorCode.clear();
            continue;
        }
        if (entry.path().extension() == ".meta") {
            continue;
        }

        QuarantineEntry item;
        item.quarantinedPath = entry.path();
        item.metadataPath = entry.path();
        item.metadataPath += ".meta";

        const auto metadata = readMetadataFile(item.metadataPath);
        if (const auto originalPath = metadata.find("original_path"); originalPath != metadata.end()) {
            item.originalPath = std::filesystem::path(originalPath->second);
        }
        if (const auto threatName = metadata.find("name"); threatName != metadata.end()) {
            item.threatName = threatName->second;
        }
        if (const auto sha256 = metadata.find("sha256"); sha256 != metadata.end()) {
            item.sha256 = sha256->second;
        }

        entries.push_back(std::move(item));
    }

    std::sort(entries.begin(), entries.end(), [](const QuarantineEntry &left, const QuarantineEntry &right) {
        return left.quarantinedPath.filename().string() < right.quarantinedPath.filename().string();
    });
    return entries;
}

QuarantineRestoreResult QuarantineManager::restore(const std::filesystem::path &quarantinedPath,
                                                   const std::filesystem::path &restorePath) const
{
    QuarantineRestoreResult result;
    std::error_code errorCode;
    if (!std::filesystem::exists(quarantinedPath, errorCode)) {
        result.error = "Quarantined file does not exist: " + quarantinedPath.string();
        return result;
    }

    std::filesystem::path metadataPath = quarantinedPath;
    metadataPath += ".meta";
    const auto metadata = readMetadataFile(metadataPath);

    std::filesystem::path resolvedRestorePath = restorePath;
    if (resolvedRestorePath.empty()) {
        const auto iterator = metadata.find("original_path");
        if (iterator != metadata.end() && !iterator->second.empty()) {
            resolvedRestorePath = std::filesystem::path(iterator->second);
        }
    }
    if (resolvedRestorePath.empty()) {
        resolvedRestorePath = quarantinedPath.stem();
    }

    std::filesystem::create_directories(resolvedRestorePath.parent_path(), errorCode);
    if (errorCode) {
        result.error = "Unable to create restore destination: " + errorCode.message();
        return result;
    }

    std::filesystem::rename(quarantinedPath, resolvedRestorePath, errorCode);
    if (errorCode) {
        errorCode.clear();
        std::filesystem::copy_file(quarantinedPath,
                                   resolvedRestorePath,
                                   std::filesystem::copy_options::overwrite_existing,
                                   errorCode);
        if (errorCode) {
            result.error = "Unable to restore quarantined file: " + errorCode.message();
            return result;
        }

        std::filesystem::remove(quarantinedPath, errorCode);
        if (errorCode) {
            result.error = "Restored copy created but original quarantine file could not be removed: " + errorCode.message();
            return result;
        }
    }

    result.restoredPath = resolvedRestorePath;
    result.success = true;
    return result;
}

} // namespace warden::scanner
