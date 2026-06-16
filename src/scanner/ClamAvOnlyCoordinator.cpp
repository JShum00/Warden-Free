#include "warden/scanner/ClamAvOnlyCoordinator.h"

#include "warden/core/ThreatAggregation.h"
#include "warden/network/DefinitionUpdater.h"
#include "warden/scanner/FileWalker.h"

#include <QDateTime>

#include <chrono>
#include <iterator>

namespace {

void appendFindings(std::vector<warden::core::ThreatFinding> &destination,
                    std::vector<warden::core::ThreatFinding> source)
{
    destination.insert(destination.end(),
                       std::make_move_iterator(source.begin()),
                       std::make_move_iterator(source.end()));
}

void appendWarning(std::vector<std::string> &warnings, const std::string &message)
{
    warnings.push_back(message);
}

std::string currentTimestampUtc()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODate).toStdString();
}

} // namespace

namespace warden::scanner {

core::ScanReport ClamAvOnlyCoordinator::runScan(const core::ScanOptions &options)
{
    core::ScanReport report;
    report.options = options;
    report.startedAtUtc = currentTimestampUtc();
    const auto startedAt = std::chrono::steady_clock::now();

    if (report.options.targetPath.empty()) {
        report.options.targetPath = std::filesystem::current_path();
    }
    if (report.options.clamAvDatabasePath.empty()) {
        report.options.clamAvDatabasePath = warden::network::DefinitionUpdater::preferredDatabaseDirectory();
    }

    std::error_code targetError;
    if (!std::filesystem::exists(report.options.targetPath, targetError)) {
        appendWarning(report.warnings, "Scan target does not exist: " + report.options.targetPath.string());
        report.stats.warningCount = report.warnings.size();
        report.completedAtUtc = currentTimestampUtc();
        report.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
        );
        return report;
    }

    if (!report.options.enableClamAv) {
        appendWarning(report.warnings, "ClamAV scanning is disabled in the current scan options.");
        report.stats.warningCount = report.warnings.size();
        report.completedAtUtc = currentTimestampUtc();
        report.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
        );
        return report;
    }

    const std::filesystem::path databasePath = report.options.clamAvDatabasePath.empty()
        ? ClamAvScanner::defaultDatabasePath()
        : report.options.clamAvDatabasePath;
    report.options.clamAvDatabasePath = databasePath;

    if (m_clamAvScanner.initialize(databasePath)) {
        report.clamAvLoaded = true;
        report.clamAvSignatures = m_clamAvScanner.status().signatures;
        report.clamAvVersion = m_clamAvScanner.status().version;
    } else {
        appendWarning(report.warnings, "ClamAV initialization failed: " + m_clamAvScanner.status().error);
    }

    FileWalker::walk(
        report.options.targetPath,
        report.options.recursive,
        report.options.includeHidden,
        report.stats,
        report.warnings,
        [&](const std::filesystem::directory_entry &entry) {
            const std::filesystem::path filePath = entry.path();
            std::error_code fileSizeError;
            const std::uintmax_t fileSize = entry.file_size(fileSizeError);
            if (!fileSizeError && fileSize > report.options.maxFileSizeBytes) {
                appendWarning(report.warnings, "Large file exceeds preferred scan size threshold: " + filePath.string());
            }

            const HashResult hashResult = m_sha256Hasher.hashFile(filePath);
            if (!hashResult.success) {
                appendWarning(report.warnings, hashResult.error);
                return;
            }

            ++report.stats.scannedFiles;
            report.stats.bytesHashed += hashResult.bytesRead;

            if (!report.clamAvLoaded) {
                return;
            }

            ClamAvScanResult clamAvResult = m_clamAvScanner.scanFile(filePath, hashResult.hexDigest);
            report.stats.bytesScannedByClamAv += clamAvResult.scannedObjects;
            if (!clamAvResult.error.empty()) {
                appendWarning(report.warnings, clamAvResult.error);
            }

            appendFindings(report.findings, std::move(clamAvResult.findings));
        }
    );

    report.records = core::aggregateThreatFindings(report.findings);
    report.stats.resultCount = report.findings.size();
    report.stats.threatsFound = report.records.size();
    report.stats.uniqueFilesFlagged = report.records.size();
    report.stats.warningCount = report.warnings.size();
    report.completedAtUtc = currentTimestampUtc();
    report.durationMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
    );
    return report;
}

} // namespace warden::scanner
