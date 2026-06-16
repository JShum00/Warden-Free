#include "warden/scanner/ScanCoordinator.h"

#include "warden/core/ThreatAggregation.h"
#include "warden/network/DefinitionUpdater.h"
#include "warden/scanner/FileWalker.h"

#include <QDateTime>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <optional>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

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

std::vector<std::string> activeEnginesForOptions(const warden::core::ScanOptions &options)
{
    std::vector<std::string> engines;
    if (options.enableClamAv) {
        engines.push_back("ClamAV");
    }
    if (options.enableHeuristics) {
        engines.push_back("Warden Heuristics");
    }
    return engines;
}

void emitProgress(const warden::scanner::ScanProgressCallback &progressCallback,
                  const warden::core::ScanPhase phase,
                  const std::string &currentItem,
                  const std::size_t scannedFiles,
                  const std::size_t totalFiles,
                  const std::size_t threatsFound,
                  const bool indeterminate,
                  const std::vector<std::string> &activeEngines)
{
    if (!progressCallback) {
        return;
    }

    progressCallback(warden::core::ScanProgress {
        phase,
        warden::core::toString(phase),
        currentItem,
        scannedFiles,
        totalFiles,
        threatsFound,
        indeterminate,
        activeEngines
    });
}

bool cancelRequested(const warden::scanner::ScanCancelFlag &cancelFlag)
{
    return cancelFlag != nullptr && cancelFlag->load();
}

std::string deduplicationKeyForFinding(const warden::core::ThreatFinding &finding)
{
    std::vector<std::string> normalizedRules = finding.triggeredRules;
    std::sort(normalizedRules.begin(), normalizedRules.end());

    std::ostringstream stream;
    stream << (!finding.sha256.empty() ? finding.sha256 : finding.path.string())
           << '|'
           << finding.name
           << '|'
           << warden::core::toString(finding.threatType)
           << '|'
           << warden::core::toString(finding.detectionSource)
           << '|'
           << finding.detectionEngine;
    for (const auto &rule : normalizedRules) {
        stream << '|' << rule;
    }
    return stream.str();
}

void suppressDuplicateFindingsByHash(std::vector<warden::core::ThreatFinding> &findings)
{
    std::unordered_set<std::string> seenKeys;
    std::vector<warden::core::ThreatFinding> uniqueFindings;
    uniqueFindings.reserve(findings.size());

    for (auto &finding : findings) {
        const std::string key = deduplicationKeyForFinding(finding);
        if (!seenKeys.insert(key).second) {
            continue;
        }
        uniqueFindings.push_back(std::move(finding));
    }

    findings = std::move(uniqueFindings);
}

} // namespace

namespace warden::scanner {

core::ScanReport ScanCoordinator::runScan(const core::ScanOptions &options,
                                          const ScanProgressCallback &progressCallback,
                                          const ScanCancelFlag &cancelFlag)
{
    core::ScanReport report;
    report.options = options;
    report.startedAtUtc = currentTimestampUtc();
    const auto startedAt = std::chrono::steady_clock::now();

    if (report.options.targetPath.empty()) {
        report.options.targetPath = std::filesystem::current_path();
    }
    if (report.options.clamAvDatabasePath.empty()) {
        report.options.clamAvDatabasePath = network::DefinitionUpdater::preferredDatabaseDirectory();
    }

    const std::vector<std::string> activeEngines = activeEnginesForOptions(report.options);
    emitProgress(progressCallback,
                 core::ScanPhase::Preparing,
                 report.options.targetPath.string(),
                 0,
                 0,
                 0,
                 true,
                 activeEngines);

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

    const auto finalizeCancellation = [&](const core::ScanPhase phase,
                                          const std::string &currentItem,
                                          const bool indeterminate) {
        report.canceled = true;
        report.cancelPhase = core::toString(phase);
        appendWarning(report.warnings, "Scan cancelled by operator during " + report.cancelPhase + '.');
        report.stats.warningCount = report.warnings.size();
        emitProgress(progressCallback,
                     phase,
                     currentItem,
                     report.stats.scannedFiles,
                     report.stats.visitedFiles,
                     report.findings.size(),
                     indeterminate,
                     activeEngines);
    };

    if (!report.options.enableClamAv && !report.options.enableHeuristics) {
        appendWarning(report.warnings, "No scan engines are enabled in the current scan options.");
        report.stats.warningCount = report.warnings.size();
        report.completedAtUtc = currentTimestampUtc();
        report.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
        );
        return report;
    }

    if (cancelRequested(cancelFlag)) {
        finalizeCancellation(core::ScanPhase::Preparing, report.options.targetPath.string(), true);
        report.completedAtUtc = currentTimestampUtc();
        report.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
        );
        return report;
    }

    emitProgress(progressCallback,
                 core::ScanPhase::Discovering,
                 report.options.targetPath.string(),
                 0,
                 0,
                 0,
                 false,
                 activeEngines);

    const std::vector<std::filesystem::path> candidateFiles = FileWalker::collectFiles(
        report.options.targetPath,
        report.options.recursive,
        report.options.includeHidden,
        report.stats,
        report.warnings,
        [&](const std::filesystem::path &currentPath, const core::ScanStats &stats) {
            emitProgress(progressCallback,
                         core::ScanPhase::Discovering,
                         currentPath.string(),
                         stats.visitedFiles,
                         0,
                         report.findings.size(),
                         false,
                         activeEngines);
        },
        [&cancelFlag]() {
            return cancelRequested(cancelFlag);
        }
    );

    if (cancelRequested(cancelFlag)) {
        finalizeCancellation(core::ScanPhase::Discovering, report.options.targetPath.string(), false);
        report.completedAtUtc = currentTimestampUtc();
        report.durationMs = static_cast<std::uint64_t>(
            std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
        );
        return report;
    }

    std::unordered_map<std::string, HashResult> hashCache;
    hashCache.reserve(candidateFiles.size());

    const auto keyForPath = [](const std::filesystem::path &path) {
        return path.lexically_normal().generic_string();
    };

    const auto hashForFile = [&](const std::filesystem::path &filePath) -> std::optional<HashResult> {
        const std::string key = keyForPath(filePath);
        const auto iterator = hashCache.find(key);
        if (iterator != hashCache.end()) {
            return iterator->second;
        }

        const HashResult hashResult = m_sha256Hasher.hashFile(filePath);
        if (hashResult.success) {
            report.stats.bytesHashed += hashResult.bytesRead;
        } else {
            appendWarning(report.warnings, hashResult.error);
        }
        hashCache.emplace(key, hashResult);
        return hashResult;
    };

    if (report.options.enableClamAv) {
        if (m_clamAvScanner.initialize(report.options.clamAvDatabasePath)) {
            report.clamAvLoaded = true;
            report.clamAvSignatures = m_clamAvScanner.status().signatures;
            report.clamAvVersion = m_clamAvScanner.status().version;
        } else {
            appendWarning(report.warnings, "ClamAV initialization failed: " + m_clamAvScanner.status().error);
        }

        emitProgress(progressCallback,
                     core::ScanPhase::SignaturePass,
                     report.options.targetPath.string(),
                     0,
                     candidateFiles.size(),
                     report.findings.size(),
                     candidateFiles.empty(),
                     activeEngines);

        std::size_t scannedFiles = 0;
        for (const auto &filePath : candidateFiles) {
            if (cancelRequested(cancelFlag)) {
                finalizeCancellation(core::ScanPhase::SignaturePass, filePath.string(), false);
                report.completedAtUtc = currentTimestampUtc();
                report.durationMs = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
                );
                return report;
            }

            std::error_code fileSizeError;
            const std::uintmax_t fileSize = std::filesystem::file_size(filePath, fileSizeError);
            if (!fileSizeError && fileSize > report.options.maxFileSizeBytes) {
                appendWarning(report.warnings, "Large file exceeds preferred scan size threshold: " + filePath.string());
            }

            const std::optional<HashResult> hashResult = hashForFile(filePath);
            if (!hashResult.has_value() || !hashResult->success) {
                ++scannedFiles;
                emitProgress(progressCallback,
                             core::ScanPhase::SignaturePass,
                             filePath.string(),
                             scannedFiles,
                             candidateFiles.size(),
                             report.findings.size(),
                             false,
                             activeEngines);
                continue;
            }

            if (report.clamAvLoaded) {
                ClamAvScanResult clamAvResult = m_clamAvScanner.scanFile(filePath, hashResult->hexDigest);
                report.stats.bytesScannedByClamAv += clamAvResult.scannedObjects;
                if (!clamAvResult.error.empty()) {
                    appendWarning(report.warnings, clamAvResult.error);
                }
                appendFindings(report.findings, std::move(clamAvResult.findings));
            }

            ++scannedFiles;
            emitProgress(progressCallback,
                         core::ScanPhase::SignaturePass,
                         filePath.string(),
                         scannedFiles,
                         candidateFiles.size(),
                         report.findings.size(),
                         false,
                         activeEngines);
        }
    }

    if (report.options.enableHeuristics) {
        emitProgress(progressCallback,
                     core::ScanPhase::LocalAnalysis,
                     report.options.targetPath.string(),
                     0,
                     candidateFiles.size(),
                     report.findings.size(),
                     candidateFiles.empty(),
                     activeEngines);

        std::size_t scannedFiles = 0;
        for (const auto &filePath : candidateFiles) {
            if (cancelRequested(cancelFlag)) {
                finalizeCancellation(core::ScanPhase::LocalAnalysis, filePath.string(), false);
                report.completedAtUtc = currentTimestampUtc();
                report.durationMs = static_cast<std::uint64_t>(
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
                );
                return report;
            }

            std::error_code fileSizeError;
            const std::uintmax_t fileSize = std::filesystem::file_size(filePath, fileSizeError);
            if (!fileSizeError && fileSize > report.options.maxFileSizeBytes) {
                appendWarning(report.warnings, "Large file exceeds preferred scan size threshold: " + filePath.string());
            }

            const std::optional<HashResult> hashResult = hashForFile(filePath);
            if (!hashResult.has_value() || !hashResult->success) {
                ++scannedFiles;
                report.stats.scannedFiles = scannedFiles;
                emitProgress(progressCallback,
                             core::ScanPhase::LocalAnalysis,
                             filePath.string(),
                             scannedFiles,
                             candidateFiles.size(),
                             report.findings.size(),
                             false,
                             activeEngines);
                continue;
            }

            HeuristicScanResult heuristicResult =
                m_heuristicAnalyzer.analyzeFile(filePath, hashResult->hexDigest, report.options);
            if (!heuristicResult.error.empty()) {
                appendWarning(report.warnings, heuristicResult.error);
            }
            appendFindings(report.findings, std::move(heuristicResult.findings));

            ++scannedFiles;
            report.stats.scannedFiles = scannedFiles;
            emitProgress(progressCallback,
                         core::ScanPhase::LocalAnalysis,
                         filePath.string(),
                         scannedFiles,
                         candidateFiles.size(),
                         report.findings.size(),
                         false,
                         activeEngines);
        }
    } else {
        report.stats.scannedFiles = candidateFiles.size();
    }

    suppressDuplicateFindingsByHash(report.findings);
    report.stats.resultCount = report.findings.size();

    emitProgress(progressCallback,
                 core::ScanPhase::Finalizing,
                 report.options.targetPath.string(),
                 report.stats.scannedFiles,
                 candidateFiles.size(),
                 report.findings.size(),
                 true,
                 activeEngines);

    report.records = core::aggregateThreatFindings(report.findings);
    report.stats.threatsFound = report.records.size();
    report.stats.uniqueFilesFlagged = report.records.size();
    report.stats.warningCount = report.warnings.size();
    report.completedAtUtc = currentTimestampUtc();
    report.durationMs = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - startedAt).count()
    );

    emitProgress(progressCallback,
                 core::ScanPhase::Completed,
                 report.options.targetPath.string(),
                 report.stats.scannedFiles,
                 candidateFiles.size(),
                 report.stats.resultCount,
                 false,
                 activeEngines);
    return report;
}

} // namespace warden::scanner
