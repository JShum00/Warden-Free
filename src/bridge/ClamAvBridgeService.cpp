#include "warden/bridge/ClamAvBridgeService.h"

#include "warden/bridge/ClamAvBridgeProtocol.h"
#include "warden/network/DefinitionUpdater.h"
#include "warden/scanner/ClamAvOnlyCoordinator.h"
#include "warden/scanner/ClamAvScanner.h"

#include <QJsonArray>

namespace {

QJsonObject makeResponse(const bool ok, const QString &error = {}, const QJsonObject &payload = {})
{
    QJsonObject response;
    response.insert(QStringLiteral("protocol_version"), warden::bridge::kProtocolVersion);
    response.insert(QStringLiteral("ok"), ok);
    response.insert(QStringLiteral("error"), error);
    response.insert(QStringLiteral("payload"), payload);
    return response;
}

QJsonArray toJsonArray(const std::vector<std::string> &values)
{
    QJsonArray array;
    for (const auto &value : values) {
        array.append(QString::fromStdString(value));
    }
    return array;
}

QJsonObject findingToJson(const warden::core::ThreatFinding &finding)
{
    QJsonObject object;
    object.insert(QStringLiteral("name"), QString::fromStdString(finding.name));
    object.insert(QStringLiteral("path"), QString::fromStdString(finding.path.string()));
    object.insert(QStringLiteral("severity"), QString::fromStdString(warden::core::toString(finding.severity)));
    object.insert(QStringLiteral("source"), QString::fromStdString(finding.source));
    object.insert(QStringLiteral("recommended_action"), QString::fromStdString(finding.recommendedAction));
    object.insert(QStringLiteral("sha256"), QString::fromStdString(finding.sha256));
    object.insert(QStringLiteral("threat_type"), QString::fromStdString(warden::core::toString(finding.threatType)));
    object.insert(QStringLiteral("description"), QString::fromStdString(finding.description));
    object.insert(QStringLiteral("file_size"), static_cast<qint64>(finding.fileSize));
    object.insert(QStringLiteral("entropy"), finding.entropy);
    object.insert(QStringLiteral("evidence"), toJsonArray(finding.evidence));
    return object;
}

QJsonObject reportToJson(const warden::core::ScanReport &report)
{
    QJsonArray findings;
    for (const auto &finding : report.findings) {
        findings.append(findingToJson(finding));
    }

    QJsonObject databaseStatus;
    databaseStatus.insert(QStringLiteral("loaded"), report.clamAvLoaded);
    databaseStatus.insert(QStringLiteral("signatures"), static_cast<int>(report.clamAvSignatures));
    databaseStatus.insert(QStringLiteral("version"), QString::fromStdString(report.clamAvVersion));
    databaseStatus.insert(QStringLiteral("database_path"), QString::fromStdString(report.options.clamAvDatabasePath.string()));

    QJsonObject payload;
    payload.insert(QStringLiteral("database_status"), databaseStatus);
    payload.insert(QStringLiteral("visited_directories"), static_cast<qint64>(report.stats.visitedDirectories));
    payload.insert(QStringLiteral("visited_files"), static_cast<qint64>(report.stats.visitedFiles));
    payload.insert(QStringLiteral("files_scanned"), static_cast<qint64>(report.stats.scannedFiles));
    payload.insert(QStringLiteral("threats_found"), static_cast<qint64>(report.stats.threatsFound));
    payload.insert(QStringLiteral("warnings"), toJsonArray(report.warnings));
    payload.insert(QStringLiteral("findings"), findings);
    payload.insert(QStringLiteral("bytes_hashed"), static_cast<qint64>(report.stats.bytesHashed));
    payload.insert(QStringLiteral("bytes_scanned_by_clamav"), static_cast<qint64>(report.stats.bytesScannedByClamAv));
    return payload;
}

QJsonObject definitionResultToJson(const warden::network::DefinitionUpdateResult &result)
{
    QJsonObject payload;
    payload.insert(QStringLiteral("supported"), result.supported);
    payload.insert(QStringLiteral("success"), result.success);
    payload.insert(QStringLiteral("updated_count"), static_cast<int>(result.updatedCount));
    payload.insert(QStringLiteral("database_directory"), QString::fromStdString(result.databaseDirectory.string()));
    payload.insert(QStringLiteral("updated_databases"), toJsonArray(result.updatedDatabases));
    payload.insert(QStringLiteral("error"), QString::fromStdString(result.error));
    return payload;
}

std::filesystem::path requestedDatabasePathFromPayload(const QJsonObject &payload)
{
    return std::filesystem::path(payload.value(QStringLiteral("database_directory")).toString().toStdString());
}

warden::core::ScanOptions scanOptionsFromPayload(const QJsonObject &payload)
{
    warden::core::ScanOptions options;
    options.targetPath = std::filesystem::path(payload.value(QStringLiteral("target_path")).toString().toStdString());
    options.clamAvDatabasePath = requestedDatabasePathFromPayload(payload);
    if (options.clamAvDatabasePath.empty()) {
        options.clamAvDatabasePath = warden::network::DefinitionUpdater::preferredDatabaseDirectory();
    }
    options.quarantineDirectory = std::filesystem::path(payload.value(QStringLiteral("quarantine_directory")).toString().toStdString());
    options.recursive = payload.value(QStringLiteral("recursive")).toBool(true);
    options.includeHidden = payload.value(QStringLiteral("include_hidden")).toBool(false);
    options.maxFileSizeBytes = static_cast<std::uintmax_t>(
        payload.value(QStringLiteral("max_file_size_bytes")).toVariant().toULongLong()
    );
    options.enableClamAv = true;
    return options;
}

} // namespace

namespace warden::bridge {

QJsonObject ClamAvBridgeService::handleRequest(const QJsonObject &request) const
{
    if (request.value(QStringLiteral("protocol_version")).toInt() != kProtocolVersion) {
        return makeResponse(false, QStringLiteral("Unsupported protocol_version."));
    }

    const QString command = request.value(QStringLiteral("command")).toString();
    const QJsonObject payload = request.value(QStringLiteral("payload")).toObject();

    if (command == kCommandPing) {
        return makeResponse(true, {}, QJsonObject {{QStringLiteral("message"), QStringLiteral("pong")}});
    }

    if (command == kCommandEngineStatus) {
        scanner::ClamAvScanner scanner;
        std::filesystem::path databasePath = requestedDatabasePathFromPayload(payload);
        if (databasePath.empty()) {
            databasePath = warden::network::DefinitionUpdater::preferredDatabaseDirectory();
        }
        const bool initialized = scanner.initialize(databasePath);

        QJsonObject statusPayload;
        statusPayload.insert(QStringLiteral("available"), scanner.status().available);
        statusPayload.insert(QStringLiteral("initialized"), scanner.status().initialized);
        statusPayload.insert(QStringLiteral("signatures"), static_cast<int>(scanner.status().signatures));
        statusPayload.insert(QStringLiteral("version"), QString::fromStdString(scanner.status().version));
        statusPayload.insert(QStringLiteral("database_path"), QString::fromStdString(scanner.status().databasePath));
        statusPayload.insert(QStringLiteral("error"), QString::fromStdString(scanner.status().error));
        return makeResponse(initialized, initialized ? QString() : QString::fromStdString(scanner.status().error), statusPayload);
    }

    if (command == kCommandScanPath) {
        warden::core::ScanOptions options = scanOptionsFromPayload(payload);
        if (options.maxFileSizeBytes == 0) {
            options.maxFileSizeBytes = 256ULL * 1024ULL * 1024ULL;
        }

        scanner::ClamAvOnlyCoordinator coordinator;
        const warden::core::ScanReport report = coordinator.runScan(options);
        const bool ok = report.clamAvLoaded || !report.warnings.empty();
        return makeResponse(ok, report.clamAvLoaded ? QString() : QStringLiteral("ClamAV scan completed without a loaded database."), reportToJson(report));
    }

    if (command == kCommandUpdateDefinitions) {
        network::DefinitionUpdater updater;
        const network::DefinitionUpdateResult result = updater.updateClamAvDefinitions(requestedDatabasePathFromPayload(payload));
        return makeResponse(result.success, QString::fromStdString(result.error), definitionResultToJson(result));
    }

    return makeResponse(false, QStringLiteral("Unsupported command."));
}

} // namespace warden::bridge
