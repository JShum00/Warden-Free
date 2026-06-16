#include "warden/storage/StateStore.h"

#include "warden/core/AppPaths.h"

#include <QDateTime>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QSqlDatabase>
#include <QSqlError>
#include <QSqlQuery>
#include <QString>

namespace {

QString toQString(const std::filesystem::path &path)
{
    return QString::fromStdString(path.string());
}

QString toQString(const std::string &value)
{
    return QString::fromStdString(value);
}

std::string normalizedPathString(const std::filesystem::path &path)
{
    return path.lexically_normal().generic_string();
}

std::string nowUtc()
{
    return QDateTime::currentDateTimeUtc().toString(Qt::ISODate).toStdString();
}

QString connectionNameForDatabasePath(const std::filesystem::path &databasePath)
{
    return QStringLiteral("warden_free_state_%1")
        .arg(QString::fromStdString(databasePath.lexically_normal().generic_string()));
}

std::optional<QSqlDatabase> openDatabaseConnection(const std::filesystem::path &databasePath,
                                                   std::string &errorMessage)
{
    const QString connectionName = connectionNameForDatabasePath(databasePath);
    QSqlDatabase database = QSqlDatabase::contains(connectionName)
        ? QSqlDatabase::database(connectionName)
        : QSqlDatabase::addDatabase(QStringLiteral("QSQLITE"), connectionName);
    database.setDatabaseName(toQString(databasePath));

    if (!database.isOpen() && !database.open()) {
        errorMessage = database.lastError().text().toStdString();
        return std::nullopt;
    }

    return database;
}

bool executeStatement(QSqlDatabase &database, const QString &statement, std::string &errorMessage)
{
    QSqlQuery query(database);
    if (!query.exec(statement)) {
        errorMessage = query.lastError().text().toStdString();
        return false;
    }

    return true;
}

std::string summarizeActions(const QString &existingSummary,
                             const QString &action,
                             const QString &details)
{
    QStringList items;
    if (!existingSummary.trimmed().isEmpty()) {
        items = existingSummary.split(QStringLiteral(" | "), Qt::SkipEmptyParts);
    }

    QString nextItem = action;
    if (!details.trimmed().isEmpty()) {
        nextItem += QStringLiteral(": ") + details;
    }
    items << nextItem;
    return items.join(QStringLiteral(" | ")).toStdString();
}

} // namespace

namespace warden::storage {

StateStore::StateStore(std::filesystem::path databasePath)
    : m_databasePath(databasePath.empty() ? core::AppPaths::stateDatabasePath() : std::move(databasePath))
{
}

bool StateStore::ensureDataDirectory(std::string &errorMessage) const
{
    std::error_code errorCode;
    std::filesystem::create_directories(m_databasePath.parent_path(), errorCode);
    if (errorCode) {
        errorMessage = errorCode.message();
        return false;
    }

    return true;
}

bool StateStore::initialize(std::string &errorMessage) const
{
    if (!ensureDataDirectory(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    const QStringList statements = {
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS scan_history ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "scan_kind TEXT NOT NULL,"
            "profile TEXT NOT NULL,"
            "started_at_utc TEXT,"
            "completed_at_utc TEXT,"
            "duration_ms INTEGER,"
            "item_count INTEGER,"
            "threat_count INTEGER,"
            "warning_count INTEGER,"
            "actions_summary TEXT,"
            "summary_text TEXT,"
            "findings_json TEXT,"
            "warnings_json TEXT)"
        ),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS scan_actions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "scan_history_id INTEGER,"
            "finding_id TEXT,"
            "action TEXT NOT NULL,"
            "details TEXT,"
            "created_at_utc TEXT NOT NULL)"
        ),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS exclusions ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "match_type TEXT NOT NULL,"
            "match_value TEXT NOT NULL UNIQUE,"
            "label TEXT,"
            "created_at_utc TEXT NOT NULL)"
        ),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS quarantine_catalog ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "finding_id TEXT,"
            "original_path TEXT,"
            "quarantined_path TEXT NOT NULL UNIQUE,"
            "metadata_path TEXT,"
            "sha256 TEXT,"
            "threat_name TEXT,"
            "status TEXT,"
            "created_at_utc TEXT NOT NULL,"
            "restored_at_utc TEXT,"
            "restored_path TEXT)"
        ),
        QStringLiteral(
            "CREATE TABLE IF NOT EXISTS status_snapshots ("
            "snapshot_key TEXT PRIMARY KEY,"
            "snapshot_value TEXT,"
            "updated_at_utc TEXT NOT NULL)"
        )
    };

    for (const auto &statement : statements) {
        if (!executeStatement(*connection, statement, errorMessage)) {
            return false;
        }
    }

    return true;
}

std::int64_t StateStore::recordScan(const ScanHistoryEntry &entry, std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return 0;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return 0;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "INSERT INTO scan_history ("
            "scan_kind, profile, started_at_utc, completed_at_utc, duration_ms, item_count, threat_count, warning_count,"
            "actions_summary, summary_text, findings_json, warnings_json"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
    );
    query.addBindValue(toQString(entry.scanKind));
    query.addBindValue(toQString(entry.profile));
    query.addBindValue(toQString(entry.startedAtUtc));
    query.addBindValue(toQString(entry.completedAtUtc));
    query.addBindValue(static_cast<qint64>(entry.durationMs));
    query.addBindValue(static_cast<qint64>(entry.itemCount));
    query.addBindValue(static_cast<qint64>(entry.threatCount));
    query.addBindValue(static_cast<qint64>(entry.warningCount));
    query.addBindValue(toQString(entry.actionsSummary));
    query.addBindValue(toQString(entry.summaryText));
    query.addBindValue(toQString(entry.findingsJson));
    query.addBindValue(toQString(entry.warningsJson));

    if (!query.exec()) {
        errorMessage = query.lastError().text().toStdString();
        return 0;
    }

    return query.lastInsertId().toLongLong();
}

std::vector<ScanHistoryEntry> StateStore::listScanHistory(const std::size_t limit) const
{
    std::string errorMessage;
    if (!initialize(errorMessage)) {
        return {};
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return {};
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "SELECT id, scan_kind, profile, started_at_utc, completed_at_utc, duration_ms, item_count, threat_count, "
            "warning_count, actions_summary, summary_text, findings_json, warnings_json "
            "FROM scan_history ORDER BY id DESC LIMIT ?"
        )
    );
    query.addBindValue(static_cast<qint64>(limit));
    if (!query.exec()) {
        return {};
    }

    std::vector<ScanHistoryEntry> entries;
    while (query.next()) {
        ScanHistoryEntry entry;
        entry.id = query.value(0).toLongLong();
        entry.scanKind = query.value(1).toString().toStdString();
        entry.profile = query.value(2).toString().toStdString();
        entry.startedAtUtc = query.value(3).toString().toStdString();
        entry.completedAtUtc = query.value(4).toString().toStdString();
        entry.durationMs = query.value(5).toULongLong();
        entry.itemCount = query.value(6).toULongLong();
        entry.threatCount = query.value(7).toULongLong();
        entry.warningCount = query.value(8).toULongLong();
        entry.actionsSummary = query.value(9).toString().toStdString();
        entry.summaryText = query.value(10).toString().toStdString();
        entry.findingsJson = query.value(11).toString().toStdString();
        entry.warningsJson = query.value(12).toString().toStdString();
        entries.push_back(std::move(entry));
    }

    return entries;
}

bool StateStore::recordScanAction(const std::int64_t scanHistoryId,
                                  const std::string &findingId,
                                  const std::string &action,
                                  const std::string &details,
                                  std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    if (!connection->transaction()) {
        errorMessage = connection->lastError().text().toStdString();
        return false;
    }

    QSqlQuery insertAction(*connection);
    insertAction.prepare(
        QStringLiteral(
            "INSERT INTO scan_actions (scan_history_id, finding_id, action, details, created_at_utc) VALUES (?, ?, ?, ?, ?)"
        )
    );
    insertAction.addBindValue(scanHistoryId == 0 ? QVariant() : QVariant::fromValue(scanHistoryId));
    insertAction.addBindValue(toQString(findingId));
    insertAction.addBindValue(toQString(action));
    insertAction.addBindValue(toQString(details));
    insertAction.addBindValue(toQString(nowUtc()));

    if (!insertAction.exec()) {
        connection->rollback();
        errorMessage = insertAction.lastError().text().toStdString();
        return false;
    }

    if (scanHistoryId != 0) {
        QSqlQuery loadSummary(*connection);
        loadSummary.prepare(QStringLiteral("SELECT actions_summary FROM scan_history WHERE id = ?"));
        loadSummary.addBindValue(static_cast<qlonglong>(scanHistoryId));
        QString existingSummary;
        if (loadSummary.exec() && loadSummary.next()) {
            existingSummary = loadSummary.value(0).toString();
        }

        QSqlQuery updateSummary(*connection);
        updateSummary.prepare(QStringLiteral("UPDATE scan_history SET actions_summary = ? WHERE id = ?"));
        updateSummary.addBindValue(toQString(summarizeActions(existingSummary, toQString(action), toQString(details))));
        updateSummary.addBindValue(static_cast<qlonglong>(scanHistoryId));
        if (!updateSummary.exec()) {
            connection->rollback();
            errorMessage = updateSummary.lastError().text().toStdString();
            return false;
        }
    }

    if (!connection->commit()) {
        errorMessage = connection->lastError().text().toStdString();
        return false;
    }

    return true;
}

bool StateStore::addExclusion(const ExclusionEntry &entry, std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral("INSERT OR IGNORE INTO exclusions (match_type, match_value, label, created_at_utc) VALUES (?, ?, ?, ?)")
    );
    query.addBindValue(toQString(entry.matchType));
    query.addBindValue(toQString(entry.matchValue));
    query.addBindValue(toQString(entry.label));
    query.addBindValue(toQString(entry.createdAtUtc.empty() ? nowUtc() : entry.createdAtUtc));
    if (!query.exec()) {
        errorMessage = query.lastError().text().toStdString();
        return false;
    }

    return true;
}

bool StateStore::removeExclusion(const std::int64_t exclusionId, std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    QSqlQuery query(*connection);
    query.prepare(QStringLiteral("DELETE FROM exclusions WHERE id = ?"));
    query.addBindValue(static_cast<qlonglong>(exclusionId));
    if (!query.exec()) {
        errorMessage = query.lastError().text().toStdString();
        return false;
    }

    return true;
}

std::vector<ExclusionEntry> StateStore::listExclusions() const
{
    std::string errorMessage;
    if (!initialize(errorMessage)) {
        return {};
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return {};
    }

    QSqlQuery query(*connection);
    if (!query.exec(QStringLiteral("SELECT id, match_type, match_value, label, created_at_utc FROM exclusions ORDER BY id DESC"))) {
        return {};
    }

    std::vector<ExclusionEntry> entries;
    while (query.next()) {
        ExclusionEntry entry;
        entry.id = query.value(0).toLongLong();
        entry.matchType = query.value(1).toString().toStdString();
        entry.matchValue = query.value(2).toString().toStdString();
        entry.label = query.value(3).toString().toStdString();
        entry.createdAtUtc = query.value(4).toString().toStdString();
        entries.push_back(std::move(entry));
    }

    return entries;
}

bool StateStore::isExcluded(const core::ThreatFinding &finding) const
{
    std::string errorMessage;
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "SELECT COUNT(*) FROM exclusions WHERE "
            "(match_type = 'sha256' AND match_value = ?) "
            "OR (match_type = 'path' AND match_value = ?) "
            "OR (match_type = 'path_prefix' AND ? LIKE match_value || '%')"
        )
    );
    query.addBindValue(toQString(finding.sha256));
    query.addBindValue(toQString(finding.path));
    query.addBindValue(toQString(normalizedPathString(finding.path)));
    if (!query.exec() || !query.next()) {
        return false;
    }

    return query.value(0).toLongLong() > 0;
}

std::vector<core::ThreatFinding> StateStore::filterExcludedFindings(const std::vector<core::ThreatFinding> &findings) const
{
    std::vector<core::ThreatFinding> filtered;
    filtered.reserve(findings.size());
    for (const auto &finding : findings) {
        if (!isExcluded(finding)) {
            filtered.push_back(finding);
        }
    }
    return filtered;
}

bool StateStore::recordQuarantineEntry(const QuarantineCatalogEntry &entry, std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "INSERT OR REPLACE INTO quarantine_catalog ("
            "finding_id, original_path, quarantined_path, metadata_path, sha256, threat_name, status, created_at_utc, "
            "restored_at_utc, restored_path"
            ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
        )
    );
    query.addBindValue(toQString(entry.findingId));
    query.addBindValue(toQString(entry.originalPath));
    query.addBindValue(toQString(entry.quarantinedPath));
    query.addBindValue(toQString(entry.metadataPath));
    query.addBindValue(toQString(entry.sha256));
    query.addBindValue(toQString(entry.threatName));
    query.addBindValue(toQString(entry.status));
    query.addBindValue(toQString(entry.createdAtUtc.empty() ? nowUtc() : entry.createdAtUtc));
    query.addBindValue(toQString(entry.restoredAtUtc));
    query.addBindValue(toQString(entry.restoredPath));
    if (!query.exec()) {
        errorMessage = query.lastError().text().toStdString();
        return false;
    }

    return true;
}

std::vector<QuarantineCatalogEntry> StateStore::listQuarantineEntries() const
{
    std::string errorMessage;
    if (!initialize(errorMessage)) {
        return {};
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return {};
    }

    QSqlQuery query(*connection);
    if (!query.exec(
            QStringLiteral(
                "SELECT id, finding_id, original_path, quarantined_path, metadata_path, sha256, threat_name, status, "
                "created_at_utc, restored_at_utc, restored_path FROM quarantine_catalog ORDER BY id DESC"
            ))) {
        return {};
    }

    std::vector<QuarantineCatalogEntry> entries;
    while (query.next()) {
        QuarantineCatalogEntry entry;
        entry.id = query.value(0).toLongLong();
        entry.findingId = query.value(1).toString().toStdString();
        entry.originalPath = std::filesystem::path(query.value(2).toString().toStdString());
        entry.quarantinedPath = std::filesystem::path(query.value(3).toString().toStdString());
        entry.metadataPath = std::filesystem::path(query.value(4).toString().toStdString());
        entry.sha256 = query.value(5).toString().toStdString();
        entry.threatName = query.value(6).toString().toStdString();
        entry.status = query.value(7).toString().toStdString();
        entry.createdAtUtc = query.value(8).toString().toStdString();
        entry.restoredAtUtc = query.value(9).toString().toStdString();
        entry.restoredPath = std::filesystem::path(query.value(10).toString().toStdString());
        entries.push_back(std::move(entry));
    }

    return entries;
}

std::optional<QuarantineCatalogEntry> StateStore::findQuarantineEntry(const std::filesystem::path &quarantinedPath) const
{
    std::string errorMessage;
    if (!initialize(errorMessage)) {
        return std::nullopt;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return std::nullopt;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "SELECT id, finding_id, original_path, quarantined_path, metadata_path, sha256, threat_name, status, "
            "created_at_utc, restored_at_utc, restored_path FROM quarantine_catalog WHERE quarantined_path = ?"
        )
    );
    query.addBindValue(toQString(quarantinedPath));
    if (!query.exec() || !query.next()) {
        return std::nullopt;
    }

    QuarantineCatalogEntry entry;
    entry.id = query.value(0).toLongLong();
    entry.findingId = query.value(1).toString().toStdString();
    entry.originalPath = std::filesystem::path(query.value(2).toString().toStdString());
    entry.quarantinedPath = std::filesystem::path(query.value(3).toString().toStdString());
    entry.metadataPath = std::filesystem::path(query.value(4).toString().toStdString());
    entry.sha256 = query.value(5).toString().toStdString();
    entry.threatName = query.value(6).toString().toStdString();
    entry.status = query.value(7).toString().toStdString();
    entry.createdAtUtc = query.value(8).toString().toStdString();
    entry.restoredAtUtc = query.value(9).toString().toStdString();
    entry.restoredPath = std::filesystem::path(query.value(10).toString().toStdString());
    return entry;
}

bool StateStore::markQuarantineRestored(const std::filesystem::path &quarantinedPath,
                                        const std::filesystem::path &restoredPath,
                                        std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "UPDATE quarantine_catalog SET status = 'restored', restored_at_utc = ?, restored_path = ? WHERE quarantined_path = ?"
        )
    );
    query.addBindValue(toQString(nowUtc()));
    query.addBindValue(toQString(restoredPath));
    query.addBindValue(toQString(quarantinedPath));
    if (!query.exec()) {
        errorMessage = query.lastError().text().toStdString();
        return false;
    }

    return true;
}

bool StateStore::setStatusSnapshot(const std::string &key,
                                   const std::string &value,
                                   std::string &errorMessage) const
{
    if (!initialize(errorMessage)) {
        return false;
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return false;
    }

    QSqlQuery query(*connection);
    query.prepare(
        QStringLiteral(
            "INSERT OR REPLACE INTO status_snapshots (snapshot_key, snapshot_value, updated_at_utc) VALUES (?, ?, ?)"
        )
    );
    query.addBindValue(toQString(key));
    query.addBindValue(toQString(value));
    query.addBindValue(toQString(nowUtc()));
    if (!query.exec()) {
        errorMessage = query.lastError().text().toStdString();
        return false;
    }

    return true;
}

std::string StateStore::statusSnapshotValue(const std::string &key) const
{
    std::string errorMessage;
    if (!initialize(errorMessage)) {
        return {};
    }

    auto connection = openDatabaseConnection(m_databasePath, errorMessage);
    if (!connection.has_value()) {
        return {};
    }

    QSqlQuery query(*connection);
    query.prepare(QStringLiteral("SELECT snapshot_value FROM status_snapshots WHERE snapshot_key = ?"));
    query.addBindValue(toQString(key));
    if (!query.exec() || !query.next()) {
        return {};
    }

    return query.value(0).toString().toStdString();
}

const std::filesystem::path &StateStore::databasePath() const
{
    return m_databasePath;
}

} // namespace warden::storage
