#include "warden/network/DefinitionUpdater.h"

#include "warden/scanner/ClamAvScanner.h"

#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QProcess>
#include <QRegularExpression>
#include <QStandardPaths>
#include <QTemporaryDir>
#include <QTextStream>

#ifdef WARDEN_HAS_FRESHCLAM
extern "C" {
#include <libfreshclam.h>
}
#endif

#include <filesystem>
#include <set>

namespace {

std::filesystem::path fallbackGenericDataLocation()
{
    return std::filesystem::path(QDir::homePath().toStdString()) / ".local" / "share";
}

std::filesystem::path genericDataLocation()
{
    const QString location = QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation);
    if (!location.trimmed().isEmpty()) {
        return std::filesystem::path(location.toStdString());
    }

    return fallbackGenericDataLocation();
}

bool directoryHasDatabaseFiles(const std::filesystem::path &databaseDirectory)
{
    const std::vector<std::string> databases = {"main", "daily", "bytecode"};

    for (const auto &database : databases) {
        std::error_code errorCode;
        if (std::filesystem::exists(databaseDirectory / (database + ".cld"), errorCode) ||
            std::filesystem::exists(databaseDirectory / (database + ".cvd"), errorCode)) {
            return true;
        }
    }

    return false;
}

bool ensureWritableDirectory(const std::filesystem::path &databaseDirectory, std::string &errorMessage)
{
    std::error_code errorCode;
    std::filesystem::create_directories(databaseDirectory, errorCode);
    if (errorCode) {
        errorMessage = "Unable to create database directory " + databaseDirectory.string() + ": " + errorCode.message();
        return false;
    }

    const std::filesystem::path probePath = databaseDirectory / ".warden-write-test";
    QFile probe(QString::fromStdString(probePath.string()));
    if (!probe.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        errorMessage = "Database directory is not writable: " + databaseDirectory.string();
        return false;
    }

    probe.write("ok");
    probe.close();
    std::filesystem::remove(probePath, errorCode);
    return true;
}

std::filesystem::path resolveUpdateDirectory(const std::filesystem::path &requestedDirectory)
{
    if (!requestedDirectory.empty()) {
        return requestedDirectory;
    }

    const std::filesystem::path managedDirectory = warden::network::DefinitionUpdater::managedDatabaseDirectory();
    if (directoryHasDatabaseFiles(managedDirectory)) {
        return managedDirectory;
    }

    const std::filesystem::path systemDirectory = warden::scanner::ClamAvScanner::defaultDatabasePath();
    std::string errorMessage;
    if (!systemDirectory.empty() && ensureWritableDirectory(systemDirectory, errorMessage)) {
        return systemDirectory;
    }

    return managedDirectory;
}

void appendTail(std::string &message, const QString &commandOutput)
{
    const QString trimmed = commandOutput.trimmed();
    if (trimmed.isEmpty()) {
        return;
    }

    const QStringList lines = trimmed.split('\n', Qt::SkipEmptyParts);
    const qsizetype startIndex = std::max<qsizetype>(0, lines.size() - 6);
    const QString tail = lines.mid(startIndex).join(QStringLiteral(" | "));
    message += ": " + tail.toStdString();
}

void populateUpdatedDatabasesFromOutput(const QString &commandOutput,
                                        warden::network::DefinitionUpdateResult &result)
{
    const QRegularExpression expression(QStringLiteral("\\b(main|daily|bytecode)\\.(?:cvd|cld) updated\\b"),
                                        QRegularExpression::CaseInsensitiveOption);
    QRegularExpressionMatchIterator iterator = expression.globalMatch(commandOutput);
    std::set<std::string> databases;

    while (iterator.hasNext()) {
        const auto match = iterator.next();
        databases.insert(match.captured(1).toLower().toStdString());
    }

    result.updatedDatabases.assign(databases.begin(), databases.end());
    result.updatedCount = static_cast<unsigned int>(result.updatedDatabases.size());
}

bool runFreshclamCli(const std::filesystem::path &databaseDirectory,
                     warden::network::DefinitionUpdateResult &result)
{
    const QString freshclamExecutable = QStandardPaths::findExecutable(QStringLiteral("freshclam"));
    if (freshclamExecutable.isEmpty()) {
        result.error = "freshclam executable was not found on PATH.";
        return false;
    }

    QTemporaryDir tempDirectory;
    if (!tempDirectory.isValid()) {
        result.error = "Unable to create a temporary directory for the freshclam configuration.";
        return false;
    }

    const QString configPath = tempDirectory.filePath(QStringLiteral("freshclam.conf"));
    QFile configFile(configPath);
    if (!configFile.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        result.error = "Unable to write a temporary freshclam configuration file.";
        return false;
    }

    QTextStream stream(&configFile);
    stream << "DatabaseDirectory " << QString::fromStdString(databaseDirectory.string()) << '\n';
    stream << "Foreground true\n";
    stream << "Checks 1\n";
    stream << "DNSDatabaseInfo current.cvd.clamav.net\n";
    stream << "DatabaseMirror db.local.clamav.net\n";
    stream << "DatabaseMirror database.clamav.net\n";
    stream << "MaxAttempts 5\n";
    stream << "ConnectTimeout 30\n";
    stream << "ReceiveTimeout 0\n";
    stream << "TestDatabases yes\n";
    stream << "ScriptedUpdates yes\n";
    stream << "CompressLocalDatabase no\n";
    stream << "Bytecode yes\n";
    configFile.close();

    QProcess process;
    process.setProgram(freshclamExecutable);
    process.setArguments({
        QStringLiteral("--stdout"),
        QStringLiteral("--config-file=%1").arg(configPath),
        QStringLiteral("--datadir=%1").arg(QString::fromStdString(databaseDirectory.string()))
    });
    process.start();
    if (!process.waitForStarted(5000)) {
        result.error = "Failed to start freshclam.";
        appendTail(result.error, process.errorString());
        return false;
    }

    if (!process.waitForFinished(10 * 60 * 1000)) {
        process.kill();
        process.waitForFinished();
        result.error = "freshclam timed out while updating definitions.";
        appendTail(result.error, QString::fromUtf8(process.readAllStandardOutput() + process.readAllStandardError()));
        return false;
    }

    const QString combinedOutput =
        QString::fromUtf8(process.readAllStandardOutput()) + "\n" + QString::fromUtf8(process.readAllStandardError());

    if (process.exitStatus() != QProcess::NormalExit || process.exitCode() != 0) {
        result.error = "freshclam failed";
        if (process.exitStatus() == QProcess::NormalExit) {
            result.error += " (exit code " + std::to_string(process.exitCode()) + ")";
        }
        appendTail(result.error, combinedOutput);
        return false;
    }

    result.success = true;
    populateUpdatedDatabasesFromOutput(combinedOutput, result);
    return true;
}

#ifdef WARDEN_HAS_FRESHCLAM
bool runLibfreshclamFallback(const std::filesystem::path &databaseDirectory,
                             warden::network::DefinitionUpdateResult &result)
{
    const std::string databaseDirectoryString = databaseDirectory.string();
    const std::string tempDirectoryString = std::filesystem::temp_directory_path().string();
    const std::string userAgent = "Warden Free";

    fc_config config {};
    config.msgFlags = FC_CONFIG_MSG_QUIET | FC_CONFIG_MSG_STDOUT;
    config.maxAttempts = 5;
    config.connectTimeout = 30;
    config.requestTimeout = 60;
    config.databaseDirectory = databaseDirectoryString.c_str();
    config.tempDirectory = tempDirectoryString.c_str();
    config.userAgent = userAgent.c_str();

    const fc_error_t initializeResult = fc_initialize(&config);
    if (initializeResult != FC_SUCCESS) {
        result.error = std::string("fc_initialize failed: ") + fc_strerror(initializeResult);
        return false;
    }

    char *databaseList[] = {
        const_cast<char *>("main"),
        const_cast<char *>("daily"),
        const_cast<char *>("bytecode")
    };
    char *serverList[] = {
        const_cast<char *>("db.local.clamav.net"),
        const_cast<char *>("database.clamav.net")
    };

    uint32_t updatedCount = 0;
    const fc_error_t updateResult = fc_update_databases(
        databaseList,
        3,
        serverList,
        2,
        0,
        "current.cvd.clamav.net",
        1,
        nullptr,
        &updatedCount
    );

    fc_cleanup();

    if (updateResult != FC_SUCCESS && updateResult != FC_UPTODATE) {
        result.error = std::string("fc_update_databases failed: ") + fc_strerror(updateResult);
        return false;
    }

    result.success = true;
    result.updatedCount = updatedCount;
    if (updatedCount > 0) {
        result.updatedDatabases = {"main", "daily", "bytecode"};
    }
    return true;
}
#endif

} // namespace

namespace warden::network {

DefinitionUpdateResult DefinitionUpdater::updateClamAvDefinitions(const std::filesystem::path &databaseDirectory) const
{
    DefinitionUpdateResult result;
    result.supported = true;
    result.databaseDirectory = resolveUpdateDirectory(databaseDirectory);

    std::string errorMessage;
    if (!ensureWritableDirectory(result.databaseDirectory, errorMessage)) {
        result.error = errorMessage;
        return result;
    }

    if (runFreshclamCli(result.databaseDirectory, result)) {
        return result;
    }

#ifndef WARDEN_HAS_FRESHCLAM
    result.error = "freshclam executable update failed, and libfreshclam fallback is not available. " + result.error;
    return result;
#else
    const std::string cliError = result.error;
    result.error.clear();
    if (runLibfreshclamFallback(result.databaseDirectory, result)) {
        return result;
    }

    result.error = "freshclam CLI failed (" + cliError + "); libfreshclam fallback failed (" + result.error + ")";
    return result;
#endif
}

std::filesystem::path DefinitionUpdater::managedDatabaseDirectory()
{
    const std::vector<std::filesystem::path> candidates = {
        genericDataLocation() / "Warden" / "warden-free" / "clamav-db",
        std::filesystem::current_path() / ".warden-data" / "clamav-db"
    };

    for (const auto &candidate : candidates) {
        std::string errorMessage;
        if (ensureWritableDirectory(candidate, errorMessage) || directoryHasDatabaseFiles(candidate)) {
            return candidate;
        }
    }

    return candidates.back();
}

std::filesystem::path DefinitionUpdater::preferredDatabaseDirectory()
{
    const std::filesystem::path managedDirectory = managedDatabaseDirectory();
    if (directoryHasDatabaseFiles(managedDirectory)) {
        return managedDirectory;
    }

    const std::filesystem::path systemDirectory = scanner::ClamAvScanner::defaultDatabasePath();
    if (!systemDirectory.empty() && directoryHasDatabaseFiles(systemDirectory)) {
        return systemDirectory;
    }

    std::string errorMessage;
    if (!systemDirectory.empty() && ensureWritableDirectory(systemDirectory, errorMessage)) {
        return systemDirectory;
    }

    return managedDirectory;
}

} // namespace warden::network
