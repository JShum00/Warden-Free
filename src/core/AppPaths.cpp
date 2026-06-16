#include "warden/core/AppPaths.h"

#include <QCoreApplication>
#include <QStandardPaths>

#include <system_error>
#include <vector>

namespace {

std::filesystem::path findRootCandidate(const std::filesystem::path &basePath)
{
    std::filesystem::path current = basePath;
    for (int depth = 0; depth < 6 && !current.empty(); ++depth) {
        std::error_code errorCode;
        if (std::filesystem::exists(current / "CMakeLists.txt", errorCode) &&
            std::filesystem::exists(current / "headers", errorCode) &&
            std::filesystem::exists(current / "src", errorCode)) {
            return current;
        }

        current = current.parent_path();
    }

    return {};
}

std::filesystem::path ensureDirectory(const std::filesystem::path &directory)
{
    std::error_code errorCode;
    std::filesystem::create_directories(directory, errorCode);
    if (!errorCode) {
        return directory;
    }

    return {};
}

} // namespace

namespace warden::core {

std::filesystem::path AppPaths::projectRoot()
{
    const std::vector<std::filesystem::path> candidates = {
        std::filesystem::current_path(),
        QCoreApplication::instance() != nullptr
            ? std::filesystem::path(QCoreApplication::applicationDirPath().toStdString())
            : std::filesystem::current_path()
    };

    for (const auto &candidate : candidates) {
        const std::filesystem::path resolved = findRootCandidate(candidate);
        if (!resolved.empty()) {
            return resolved;
        }
    }

    return std::filesystem::current_path();
}

std::filesystem::path AppPaths::appDataDirectory()
{
    const QString appDataLocation = QStandardPaths::writableLocation(QStandardPaths::AppDataLocation);
    if (!appDataLocation.trimmed().isEmpty()) {
        const std::filesystem::path resolved = ensureDirectory(std::filesystem::path(appDataLocation.toStdString()));
        if (!resolved.empty()) {
            return resolved;
        }
    }

    return ensureDirectory(projectRoot() / ".warden-data" / "warden-free");
}

std::filesystem::path AppPaths::stateDatabasePath()
{
    return appDataDirectory() / "warden_state.sqlite";
}

std::filesystem::path AppPaths::quarantineDirectory()
{
    return ensureDirectory(appDataDirectory() / "quarantine");
}

} // namespace warden::core
