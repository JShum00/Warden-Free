#include "warden/scanner/FileWalker.h"

#include <sstream>
#include <type_traits>

namespace {

void appendWarning(std::vector<std::string> &warnings, const std::string &message)
{
    warnings.push_back(message);
}

} // namespace

namespace warden::scanner {

bool FileWalker::isHidden(const std::filesystem::path &path)
{
    const std::string filename = path.filename().string();
    return !filename.empty() && filename != "." && filename != ".." && filename.front() == '.';
}

void FileWalker::walk(const std::filesystem::path &rootPath,
                      const bool recursive,
                      const bool includeHidden,
                      core::ScanStats &stats,
                      std::vector<std::string> &warnings,
                      const FileCallback &callback,
                      const CancellationCallback &cancellationCallback)
{
    if (rootPath.empty()) {
        appendWarning(warnings, "File walker received an empty scan root.");
        return;
    }

    std::error_code errorCode;
    if (!std::filesystem::exists(rootPath, errorCode)) {
        appendWarning(warnings, "Scan root does not exist: " + rootPath.string());
        return;
    }

    if (std::filesystem::is_regular_file(rootPath, errorCode)) {
        if (!includeHidden && isHidden(rootPath)) {
            return;
        }

        ++stats.visitedFiles;
        callback(std::filesystem::directory_entry(rootPath));
        return;
    }

    if (!std::filesystem::is_directory(rootPath, errorCode)) {
        appendWarning(warnings, "Scan root is neither a file nor a directory: " + rootPath.string());
        return;
    }

    ++stats.visitedDirectories;

    const auto iterateDirectory = [&](auto &iterator, const auto &endSentinel) {
        for (; iterator != endSentinel; iterator.increment(errorCode)) {
            if (cancellationCallback && cancellationCallback()) {
                return;
            }

            if (errorCode) {
                appendWarning(warnings, "Directory iteration error under " + rootPath.string() + ": " + errorCode.message());
                errorCode.clear();
                continue;
            }

            const std::filesystem::directory_entry &entry = *iterator;
            const auto path = entry.path();

            if (entry.is_symlink(errorCode)) {
                if constexpr (std::is_same_v<std::decay_t<decltype(iterator)>, std::filesystem::recursive_directory_iterator>) {
                    iterator.disable_recursion_pending();
                }
                continue;
            }

            if (errorCode) {
                appendWarning(warnings, "Metadata error for " + path.string() + ": " + errorCode.message());
                errorCode.clear();
                continue;
            }

            if (!includeHidden && isHidden(path)) {
                if constexpr (std::is_same_v<std::decay_t<decltype(iterator)>, std::filesystem::recursive_directory_iterator>) {
                    iterator.disable_recursion_pending();
                }
                continue;
            }

            if (entry.is_directory(errorCode)) {
                ++stats.visitedDirectories;
                continue;
            }

            if (errorCode) {
                appendWarning(warnings, "Directory metadata error for " + path.string() + ": " + errorCode.message());
                errorCode.clear();
                continue;
            }

            if (entry.is_regular_file(errorCode)) {
                ++stats.visitedFiles;
                callback(entry);
            }

            if (errorCode) {
                appendWarning(warnings, "File metadata error for " + path.string() + ": " + errorCode.message());
                errorCode.clear();
            }
        }
    };

    if (recursive) {
        auto iterator = std::filesystem::recursive_directory_iterator(
            rootPath,
            std::filesystem::directory_options::skip_permission_denied,
            errorCode
        );
        const auto endSentinel = std::filesystem::recursive_directory_iterator();

        if (errorCode) {
            appendWarning(warnings, "Unable to traverse " + rootPath.string() + ": " + errorCode.message());
            return;
        }

        iterateDirectory(iterator, endSentinel);
        return;
    }

    auto iterator = std::filesystem::directory_iterator(
        rootPath,
        std::filesystem::directory_options::skip_permission_denied,
        errorCode
    );
    const auto endSentinel = std::filesystem::directory_iterator();

    if (errorCode) {
        appendWarning(warnings, "Unable to inspect " + rootPath.string() + ": " + errorCode.message());
        return;
    }

    iterateDirectory(iterator, endSentinel);
}

std::vector<std::filesystem::path> FileWalker::collectFiles(const std::filesystem::path &rootPath,
                                                            const bool recursive,
                                                            const bool includeHidden,
                                                            core::ScanStats &stats,
                                                            std::vector<std::string> &warnings,
                                                            const DiscoveryCallback &callback,
                                                            const CancellationCallback &cancellationCallback)
{
    std::vector<std::filesystem::path> files;
    walk(
        rootPath,
        recursive,
        includeHidden,
        stats,
        warnings,
        [&](const std::filesystem::directory_entry &entry) {
            files.push_back(entry.path());
            if (callback) {
                callback(entry.path(), stats);
            }
        },
        cancellationCallback
    );
    return files;
}

} // namespace warden::scanner
