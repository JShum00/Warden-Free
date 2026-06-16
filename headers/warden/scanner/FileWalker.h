#ifndef WARDEN_FREE_SCANNER_FILEWALKER_H
#define WARDEN_FREE_SCANNER_FILEWALKER_H

#include <filesystem>
#include <functional>
#include <vector>

#include "warden/core/ScanTypes.h"

namespace warden::scanner {

class FileWalker
{
public:
    using FileCallback = std::function<void(const std::filesystem::directory_entry &)>;
    using DiscoveryCallback = std::function<void(const std::filesystem::path &, const core::ScanStats &)>;
    using CancellationCallback = std::function<bool()>;

    static void walk(const std::filesystem::path &rootPath,
                     bool recursive,
                     bool includeHidden,
                     core::ScanStats &stats,
                     std::vector<std::string> &warnings,
                     const FileCallback &callback,
                     const CancellationCallback &cancellationCallback = {});
    static std::vector<std::filesystem::path> collectFiles(const std::filesystem::path &rootPath,
                                                           bool recursive,
                                                           bool includeHidden,
                                                           core::ScanStats &stats,
                                                           std::vector<std::string> &warnings,
                                                           const DiscoveryCallback &callback = {},
                                                           const CancellationCallback &cancellationCallback = {});

    static bool isHidden(const std::filesystem::path &path);
};

} // namespace warden::scanner

#endif
