#ifndef WARDEN_FREE_CORE_APPPATHS_H
#define WARDEN_FREE_CORE_APPPATHS_H

#include <filesystem>

namespace warden::core {

class AppPaths
{
public:
    static std::filesystem::path projectRoot();
    static std::filesystem::path appDataDirectory();
    static std::filesystem::path stateDatabasePath();
    static std::filesystem::path quarantineDirectory();
};

} // namespace warden::core

#endif
