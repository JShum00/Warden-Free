#ifndef WARDEN_FREE_NETWORK_DEFINITIONUPDATER_H
#define WARDEN_FREE_NETWORK_DEFINITIONUPDATER_H

#include <filesystem>
#include <string>
#include <vector>

namespace warden::network {

struct DefinitionUpdateResult {
    bool supported {false};
    bool success {false};
    unsigned int updatedCount {0};
    std::filesystem::path databaseDirectory;
    std::vector<std::string> updatedDatabases;
    std::string error;
};

class DefinitionUpdater
{
public:
    DefinitionUpdateResult updateClamAvDefinitions(const std::filesystem::path &databaseDirectory) const;

    static std::filesystem::path managedDatabaseDirectory();
    static std::filesystem::path preferredDatabaseDirectory();
};

} // namespace warden::network

#endif
