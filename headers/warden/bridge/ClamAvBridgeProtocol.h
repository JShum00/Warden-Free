#ifndef WARDEN_FREE_BRIDGE_CLAMAVBRIDGEPROTOCOL_H
#define WARDEN_FREE_BRIDGE_CLAMAVBRIDGEPROTOCOL_H

#include <QString>

namespace warden::bridge {

inline constexpr int kProtocolVersion = 1;

inline const QString kCommandPing = QStringLiteral("ping");
inline const QString kCommandEngineStatus = QStringLiteral("engine_status");
inline const QString kCommandScanPath = QStringLiteral("scan_path");
inline const QString kCommandUpdateDefinitions = QStringLiteral("update_definitions");

} // namespace warden::bridge

#endif
