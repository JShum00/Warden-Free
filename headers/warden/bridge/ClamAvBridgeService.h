#ifndef WARDEN_FREE_BRIDGE_CLAMAVBRIDGESERVICE_H
#define WARDEN_FREE_BRIDGE_CLAMAVBRIDGESERVICE_H

#include <QJsonObject>

namespace warden::bridge {

class ClamAvBridgeService
{
public:
    QJsonObject handleRequest(const QJsonObject &request) const;
};

} // namespace warden::bridge

#endif
