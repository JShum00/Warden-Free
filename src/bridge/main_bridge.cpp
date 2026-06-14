#include <QCoreApplication>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>

#include "warden/bridge/ClamAvBridgeProtocol.h"
#include "warden/bridge/ClamAvBridgeService.h"

namespace {

QJsonObject invalidJsonResponse(const QString &message)
{
    QJsonObject response;
    response.insert(QStringLiteral("protocol_version"), warden::bridge::kProtocolVersion);
    response.insert(QStringLiteral("ok"), false);
    response.insert(QStringLiteral("error"), message);
    response.insert(QStringLiteral("payload"), QJsonObject {});
    return response;
}

} // namespace

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    QCoreApplication::setApplicationName(QStringLiteral("warden-clamav-bridge"));

    QFile stdinFile;
    stdinFile.open(stdin, QIODevice::ReadOnly);
    const QByteArray rawInput = stdinFile.readAll();

    QJsonObject response;
    QJsonParseError parseError {};
    const QJsonDocument requestDocument = QJsonDocument::fromJson(rawInput, &parseError);
    if (parseError.error != QJsonParseError::NoError || !requestDocument.isObject()) {
        response = invalidJsonResponse(QStringLiteral("Invalid JSON request: %1").arg(parseError.errorString()));
    } else {
        warden::bridge::ClamAvBridgeService service;
        response = service.handleRequest(requestDocument.object());
    }

    QFile stdoutFile;
    if (!stdoutFile.open(stdout, QIODevice::WriteOnly)) {
        return 1;
    }

    stdoutFile.write(QJsonDocument(response).toJson(QJsonDocument::Compact));
    stdoutFile.write("\n");
    stdoutFile.close();

    return response.value(QStringLiteral("ok")).toBool() ? 0 : 1;
}
