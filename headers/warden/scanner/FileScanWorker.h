#ifndef WARDEN_FREE_SCANNER_FILESCANWORKER_H
#define WARDEN_FREE_SCANNER_FILESCANWORKER_H

#include <QObject>
#include <QString>
#include <QStringList>
#include <memory>

#include "warden/core/ScanTypes.h"
#include "warden/scanner/ScanCoordinator.h"

namespace warden::scanner {

class FileScanWorker : public QObject
{
    Q_OBJECT

public:
    explicit FileScanWorker(core::ScanOptions options,
                            ScanCancelFlag cancelRequested = {},
                            QObject *parent = nullptr);

public slots:
    void run();

signals:
    void progressChanged(const QString &phase,
                         const QString &currentItem,
                         int scannedFiles,
                         int totalFiles,
                         int threatsFound,
                         bool indeterminate,
                         const QStringList &activeEngines);
    void finished(const warden::core::ScanReport &report);

private:
    core::ScanOptions m_options;
    ScanCancelFlag m_cancelRequested;
};

} // namespace warden::scanner

#endif
