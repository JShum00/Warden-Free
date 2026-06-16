#include "warden/scanner/FileScanWorker.h"

#include "warden/scanner/ScanCoordinator.h"

namespace {

QStringList toQStringList(const std::vector<std::string> &values)
{
    QStringList result;
    result.reserve(static_cast<int>(values.size()));
    for (const auto &value : values) {
        result << QString::fromStdString(value);
    }
    return result;
}

} // namespace

namespace warden::scanner {

FileScanWorker::FileScanWorker(core::ScanOptions options,
                               ScanCancelFlag cancelRequested,
                               QObject *parent)
    : QObject(parent),
      m_options(std::move(options)),
      m_cancelRequested(std::move(cancelRequested))
{
}

void FileScanWorker::run()
{
    ScanCoordinator coordinator;
    const core::ScanReport report = coordinator.runScan(m_options, [this](const core::ScanProgress &progress) {
        emit progressChanged(QString::fromStdString(progress.phaseLabel),
                             QString::fromStdString(progress.currentItem),
                             static_cast<int>(progress.scannedFiles),
                             static_cast<int>(progress.totalFiles),
                             static_cast<int>(progress.threatsFound),
                             progress.indeterminate,
                             toQStringList(progress.activeEngines));
    }, m_cancelRequested);
    emit finished(report);
}

} // namespace warden::scanner
