#include "MainWindow.h"

#include "warden/core/AppPaths.h"
#include "warden/core/ThreatAggregation.h"
#include "warden/scanner/FileScanWorker.h"
#include "warden/scanner/QuarantineManager.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QCheckBox>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QFileDialog>
#include <QFile>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QItemSelectionModel>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMessageBox>
#include <QModelIndex>
#include <QPlainTextEdit>
#include <QProgressBar>
#include <QPushButton>
#include <QSaveFile>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QSplitter>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QTextStream>
#include <QThread>
#include <QVBoxLayout>
#include <QtConcurrent>

#include <algorithm>
#include <filesystem>
#include <set>
#include <sstream>

namespace {

QString toQString(const std::string &value)
{
    return QString::fromStdString(value);
}

QString toQString(const std::filesystem::path &value)
{
    return QString::fromStdString(value.string());
}

QString severityText(const warden::core::Severity severity)
{
    return QString::fromStdString(warden::core::toString(severity));
}

QString categoryText(const warden::core::FindingCategory classification)
{
    return QString::fromStdString(warden::core::toString(classification));
}

QString detectionSourceText(const warden::core::DetectionSource detectionSource)
{
    return QString::fromStdString(warden::core::toString(detectionSource));
}

QString modeText(const warden::core::ScanMode mode)
{
    return QString::fromStdString(warden::core::toString(mode));
}

QStringList actionChoices()
{
    return {
        QStringLiteral("Select Action"),
        QObject::tr("View Details"),
        QObject::tr("Quarantine"),
        QObject::tr("Ignore"),
        QObject::tr("Mark Reviewed"),
        QObject::tr("Exclude File"),
        QObject::tr("Exclude Folder")
    };
}

QColor severityColor(const warden::core::Severity severity)
{
    switch (severity) {
    case warden::core::Severity::Informational:
        return QColor(QStringLiteral("#A7D4FF"));
    case warden::core::Severity::Low:
        return QColor(QStringLiteral("#9CD4B5"));
    case warden::core::Severity::Medium:
        return QColor(QStringLiteral("#F0CF76"));
    case warden::core::Severity::High:
        return QColor(QStringLiteral("#F0A26B"));
    case warden::core::Severity::Critical:
        return QColor(QStringLiteral("#DE6A73"));
    }

    return QColor(QStringLiteral("#A7D4FF"));
}

QString darkStylesheet()
{
    return QStringLiteral(
        "QWidget { background: #14181d; color: #e7edf4; }"
        "QGroupBox { border: 1px solid #2e3843; margin-top: 14px; padding-top: 14px; font-weight: 600; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; color: #c9d4df; }"
        "QPushButton { background: #1f2730; border: 1px solid #3d4a57; padding: 7px 12px; border-radius: 4px; }"
        "QPushButton:hover { background: #27313c; }"
        "QPushButton:disabled { color: #7b8894; border-color: #2f3841; }"
        "QLineEdit, QComboBox, QTableWidget, QPlainTextEdit { background: #11151a; border: 1px solid #36414c; }"
        "QCheckBox { spacing: 8px; }"
        "QHeaderView::section { background: #1d242c; padding: 6px; border: 0; border-right: 1px solid #303944; }"
        "QTabBar::tab { background: #1a2129; padding: 8px 16px; margin-right: 2px; }"
        "QTabBar::tab:selected { background: #24303a; }"
        "QMenu::item { padding: 6px 22px; }"
        "QProgressBar { border: 1px solid #36414c; text-align: center; }"
        "QProgressBar::chunk { background: #4f8bd6; }"
    );
}

QString lightStylesheet()
{
    return QStringLiteral(
        "QGroupBox { border: 1px solid #ccd5df; margin-top: 14px; padding-top: 14px; font-weight: 600; }"
        "QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 4px; }"
        "QPushButton { background: #f1f5f9; border: 1px solid #c2ced9; padding: 7px 12px; border-radius: 4px; }"
        "QPushButton:hover { background: #e7edf4; }"
        "QLineEdit, QComboBox, QTableWidget, QPlainTextEdit { background: #ffffff; border: 1px solid #cbd5df; }"
        "QHeaderView::section { background: #e8eef5; padding: 6px; border: 0; border-right: 1px solid #d3dde7; }"
    );
}

QString joinStrings(const std::vector<std::string> &values)
{
    QStringList items;
    for (const auto &value : values) {
        if (!value.empty()) {
            items << QString::fromStdString(value);
        }
    }
    return items.join(QStringLiteral(", "));
}

QString activeEnginesText(const bool enableClamAv, const bool enableHeuristics)
{
    QStringList items;
    if (enableClamAv) {
        items << QObject::tr("ClamAV");
    }
    if (enableHeuristics) {
        items << QObject::tr("Heuristics");
    }

    return items.isEmpty() ? QObject::tr("(none)") : items.join(QStringLiteral(", "));
}

QString formatDuration(const std::uint64_t durationMs)
{
    if (durationMs == 0) {
        return QObject::tr("0s");
    }

    const auto seconds = durationMs / 1000;
    const auto minutes = seconds / 60;
    const auto remainingSeconds = seconds % 60;
    if (minutes == 0) {
        return QObject::tr("%1s").arg(remainingSeconds);
    }

    return QObject::tr("%1m %2s").arg(minutes).arg(remainingSeconds);
}

QString csvEscape(const QString &value)
{
    QString escaped = value;
    escaped.replace('"', QStringLiteral("\"\""));
    return QStringLiteral("\"%1\"").arg(escaped);
}

QJsonArray toJsonArray(const std::vector<std::string> &values)
{
    QJsonArray array;
    for (const auto &value : values) {
        array.append(QString::fromStdString(value));
    }
    return array;
}

std::vector<std::string> fromJsonArray(const QJsonArray &array)
{
    std::vector<std::string> values;
    values.reserve(array.size());
    for (const auto &value : array) {
        values.push_back(value.toString().toStdString());
    }
    return values;
}

QJsonObject findingToJson(const warden::core::ThreatFinding &finding)
{
    QJsonObject object;
    object.insert(QStringLiteral("name"), toQString(finding.name));
    object.insert(QStringLiteral("path"), toQString(finding.path));
    object.insert(QStringLiteral("threat_type"), toQString(warden::core::toString(finding.threatType)));
    object.insert(QStringLiteral("classification"), toQString(warden::core::toString(finding.classification)));
    object.insert(QStringLiteral("severity"), toQString(warden::core::toString(finding.severity)));
    object.insert(QStringLiteral("source"), toQString(finding.source));
    object.insert(QStringLiteral("detection_engine"), toQString(finding.detectionEngine));
    object.insert(QStringLiteral("detection_source"), toQString(warden::core::toString(finding.detectionSource)));
    object.insert(QStringLiteral("description"), toQString(finding.description));
    object.insert(QStringLiteral("operator_summary"), toQString(finding.operatorSummary));
    object.insert(QStringLiteral("recommended_action"), toQString(finding.recommendedAction));
    object.insert(QStringLiteral("sha256"), toQString(finding.sha256));
    object.insert(QStringLiteral("file_size"), static_cast<qint64>(finding.fileSize));
    object.insert(QStringLiteral("entropy"), finding.entropy);
    object.insert(QStringLiteral("confidence_score"), finding.confidenceScore);
    object.insert(QStringLiteral("triggered_rules"), toJsonArray(finding.triggeredRules));
    object.insert(QStringLiteral("evidence"), toJsonArray(finding.evidence));
    return object;
}

warden::core::ThreatFinding findingFromJson(const QJsonObject &object)
{
    warden::core::ThreatFinding finding;
    finding.name = object.value(QStringLiteral("name")).toString().toStdString();
    finding.path = std::filesystem::path(object.value(QStringLiteral("path")).toString().toStdString());
    finding.threatType = warden::core::threatTypeFromString(object.value(QStringLiteral("threat_type")).toString().toStdString());
    finding.classification = warden::core::findingCategoryFromString(object.value(QStringLiteral("classification")).toString().toStdString());
    finding.severity = warden::core::severityFromString(object.value(QStringLiteral("severity")).toString().toStdString());
    finding.source = object.value(QStringLiteral("source")).toString().toStdString();
    finding.detectionEngine = object.value(QStringLiteral("detection_engine")).toString().toStdString();
    finding.detectionSource = warden::core::detectionSourceFromString(object.value(QStringLiteral("detection_source")).toString().toStdString());
    finding.description = object.value(QStringLiteral("description")).toString().toStdString();
    finding.operatorSummary = object.value(QStringLiteral("operator_summary")).toString().toStdString();
    finding.recommendedAction = object.value(QStringLiteral("recommended_action")).toString().toStdString();
    finding.sha256 = object.value(QStringLiteral("sha256")).toString().toStdString();
    finding.fileSize = static_cast<std::uintmax_t>(object.value(QStringLiteral("file_size")).toVariant().toULongLong());
    finding.entropy = object.value(QStringLiteral("entropy")).toDouble();
    finding.confidenceScore = object.value(QStringLiteral("confidence_score")).toDouble();
    finding.triggeredRules = fromJsonArray(object.value(QStringLiteral("triggered_rules")).toArray());
    finding.evidence = fromJsonArray(object.value(QStringLiteral("evidence")).toArray());
    return finding;
}

QByteArray findingsToJsonBytes(const std::vector<warden::core::ThreatFinding> &findings)
{
    QJsonArray array;
    for (const auto &finding : findings) {
        array.append(findingToJson(finding));
    }
    return QJsonDocument(array).toJson(QJsonDocument::Compact);
}

std::vector<warden::core::ThreatFinding> findingsFromJsonBytes(const QByteArray &json, QString &error)
{
    const QJsonDocument document = QJsonDocument::fromJson(json);
    if (!document.isArray()) {
        error = QObject::tr("Expected a JSON array of findings.");
        return {};
    }

    std::vector<warden::core::ThreatFinding> findings;
    for (const auto &value : document.array()) {
        if (!value.isObject()) {
            continue;
        }
        findings.push_back(findingFromJson(value.toObject()));
    }
    return findings;
}

QByteArray warningsToJsonBytes(const std::vector<std::string> &warnings)
{
    return QJsonDocument(toJsonArray(warnings)).toJson(QJsonDocument::Compact);
}

std::vector<std::string> warningsFromJsonBytes(const QByteArray &json)
{
    const QJsonDocument document = QJsonDocument::fromJson(json);
    if (!document.isArray()) {
        return {};
    }

    return fromJsonArray(document.array());
}

QJsonObject reportToJsonObject(const warden::core::ScanReport &report)
{
    QJsonObject options;
    options.insert(QStringLiteral("target_path"), toQString(report.options.targetPath));
    options.insert(QStringLiteral("clamav_database_path"), toQString(report.options.clamAvDatabasePath));
    options.insert(QStringLiteral("quarantine_directory"), toQString(report.options.quarantineDirectory));
    options.insert(QStringLiteral("recursive"), report.options.recursive);
    options.insert(QStringLiteral("include_hidden"), report.options.includeHidden);
    options.insert(QStringLiteral("max_file_size_bytes"), static_cast<qint64>(report.options.maxFileSizeBytes));
    options.insert(QStringLiteral("mode"), toQString(warden::core::toString(report.options.mode)));
    options.insert(QStringLiteral("enable_clamav"), report.options.enableClamAv);
    options.insert(QStringLiteral("enable_heuristics"), report.options.enableHeuristics);

    QJsonObject stats;
    stats.insert(QStringLiteral("visited_directories"), static_cast<qint64>(report.stats.visitedDirectories));
    stats.insert(QStringLiteral("visited_files"), static_cast<qint64>(report.stats.visitedFiles));
    stats.insert(QStringLiteral("scanned_files"), static_cast<qint64>(report.stats.scannedFiles));
    stats.insert(QStringLiteral("result_count"), static_cast<qint64>(report.stats.resultCount));
    stats.insert(QStringLiteral("threats_found"), static_cast<qint64>(report.stats.threatsFound));
    stats.insert(QStringLiteral("unique_files_flagged"), static_cast<qint64>(report.stats.uniqueFilesFlagged));
    stats.insert(QStringLiteral("warning_count"), static_cast<qint64>(report.stats.warningCount));
    stats.insert(QStringLiteral("bytes_hashed"), static_cast<qint64>(report.stats.bytesHashed));
    stats.insert(QStringLiteral("bytes_scanned_by_clamav"), static_cast<qint64>(report.stats.bytesScannedByClamAv));

    QJsonObject object;
    object.insert(QStringLiteral("options"), options);
    object.insert(QStringLiteral("stats"), stats);
    object.insert(QStringLiteral("clamav_loaded"), report.clamAvLoaded);
    object.insert(QStringLiteral("clamav_signatures"), static_cast<int>(report.clamAvSignatures));
    object.insert(QStringLiteral("clamav_version"), toQString(report.clamAvVersion));
    object.insert(QStringLiteral("started_at_utc"), toQString(report.startedAtUtc));
    object.insert(QStringLiteral("completed_at_utc"), toQString(report.completedAtUtc));
    object.insert(QStringLiteral("duration_ms"), static_cast<qint64>(report.durationMs));
    object.insert(QStringLiteral("canceled"), report.canceled);
    object.insert(QStringLiteral("cancel_phase"), toQString(report.cancelPhase));
    object.insert(QStringLiteral("findings"), QJsonDocument::fromJson(findingsToJsonBytes(report.findings)).array());
    object.insert(QStringLiteral("warnings"), QJsonDocument::fromJson(warningsToJsonBytes(report.warnings)).array());
    return object;
}

QByteArray reportToJsonBytes(const warden::core::ScanReport &report)
{
    return QJsonDocument(reportToJsonObject(report)).toJson(QJsonDocument::Indented);
}

warden::core::ScanMode scanModeFromString(const QString &value)
{
    const QString normalized = value.trimmed().toLower();
    if (normalized == QStringLiteral("full")) {
        return warden::core::ScanMode::Full;
    }
    if (normalized == QStringLiteral("signature-only")) {
        return warden::core::ScanMode::SignatureOnly;
    }
    if (normalized == QStringLiteral("heuristic-only")) {
        return warden::core::ScanMode::HeuristicOnly;
    }
    if (normalized == QStringLiteral("custom")) {
        return warden::core::ScanMode::Custom;
    }
    return warden::core::ScanMode::Quick;
}

std::optional<warden::core::ScanReport> reportFromJsonBytes(const QByteArray &json, QString &error)
{
    const QJsonDocument document = QJsonDocument::fromJson(json);
    if (!document.isObject()) {
        error = QObject::tr("Expected a JSON object report.");
        return std::nullopt;
    }

    const QJsonObject object = document.object();
    const QJsonObject optionsObject = object.value(QStringLiteral("options")).toObject();
    const QJsonObject statsObject = object.value(QStringLiteral("stats")).toObject();

    warden::core::ScanReport report;
    report.options.targetPath = std::filesystem::path(optionsObject.value(QStringLiteral("target_path")).toString().toStdString());
    report.options.clamAvDatabasePath = std::filesystem::path(optionsObject.value(QStringLiteral("clamav_database_path")).toString().toStdString());
    report.options.quarantineDirectory = std::filesystem::path(optionsObject.value(QStringLiteral("quarantine_directory")).toString().toStdString());
    report.options.recursive = optionsObject.value(QStringLiteral("recursive")).toBool(true);
    report.options.includeHidden = optionsObject.value(QStringLiteral("include_hidden")).toBool(false);
    report.options.maxFileSizeBytes = static_cast<std::uintmax_t>(
        optionsObject.value(QStringLiteral("max_file_size_bytes")).toVariant().toULongLong()
    );
    report.options.mode = scanModeFromString(optionsObject.value(QStringLiteral("mode")).toString());
    report.options.enableClamAv = optionsObject.value(QStringLiteral("enable_clamav")).toBool(true);
    report.options.enableHeuristics = optionsObject.value(QStringLiteral("enable_heuristics")).toBool(true);

    report.stats.visitedDirectories = statsObject.value(QStringLiteral("visited_directories")).toVariant().toULongLong();
    report.stats.visitedFiles = statsObject.value(QStringLiteral("visited_files")).toVariant().toULongLong();
    report.stats.scannedFiles = statsObject.value(QStringLiteral("scanned_files")).toVariant().toULongLong();
    report.stats.resultCount = statsObject.value(QStringLiteral("result_count")).toVariant().toULongLong();
    report.stats.threatsFound = statsObject.value(QStringLiteral("threats_found")).toVariant().toULongLong();
    report.stats.uniqueFilesFlagged = statsObject.value(QStringLiteral("unique_files_flagged")).toVariant().toULongLong();
    report.stats.warningCount = statsObject.value(QStringLiteral("warning_count")).toVariant().toULongLong();
    report.stats.bytesHashed = statsObject.value(QStringLiteral("bytes_hashed")).toVariant().toULongLong();
    report.stats.bytesScannedByClamAv = statsObject.value(QStringLiteral("bytes_scanned_by_clamav")).toVariant().toULongLong();

    report.clamAvLoaded = object.value(QStringLiteral("clamav_loaded")).toBool();
    report.clamAvSignatures = static_cast<unsigned int>(object.value(QStringLiteral("clamav_signatures")).toInt());
    report.clamAvVersion = object.value(QStringLiteral("clamav_version")).toString().toStdString();
    report.startedAtUtc = object.value(QStringLiteral("started_at_utc")).toString().toStdString();
    report.completedAtUtc = object.value(QStringLiteral("completed_at_utc")).toString().toStdString();
    report.durationMs = object.value(QStringLiteral("duration_ms")).toVariant().toULongLong();
    report.canceled = object.value(QStringLiteral("canceled")).toBool(false);
    report.cancelPhase = object.value(QStringLiteral("cancel_phase")).toString().toStdString();

    QString findingsError;
    report.findings = findingsFromJsonBytes(QJsonDocument(object.value(QStringLiteral("findings")).toArray()).toJson(QJsonDocument::Compact),
                                            findingsError);
    if (!findingsError.isEmpty()) {
        error = findingsError;
        return std::nullopt;
    }
    report.records = warden::core::aggregateThreatFindings(report.findings);
    report.warnings = warningsFromJsonBytes(QJsonDocument(object.value(QStringLiteral("warnings")).toArray()).toJson(QJsonDocument::Compact));
    if (report.stats.resultCount == 0) {
        report.stats.resultCount = report.findings.size();
    }
    if (report.stats.threatsFound == 0) {
        report.stats.threatsFound = report.records.size();
    }
    if (report.stats.uniqueFilesFlagged == 0) {
        report.stats.uniqueFilesFlagged = report.records.size();
    }
    if (report.stats.warningCount == 0) {
        report.stats.warningCount = report.warnings.size();
    }

    return report;
}

QString reportSummaryText(const warden::core::ScanReport &report)
{
    return QObject::tr("%1 scan | Files: %2 | Results: %3 | Warnings: %4 | Duration: %5")
        .arg(modeText(report.options.mode))
        .arg(report.stats.scannedFiles)
        .arg(report.records.size())
        .arg(report.warnings.size())
        .arg(formatDuration(report.durationMs));
}

bool recordMatchesExclusion(const warden::storage::StateStore &stateStore,
                            const warden::core::ThreatRecord &record)
{
    if (!record.findings.empty()) {
        return stateStore.isExcluded(record.findings.front());
    }

    warden::core::ThreatFinding finding;
    finding.path = record.path;
    finding.sha256 = record.sha256;
    return stateStore.isExcluded(finding);
}

warden::core::ThreatFinding representativeFinding(const warden::core::ThreatRecord &record)
{
    if (!record.findings.empty()) {
        return record.findings.front();
    }

    warden::core::ThreatFinding finding;
    finding.name = record.name;
    finding.path = record.path;
    finding.threatType = record.threatType;
    finding.classification = record.classification;
    finding.severity = record.severity;
    finding.source = joinStrings(record.detectionEngines).toStdString();
    finding.detectionEngine = finding.source;
    finding.detectionSource = record.detectionSource;
    finding.description = record.description;
    finding.operatorSummary = record.operatorSummary;
    finding.recommendedAction = record.recommendedAction;
    finding.sha256 = record.sha256;
    finding.fileSize = record.fileSize;
    finding.entropy = record.entropy;
    finding.confidenceScore = record.confidenceScore;
    finding.triggeredRules = record.triggeredRules;
    finding.evidence = record.evidence;
    return finding;
}

} // namespace

MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent),
      m_tabWidget(new QTabWidget(this)),
      m_homeTab(nullptr),
      m_fileScanTab(nullptr),
      m_settingsTab(nullptr),
      m_trayIcon(nullptr),
      m_trayMenu(nullptr),
      m_homeQuickScanButton(nullptr),
      m_homeFullScanButton(nullptr),
      m_homeUpdateDefsButton(nullptr),
      m_homeFileScanStatusLabel(nullptr),
      m_homeThreatSummaryLabel(nullptr),
      m_homeDefinitionsStatusLabel(nullptr),
      m_homeHistorySummaryLabel(nullptr),
      m_fileScanTargetEdit(nullptr),
      m_fileScanBrowseButton(nullptr),
      m_fileScanProfileCombo(nullptr),
      m_fileScanRunButton(nullptr),
      m_fileScanQuickButton(nullptr),
      m_fileScanFullButton(nullptr),
      m_fileScanCancelButton(nullptr),
      m_fileScanClamAvCheckBox(nullptr),
      m_fileScanHeuristicCheckBox(nullptr),
      m_fileScanProgressBar(nullptr),
      m_fileScanStatusLabel(nullptr),
      m_fileScanCurrentItemLabel(nullptr),
      m_fileScanCountersLabel(nullptr),
      m_fileScanEnginesLabel(nullptr),
      m_fileScanSummaryLabel(nullptr),
      m_fileClassFilterCombo(nullptr),
      m_fileSeverityFilterCombo(nullptr),
      m_fileEngineFilterCombo(nullptr),
      m_fileExtensionFilterCombo(nullptr),
      m_exportFindingsButton(nullptr),
      m_exportSelectedFindingsButton(nullptr),
      m_saveReportButton(nullptr),
      m_loadReportButton(nullptr),
      m_ignoreSelectedFindingsButton(nullptr),
      m_markReviewedFindingsButton(nullptr),
      m_addSelectedExclusionsButton(nullptr),
      m_threatTable(nullptr),
      m_threatDetailsText(nullptr),
      m_scanHistoryTable(nullptr),
      m_exclusionsTable(nullptr),
      m_removeExclusionButton(nullptr),
      m_quarantinePathLabel(nullptr),
      m_quarantineTable(nullptr),
      m_refreshQuarantineButton(nullptr),
      m_restoreQuarantineButton(nullptr),
      m_updateClamAvButton(nullptr),
      m_clamAvUpdateStatusLabel(nullptr),
      m_themeComboBox(nullptr),
      m_lastScanHistoryId(0),
      m_fileScanThread(nullptr),
      m_fileScanWorker(nullptr),
      m_definitionUpdateWatcher(new QFutureWatcher<warden::network::DefinitionUpdateResult>(this)),
      m_allowClose(false),
      m_hasShownMinimizeNotice(false)
{
    qRegisterMetaType<warden::core::ScanReport>("warden::core::ScanReport");

    QIcon appIcon(QStringLiteral(":/icons/Warden-Logo.png"));
    if (appIcon.isNull()) {
        appIcon = style()->standardIcon(QStyle::SP_MessageBoxInformation);
    }

    setWindowTitle(tr("Warden Free"));
    setWindowIcon(appIcon);
    resize(1280, 860);

    createTabs();
    setCentralWidget(m_tabWidget);

    connect(m_definitionUpdateWatcher,
            &QFutureWatcher<warden::network::DefinitionUpdateResult>::finished,
            this,
            &MainWindow::handleClamAvDefinitionUpdateFinished);

    initializeUiState();
    createTrayIcon();
}

void MainWindow::closeEvent(QCloseEvent *event)
{
    if (m_allowClose || m_trayIcon == nullptr || !m_trayIcon->isVisible()) {
        event->accept();
        return;
    }

    event->ignore();
    hide();

    if (!m_hasShownMinimizeNotice) {
        m_hasShownMinimizeNotice = true;
        showTrayNotification(tr("Warden Free"),
                             tr("Warden Free is still running in the system tray."),
                             QSystemTrayIcon::Information);
    }
}

void MainWindow::createTabs()
{
    m_homeTab = createHomeTab();
    m_fileScanTab = createFileScanTab();
    m_settingsTab = createSettingsTab();

    m_tabWidget->addTab(m_homeTab, tr("Home Base"));
    m_tabWidget->addTab(m_fileScanTab, tr("FS Scan"));
    m_tabWidget->addTab(m_settingsTab, tr("Settings"));
}

QWidget *MainWindow::createHomeTab()
{
    auto *tab = new QWidget(m_tabWidget);
    auto *layout = new QVBoxLayout(tab);

    auto *actionsBox = new QGroupBox(tr("Filesystem Workflows"), tab);
    auto *actionsLayout = new QHBoxLayout(actionsBox);
    m_homeQuickScanButton = new QPushButton(tr("Quick Scan"), actionsBox);
    m_homeFullScanButton = new QPushButton(tr("Full Scan"), actionsBox);
    m_homeUpdateDefsButton = new QPushButton(tr("Update Definitions"), actionsBox);
    actionsLayout->addWidget(m_homeQuickScanButton);
    actionsLayout->addWidget(m_homeFullScanButton);
    actionsLayout->addWidget(m_homeUpdateDefsButton);
    layout->addWidget(actionsBox);

    auto *statusBox = new QGroupBox(tr("Status Summary"), tab);
    auto *statusLayout = new QVBoxLayout(statusBox);
    m_homeFileScanStatusLabel = new QLabel(tr("No filesystem scan has been run yet."), statusBox);
    m_homeThreatSummaryLabel = new QLabel(tr("No findings are currently loaded."), statusBox);
    m_homeDefinitionsStatusLabel = new QLabel(tr("Definition updater idle."), statusBox);
    m_homeHistorySummaryLabel = new QLabel(tr("History, exclusions, and quarantine are empty."), statusBox);
    for (QLabel *label : {m_homeFileScanStatusLabel, m_homeThreatSummaryLabel, m_homeDefinitionsStatusLabel, m_homeHistorySummaryLabel}) {
        label->setWordWrap(true);
        label->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
        statusLayout->addWidget(label);
    }
    layout->addWidget(statusBox);
    layout->addStretch(1);

    connect(m_homeQuickScanButton, &QPushButton::clicked, this, &MainWindow::startQuickFileScan);
    connect(m_homeFullScanButton, &QPushButton::clicked, this, &MainWindow::startFullFileScan);
    connect(m_homeUpdateDefsButton, &QPushButton::clicked, this, &MainWindow::startClamAvDefinitionUpdate);

    return tab;
}

QWidget *MainWindow::createFileScanTab()
{
    auto *tab = new QWidget(m_tabWidget);
    auto *layout = new QVBoxLayout(tab);

    auto *controlsBox = new QGroupBox(tr("Filesystem Scan"), tab);
    auto *controlsLayout = new QGridLayout(controlsBox);

    m_fileScanTargetEdit = new QLineEdit(controlsBox);
    m_fileScanBrowseButton = new QPushButton(tr("Browse"), controlsBox);
    m_fileScanProfileCombo = new QComboBox(controlsBox);
    m_fileScanProfileCombo->addItem(tr("Quick"), static_cast<int>(warden::core::ScanMode::Quick));
    m_fileScanProfileCombo->addItem(tr("Full"), static_cast<int>(warden::core::ScanMode::Full));
    m_fileScanProfileCombo->addItem(tr("Signature-Only"), static_cast<int>(warden::core::ScanMode::SignatureOnly));
    m_fileScanProfileCombo->addItem(tr("Heuristic-Only"), static_cast<int>(warden::core::ScanMode::HeuristicOnly));
    m_fileScanProfileCombo->addItem(tr("Custom"), static_cast<int>(warden::core::ScanMode::Custom));
    m_fileScanRunButton = new QPushButton(tr("Run Profile"), controlsBox);
    m_fileScanQuickButton = new QPushButton(tr("Quick"), controlsBox);
    m_fileScanFullButton = new QPushButton(tr("Full"), controlsBox);
    m_fileScanCancelButton = new QPushButton(tr("Cancel"), controlsBox);
    m_fileScanCancelButton->setEnabled(false);
    m_fileScanClamAvCheckBox = new QCheckBox(tr("ClamAV"), controlsBox);
    m_fileScanHeuristicCheckBox = new QCheckBox(tr("Heuristics"), controlsBox);

    controlsLayout->addWidget(new QLabel(tr("Target:"), controlsBox), 0, 0);
    controlsLayout->addWidget(m_fileScanTargetEdit, 0, 1, 1, 4);
    controlsLayout->addWidget(m_fileScanBrowseButton, 0, 5);
    controlsLayout->addWidget(new QLabel(tr("Profile:"), controlsBox), 1, 0);
    controlsLayout->addWidget(m_fileScanProfileCombo, 1, 1);
    controlsLayout->addWidget(m_fileScanRunButton, 1, 2);
    controlsLayout->addWidget(m_fileScanQuickButton, 1, 3);
    controlsLayout->addWidget(m_fileScanFullButton, 1, 4);
    controlsLayout->addWidget(m_fileScanCancelButton, 1, 5);
    controlsLayout->addWidget(m_fileScanClamAvCheckBox, 2, 1);
    controlsLayout->addWidget(m_fileScanHeuristicCheckBox, 2, 2);
    layout->addWidget(controlsBox);

    auto *activityBox = new QGroupBox(tr("Live Activity"), tab);
    auto *activityLayout = new QVBoxLayout(activityBox);
    m_fileScanStatusLabel = new QLabel(tr("Ready."), activityBox);
    m_fileScanCurrentItemLabel = new QLabel(tr("Current item: idle"), activityBox);
    m_fileScanCountersLabel = new QLabel(tr("Scanned: 0 | Total: 0 | Results: 0"), activityBox);
    m_fileScanEnginesLabel = new QLabel(tr("Active engines: ClamAV, Heuristics"), activityBox);
    m_fileScanProgressBar = new QProgressBar(activityBox);
    m_fileScanProgressBar->setRange(0, 100);
    m_fileScanProgressBar->setValue(0);
    for (QLabel *label : {m_fileScanStatusLabel, m_fileScanCurrentItemLabel, m_fileScanCountersLabel, m_fileScanEnginesLabel}) {
        label->setWordWrap(true);
        activityLayout->addWidget(label);
    }
    activityLayout->addWidget(m_fileScanProgressBar);
    layout->addWidget(activityBox);

    m_fileScanSummaryLabel = new QLabel(tr("No filesystem report loaded."), tab);
    m_fileScanSummaryLabel->setWordWrap(true);
    layout->addWidget(m_fileScanSummaryLabel);

    auto *workspaceTabs = new QTabWidget(tab);

    auto *findingsTab = new QWidget(workspaceTabs);
    auto *findingsLayout = new QVBoxLayout(findingsTab);

    auto *filterLayout = new QHBoxLayout();
    m_fileClassFilterCombo = new QComboBox(findingsTab);
    m_fileSeverityFilterCombo = new QComboBox(findingsTab);
    m_fileEngineFilterCombo = new QComboBox(findingsTab);
    m_fileExtensionFilterCombo = new QComboBox(findingsTab);
    filterLayout->addWidget(new QLabel(tr("Class:"), findingsTab));
    filterLayout->addWidget(m_fileClassFilterCombo);
    filterLayout->addWidget(new QLabel(tr("Severity:"), findingsTab));
    filterLayout->addWidget(m_fileSeverityFilterCombo);
    filterLayout->addWidget(new QLabel(tr("Engine:"), findingsTab));
    filterLayout->addWidget(m_fileEngineFilterCombo);
    filterLayout->addWidget(new QLabel(tr("Extension:"), findingsTab));
    filterLayout->addWidget(m_fileExtensionFilterCombo);
    findingsLayout->addLayout(filterLayout);

    auto *actionsLayout = new QHBoxLayout();
    m_exportFindingsButton = new QPushButton(tr("Export Visible CSV"), findingsTab);
    m_exportSelectedFindingsButton = new QPushButton(tr("Export Selected CSV"), findingsTab);
    m_saveReportButton = new QPushButton(tr("Save Report"), findingsTab);
    m_loadReportButton = new QPushButton(tr("Load Report"), findingsTab);
    m_ignoreSelectedFindingsButton = new QPushButton(tr("Ignore Selected"), findingsTab);
    m_markReviewedFindingsButton = new QPushButton(tr("Mark Reviewed"), findingsTab);
    m_addSelectedExclusionsButton = new QPushButton(tr("Exclude Selected"), findingsTab);
    actionsLayout->addWidget(m_exportFindingsButton);
    actionsLayout->addWidget(m_exportSelectedFindingsButton);
    actionsLayout->addWidget(m_saveReportButton);
    actionsLayout->addWidget(m_loadReportButton);
    actionsLayout->addWidget(m_ignoreSelectedFindingsButton);
    actionsLayout->addWidget(m_markReviewedFindingsButton);
    actionsLayout->addWidget(m_addSelectedExclusionsButton);
    findingsLayout->addLayout(actionsLayout);

    auto *findingsSplitter = new QSplitter(Qt::Vertical, findingsTab);
    m_threatTable = new QTableWidget(findingsSplitter);
    m_threatTable->setColumnCount(8);
    m_threatTable->setHorizontalHeaderLabels({
        tr("Threat"),
        tr("Path"),
        tr("Class"),
        tr("Severity"),
        tr("Engines"),
        tr("Confidence"),
        tr("Status"),
        tr("Action")
    });
    m_threatTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_threatTable->verticalHeader()->setVisible(false);
    m_threatTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_threatTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_threatTable->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_threatDetailsText = new QPlainTextEdit(findingsSplitter);
    m_threatDetailsText->setReadOnly(true);
    m_threatDetailsText->setPlaceholderText(tr("Select a finding to inspect its details, evidence, and recommended action."));
    findingsSplitter->addWidget(m_threatTable);
    findingsSplitter->addWidget(m_threatDetailsText);
    findingsSplitter->setStretchFactor(0, 3);
    findingsSplitter->setStretchFactor(1, 2);
    findingsLayout->addWidget(findingsSplitter, 1);
    workspaceTabs->addTab(findingsTab, tr("Findings"));

    auto *historyTab = new QWidget(workspaceTabs);
    auto *historyLayout = new QVBoxLayout(historyTab);
    m_scanHistoryTable = new QTableWidget(historyTab);
    m_scanHistoryTable->setColumnCount(7);
    m_scanHistoryTable->setHorizontalHeaderLabels({
        tr("Completed"),
        tr("Profile"),
        tr("Files"),
        tr("Results"),
        tr("Warnings"),
        tr("Duration"),
        tr("Summary")
    });
    m_scanHistoryTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_scanHistoryTable->verticalHeader()->setVisible(false);
    m_scanHistoryTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_scanHistoryTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    historyLayout->addWidget(m_scanHistoryTable);
    workspaceTabs->addTab(historyTab, tr("History"));

    auto *exclusionsTab = new QWidget(workspaceTabs);
    auto *exclusionsLayout = new QVBoxLayout(exclusionsTab);
    m_removeExclusionButton = new QPushButton(tr("Remove Selected Exclusions"), exclusionsTab);
    m_exclusionsTable = new QTableWidget(exclusionsTab);
    m_exclusionsTable->setColumnCount(4);
    m_exclusionsTable->setHorizontalHeaderLabels({
        tr("Type"),
        tr("Value"),
        tr("Label"),
        tr("Created")
    });
    m_exclusionsTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_exclusionsTable->verticalHeader()->setVisible(false);
    m_exclusionsTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_exclusionsTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    exclusionsLayout->addWidget(m_removeExclusionButton);
    exclusionsLayout->addWidget(m_exclusionsTable);
    workspaceTabs->addTab(exclusionsTab, tr("Exclusions"));

    auto *quarantineTab = new QWidget(workspaceTabs);
    auto *quarantineLayout = new QVBoxLayout(quarantineTab);
    m_quarantinePathLabel = new QLabel(quarantineTab);
    auto *quarantineActionsLayout = new QHBoxLayout();
    m_refreshQuarantineButton = new QPushButton(tr("Refresh Quarantine"), quarantineTab);
    m_restoreQuarantineButton = new QPushButton(tr("Restore Selected"), quarantineTab);
    quarantineActionsLayout->addWidget(m_refreshQuarantineButton);
    quarantineActionsLayout->addWidget(m_restoreQuarantineButton);
    quarantineActionsLayout->addStretch(1);
    m_quarantineTable = new QTableWidget(quarantineTab);
    m_quarantineTable->setColumnCount(6);
    m_quarantineTable->setHorizontalHeaderLabels({
        tr("Threat"),
        tr("Original Path"),
        tr("Quarantine Path"),
        tr("Status"),
        tr("Created"),
        tr("Restored")
    });
    m_quarantineTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_quarantineTable->verticalHeader()->setVisible(false);
    m_quarantineTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_quarantineTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    quarantineLayout->addWidget(m_quarantinePathLabel);
    quarantineLayout->addLayout(quarantineActionsLayout);
    quarantineLayout->addWidget(m_quarantineTable);
    workspaceTabs->addTab(quarantineTab, tr("Quarantine"));

    layout->addWidget(workspaceTabs, 1);

    connect(m_fileScanBrowseButton, &QPushButton::clicked, this, &MainWindow::browseFileScanTarget);
    connect(m_fileScanProfileCombo, &QComboBox::currentIndexChanged, this, [this]() {
        handleFileProfileChanged();
    });
    connect(m_fileScanRunButton, &QPushButton::clicked, this, &MainWindow::startConfiguredFileScan);
    connect(m_fileScanQuickButton, &QPushButton::clicked, this, &MainWindow::startQuickFileScan);
    connect(m_fileScanFullButton, &QPushButton::clicked, this, &MainWindow::startFullFileScan);
    connect(m_fileScanCancelButton, &QPushButton::clicked, this, &MainWindow::cancelFileScan);
    connect(m_fileClassFilterCombo, &QComboBox::currentTextChanged, this, [this]() { applyThreatFilters(); });
    connect(m_fileSeverityFilterCombo, &QComboBox::currentTextChanged, this, [this]() { applyThreatFilters(); });
    connect(m_fileEngineFilterCombo, &QComboBox::currentTextChanged, this, [this]() { applyThreatFilters(); });
    connect(m_fileExtensionFilterCombo, &QComboBox::currentTextChanged, this, [this]() { applyThreatFilters(); });
    connect(m_threatTable->selectionModel(), &QItemSelectionModel::selectionChanged, this, [this]() {
        handleThreatSelectionChanged();
    });
    connect(m_exportFindingsButton, &QPushButton::clicked, this, &MainWindow::exportFindingsToCsv);
    connect(m_exportSelectedFindingsButton, &QPushButton::clicked, this, &MainWindow::exportSelectedFindings);
    connect(m_saveReportButton, &QPushButton::clicked, this, &MainWindow::saveCurrentReport);
    connect(m_loadReportButton, &QPushButton::clicked, this, &MainWindow::loadSavedReport);
    connect(m_ignoreSelectedFindingsButton, &QPushButton::clicked, this, &MainWindow::ignoreSelectedThreats);
    connect(m_markReviewedFindingsButton, &QPushButton::clicked, this, &MainWindow::markSelectedThreatsReviewed);
    connect(m_addSelectedExclusionsButton, &QPushButton::clicked, this, &MainWindow::addSelectedThreatsToExclusions);
    connect(m_removeExclusionButton, &QPushButton::clicked, this, &MainWindow::removeSelectedExclusions);
    connect(m_refreshQuarantineButton, &QPushButton::clicked, this, &MainWindow::refreshQuarantineData);
    connect(m_restoreQuarantineButton, &QPushButton::clicked, this, &MainWindow::restoreSelectedQuarantine);

    return tab;
}

QWidget *MainWindow::createSettingsTab()
{
    auto *tab = new QWidget(m_tabWidget);
    auto *layout = new QVBoxLayout(tab);

    auto *updatesBox = new QGroupBox(tr("Definition Updates"), tab);
    auto *updatesLayout = new QGridLayout(updatesBox);
    m_updateClamAvButton = new QPushButton(tr("Update ClamAV Definitions"), updatesBox);
    m_clamAvUpdateStatusLabel = new QLabel(tr("Idle."), updatesBox);
    m_clamAvUpdateStatusLabel->setWordWrap(true);
    m_clamAvUpdateStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    updatesLayout->addWidget(m_updateClamAvButton, 0, 0);
    updatesLayout->addWidget(m_clamAvUpdateStatusLabel, 0, 1);
    layout->addWidget(updatesBox);

    auto *appearanceBox = new QGroupBox(tr("Appearance"), tab);
    auto *appearanceLayout = new QFormLayout(appearanceBox);
    m_themeComboBox = new QComboBox(appearanceBox);
    m_themeComboBox->addItems({tr("Warden Dark"), tr("Clean Light"), tr("System Default")});
    appearanceLayout->addRow(tr("Theme:"), m_themeComboBox);
    layout->addWidget(appearanceBox);
    layout->addStretch(1);

    connect(m_updateClamAvButton, &QPushButton::clicked, this, &MainWindow::startClamAvDefinitionUpdate);
    connect(m_themeComboBox, &QComboBox::currentTextChanged, this, &MainWindow::applyTheme);

    return tab;
}

void MainWindow::createTrayIcon()
{
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        return;
    }

    m_trayMenu = new QMenu(this);
    QAction *openAction = m_trayMenu->addAction(tr("Open Warden"));
    QAction *quickScanAction = m_trayMenu->addAction(tr("Quick Scan"));
    m_trayMenu->addSeparator();
    QAction *exitAction = m_trayMenu->addAction(tr("Exit"));

    m_trayIcon = new QSystemTrayIcon(windowIcon(), this);
    m_trayIcon->setToolTip(tr("Warden Free"));
    m_trayIcon->setContextMenu(m_trayMenu);

    connect(openAction, &QAction::triggered, this, &MainWindow::showAndRaiseWindow);
    connect(quickScanAction, &QAction::triggered, this, &MainWindow::quickScan);
    connect(exitAction, &QAction::triggered, this, &MainWindow::exitApplication);
    connect(m_trayIcon, &QSystemTrayIcon::activated, this, &MainWindow::handleTrayIconActivated);

    m_trayIcon->show();
}

void MainWindow::initializeUiState()
{
    std::string stateError;
    m_stateStore.initialize(stateError);

    m_fileScanTargetEdit->setText(toQString(warden::core::AppPaths::projectRoot()));
    m_quarantinePathLabel->setText(tr("Quarantine directory: %1").arg(toQString(warden::core::AppPaths::quarantineDirectory())));
    m_themeComboBox->setCurrentText(tr("Warden Dark"));
    applyTheme(m_themeComboBox->currentText());
    handleFileProfileChanged();

    const std::string storedDefinitionsStatus = m_stateStore.statusSnapshotValue("definitions_status");
    if (!storedDefinitionsStatus.empty()) {
        m_clamAvUpdateStatusLabel->setText(QString::fromStdString(storedDefinitionsStatus));
    } else if (!stateError.empty()) {
        m_clamAvUpdateStatusLabel->setText(tr("State store unavailable: %1").arg(QString::fromStdString(stateError)));
    }

    refreshHistoryData();
    refreshExclusionData();
    refreshQuarantineData();
    updateHomeSummary();
}

void MainWindow::applyTheme(const QString &themeName)
{
    if (themeName == tr("Warden Dark")) {
        qApp->setStyleSheet(darkStylesheet());
    } else if (themeName == tr("Clean Light")) {
        qApp->setStyleSheet(lightStylesheet());
    } else {
        qApp->setStyleSheet(QString());
    }
}

void MainWindow::showAndRaiseWindow()
{
    if (isMinimized()) {
        showNormal();
    } else {
        show();
    }

    raise();
    activateWindow();
}

void MainWindow::quickScan()
{
    m_tabWidget->setCurrentWidget(m_fileScanTab);
    startQuickFileScan();
}

void MainWindow::exitApplication()
{
    m_allowClose = true;

    if (m_trayIcon != nullptr) {
        m_trayIcon->hide();
    }

    QApplication::quit();
}

void MainWindow::handleTrayIconActivated(const QSystemTrayIcon::ActivationReason reason)
{
    if (reason == QSystemTrayIcon::DoubleClick) {
        showAndRaiseWindow();
    }
}

void MainWindow::browseFileScanTarget()
{
    const QString selectedDirectory = QFileDialog::getExistingDirectory(this,
                                                                        tr("Select Scan Target"),
                                                                        m_fileScanTargetEdit->text());
    if (!selectedDirectory.isEmpty()) {
        m_fileScanTargetEdit->setText(selectedDirectory);
    }
}

void MainWindow::handleFileProfileChanged()
{
    const auto mode = static_cast<warden::core::ScanMode>(m_fileScanProfileCombo->currentData().toInt());
    const bool isCustom = mode == warden::core::ScanMode::Custom;

    const QSignalBlocker clamAvBlocker(m_fileScanClamAvCheckBox);
    const QSignalBlocker heuristicBlocker(m_fileScanHeuristicCheckBox);

    if (isCustom) {
        m_fileScanClamAvCheckBox->setChecked(true);
        m_fileScanHeuristicCheckBox->setChecked(true);
    } else if (mode == warden::core::ScanMode::SignatureOnly) {
        m_fileScanClamAvCheckBox->setChecked(true);
        m_fileScanHeuristicCheckBox->setChecked(false);
    } else if (mode == warden::core::ScanMode::HeuristicOnly) {
        m_fileScanClamAvCheckBox->setChecked(false);
        m_fileScanHeuristicCheckBox->setChecked(true);
    } else {
        m_fileScanClamAvCheckBox->setChecked(true);
        m_fileScanHeuristicCheckBox->setChecked(true);
    }

    m_fileScanClamAvCheckBox->setEnabled(isCustom);
    m_fileScanHeuristicCheckBox->setEnabled(isCustom);
}

void MainWindow::startConfiguredFileScan()
{
    const auto mode = static_cast<warden::core::ScanMode>(m_fileScanProfileCombo->currentData().toInt());
    startFileScan(mode, false);
}

void MainWindow::startQuickFileScan()
{
    startFileScan(warden::core::ScanMode::Quick, true);
}

void MainWindow::startFullFileScan()
{
    startFileScan(warden::core::ScanMode::Full, true);
}

void MainWindow::startFileScan(const warden::core::ScanMode mode, const bool overrideProfile)
{
    if (m_fileScanThread != nullptr) {
        QMessageBox::information(this, tr("Filesystem Scan"), tr("A filesystem scan is already running."));
        return;
    }

    if (m_fileScanTargetEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Filesystem Scan"), tr("Choose a scan target before starting the scan."));
        return;
    }

    const warden::core::ScanOptions options = buildFileScanOptions(mode, overrideProfile);
    if (!options.enableClamAv && !options.enableHeuristics) {
        QMessageBox::warning(this,
                             tr("Filesystem Scan"),
                             tr("Enable ClamAV and/or Heuristics before starting a custom scan."));
        return;
    }

    m_tabWidget->setCurrentWidget(m_fileScanTab);
    m_fileScanStatusLabel->setText(tr("Starting %1 filesystem scan ...").arg(modeText(options.mode)));
    m_fileScanCurrentItemLabel->setText(tr("Current item: preparing scan target"));
    m_fileScanCountersLabel->setText(tr("Scanned: 0 | Total: 0 | Results: 0"));
    m_fileScanEnginesLabel->setText(tr("Active engines: %1").arg(activeEnginesText(options.enableClamAv,
                                                                                   options.enableHeuristics)));
    m_fileScanProgressBar->setRange(0, 0);
    m_fileScanProgressBar->setValue(0);
    m_fileScanRunButton->setEnabled(false);
    m_fileScanQuickButton->setEnabled(false);
    m_fileScanFullButton->setEnabled(false);
    m_fileScanCancelButton->setEnabled(true);
    m_homeQuickScanButton->setEnabled(false);
    m_homeFullScanButton->setEnabled(false);

    m_lastScanHistoryId = 0;
    m_fileScanCancelFlag = std::make_shared<std::atomic_bool>(false);
    m_fileScanThread = new QThread(this);
    m_fileScanWorker = new warden::scanner::FileScanWorker(options, m_fileScanCancelFlag);
    m_fileScanWorker->moveToThread(m_fileScanThread);

    connect(m_fileScanThread, &QThread::started, m_fileScanWorker, &warden::scanner::FileScanWorker::run);
    connect(m_fileScanWorker,
            &warden::scanner::FileScanWorker::progressChanged,
            this,
            &MainWindow::handleFileScanProgress);
    connect(m_fileScanWorker,
            &warden::scanner::FileScanWorker::finished,
            this,
            &MainWindow::handleFileScanFinished);
    connect(m_fileScanWorker, &warden::scanner::FileScanWorker::finished, m_fileScanThread, &QThread::quit);
    connect(m_fileScanThread, &QThread::finished, m_fileScanWorker, &QObject::deleteLater);
    connect(m_fileScanThread, &QThread::finished, m_fileScanThread, &QObject::deleteLater);
    connect(m_fileScanThread, &QThread::finished, this, [this]() {
        m_fileScanThread = nullptr;
        m_fileScanWorker = nullptr;
        m_fileScanCancelFlag.reset();
    });

    m_fileScanThread->start();
}

void MainWindow::cancelFileScan()
{
    if (m_fileScanCancelFlag != nullptr) {
        m_fileScanCancelFlag->store(true);
        m_fileScanStatusLabel->setText(tr("Cancelling filesystem scan ..."));
    }
}

warden::core::ScanOptions MainWindow::buildFileScanOptions(const warden::core::ScanMode mode,
                                                           const bool overrideProfile) const
{
    const auto effectiveMode = overrideProfile
        ? mode
        : static_cast<warden::core::ScanMode>(m_fileScanProfileCombo->currentData().toInt());

    warden::core::ScanOptions options;
    options.targetPath = std::filesystem::path(m_fileScanTargetEdit->text().toStdString());
    options.mode = effectiveMode;
    options.clamAvDatabasePath = warden::network::DefinitionUpdater::preferredDatabaseDirectory();
    options.quarantineDirectory = warden::core::AppPaths::quarantineDirectory();
    options.enableCustomDat = false;
    options.enableScriptActivity = false;
    options.enablePupScan = false;

    switch (effectiveMode) {
    case warden::core::ScanMode::Quick:
    case warden::core::ScanMode::Full:
        options.enableClamAv = true;
        options.enableHeuristics = true;
        break;
    case warden::core::ScanMode::SignatureOnly:
        options.enableClamAv = true;
        options.enableHeuristics = false;
        break;
    case warden::core::ScanMode::HeuristicOnly:
        options.enableClamAv = false;
        options.enableHeuristics = true;
        break;
    case warden::core::ScanMode::Custom:
        options.enableClamAv = m_fileScanClamAvCheckBox->isChecked();
        options.enableHeuristics = m_fileScanHeuristicCheckBox->isChecked();
        break;
    }

    return options;
}

void MainWindow::handleFileScanProgress(const QString &phase,
                                        const QString &currentItem,
                                        const int scannedFiles,
                                        const int totalFiles,
                                        const int threatsFound,
                                        const bool indeterminate,
                                        const QStringList &activeEngines)
{
    if (indeterminate || totalFiles <= 0) {
        m_fileScanProgressBar->setRange(0, 0);
    } else {
        m_fileScanProgressBar->setRange(0, 100);
        m_fileScanProgressBar->setValue((scannedFiles * 100) / std::max(1, totalFiles));
    }

    m_fileScanStatusLabel->setText(tr("Phase: %1").arg(phase));
    m_fileScanCurrentItemLabel->setText(tr("Current item: %1").arg(currentItem));
    m_fileScanCountersLabel->setText(tr("Scanned: %1 | Total: %2 | Results: %3")
                                         .arg(scannedFiles)
                                         .arg(totalFiles)
                                         .arg(threatsFound));
    m_fileScanEnginesLabel->setText(tr("Active engines: %1").arg(activeEngines.join(QStringLiteral(", "))));
    m_homeFileScanStatusLabel->setText(tr("Filesystem scan running: %1").arg(phase));
}

void MainWindow::handleFileScanFinished(const warden::core::ScanReport &report)
{
    m_fileScanRunButton->setEnabled(true);
    m_fileScanQuickButton->setEnabled(true);
    m_fileScanFullButton->setEnabled(true);
    m_fileScanCancelButton->setEnabled(false);
    m_homeQuickScanButton->setEnabled(true);
    m_homeFullScanButton->setEnabled(true);
    m_fileScanProgressBar->setRange(0, 100);
    m_fileScanProgressBar->setValue(report.canceled ? 0 : 100);

    m_lastFileScanReport = report;
    if (m_lastFileScanReport->records.empty()) {
        m_lastFileScanReport->records = warden::core::aggregateThreatFindings(m_lastFileScanReport->findings);
    }
    m_recordStatuses.assign(m_lastFileScanReport->records.size(), tr("Pending review"));

    m_fileScanStatusLabel->setText(
        report.canceled
            ? tr("Scan canceled during %1.").arg(toQString(report.cancelPhase))
            : tr("Completed %1 scan.").arg(modeText(report.options.mode))
    );
    m_fileScanCurrentItemLabel->setText(
        tr("Last target: %1").arg(toQString(report.options.targetPath))
    );
    m_fileScanCountersLabel->setText(
        tr("Scanned: %1 | Results: %2 | Warnings: %3")
            .arg(report.stats.scannedFiles)
            .arg(m_lastFileScanReport->records.size())
            .arg(report.warnings.size())
    );
    m_fileScanEnginesLabel->setText(
        tr("Active engines: %1").arg(activeEnginesText(report.options.enableClamAv,
                                                       report.options.enableHeuristics))
    );

    const QString summary = reportSummaryText(*m_lastFileScanReport);
    m_fileScanSummaryLabel->setText(summary);

    std::string errorMessage;
    const warden::storage::ScanHistoryEntry entry {
        0,
        "filesystem",
        warden::core::toString(report.options.mode),
        report.startedAtUtc,
        report.completedAtUtc,
        report.durationMs,
        report.stats.scannedFiles,
        m_lastFileScanReport->records.size(),
        report.warnings.size(),
        "",
        summary.toStdString(),
        findingsToJsonBytes(report.findings).toStdString(),
        warningsToJsonBytes(report.warnings).toStdString()
    };
    m_lastScanHistoryId = m_stateStore.recordScan(entry, errorMessage);

    std::string snapshotError;
    m_stateStore.setStatusSnapshot("last_scan_status", summary.toStdString(), snapshotError);
    m_stateStore.setStatusSnapshot("last_threat_status",
                                   tr("ClamAV loaded: %1 | Signatures: %2")
                                       .arg(report.clamAvLoaded ? tr("yes") : tr("no"))
                                       .arg(report.clamAvSignatures)
                                       .toStdString(),
                                   snapshotError);

    refreshFileWorkspaceViews();

    if (report.canceled) {
        showTrayNotification(tr("Scan Canceled"),
                             tr("Filesystem scan was canceled during %1.").arg(toQString(report.cancelPhase)),
                             QSystemTrayIcon::Information);
    } else if (!m_lastFileScanReport->records.empty()) {
        showTrayNotification(tr("Findings Detected"),
                             tr("%1 file result(s) require review.").arg(m_lastFileScanReport->records.size()),
                             QSystemTrayIcon::Warning);
    } else {
        showTrayNotification(tr("Scan Complete"),
                             tr("Filesystem scan completed with no findings."),
                             QSystemTrayIcon::Information);
    }
}

void MainWindow::populateThreatTable()
{
    m_threatTable->clearContents();
    m_visibleThreatIndices.clear();

    if (!m_lastFileScanReport.has_value()) {
        m_threatTable->setRowCount(0);
        return;
    }

    const QString classFilter = m_fileClassFilterCombo->currentText();
    const QString severityFilter = m_fileSeverityFilterCombo->currentText();
    const QString engineFilter = m_fileEngineFilterCombo->currentText();
    const QString extensionFilter = m_fileExtensionFilterCombo->currentText();

    int row = 0;
    m_threatTable->setRowCount(0);
    for (int index = 0; index < static_cast<int>(m_lastFileScanReport->records.size()); ++index) {
        const auto &record = m_lastFileScanReport->records.at(static_cast<std::size_t>(index));
        if (recordMatchesExclusion(m_stateStore, record)) {
            continue;
        }

        const QString recordClass = categoryText(record.classification);
        const QString recordSeverity = severityText(record.severity);
        const QString recordEngines = joinStrings(record.detectionEngines);
        const QString recordExtension = record.path.extension().empty()
            ? tr("(none)")
            : toQString(record.path.extension());

        if (classFilter != tr("All Classes") && recordClass != classFilter) {
            continue;
        }
        if (severityFilter != tr("All Severities") && recordSeverity != severityFilter) {
            continue;
        }
        if (engineFilter != tr("All Engines") && !recordEngines.contains(engineFilter, Qt::CaseInsensitive)) {
            continue;
        }
        if (extensionFilter != tr("All Extensions") && recordExtension != extensionFilter) {
            continue;
        }

        m_threatTable->insertRow(row);
        m_visibleThreatIndices.push_back(index);

        auto *nameItem = new QTableWidgetItem(toQString(record.name));
        auto *pathItem = new QTableWidgetItem(toQString(record.path));
        auto *classItem = new QTableWidgetItem(recordClass);
        auto *severityItem = new QTableWidgetItem(recordSeverity);
        auto *enginesItem = new QTableWidgetItem(recordEngines);
        auto *confidenceItem = new QTableWidgetItem(QString::number(record.confidenceScore * 100.0, 'f', 1) + QLatin1String("%"));
        auto *statusItem = new QTableWidgetItem(m_recordStatuses.at(static_cast<std::size_t>(index)));

        severityItem->setBackground(severityColor(record.severity));

        m_threatTable->setItem(row, 0, nameItem);
        m_threatTable->setItem(row, 1, pathItem);
        m_threatTable->setItem(row, 2, classItem);
        m_threatTable->setItem(row, 3, severityItem);
        m_threatTable->setItem(row, 4, enginesItem);
        m_threatTable->setItem(row, 5, confidenceItem);
        m_threatTable->setItem(row, 6, statusItem);

        auto *actionCombo = new QComboBox(m_threatTable);
        actionCombo->addItems(actionChoices());
        connect(actionCombo, &QComboBox::currentTextChanged, this, [this, row](const QString &actionText) {
            handleThreatActionChanged(row, actionText);
        });
        m_threatTable->setCellWidget(row, 7, actionCombo);

        ++row;
    }

    if (m_threatTable->rowCount() > 0) {
        m_threatTable->selectRow(0);
    } else {
        m_threatDetailsText->clear();
    }
}

void MainWindow::populateHistoryTable()
{
    m_scanHistoryTable->clearContents();
    m_scanHistoryTable->setRowCount(static_cast<int>(m_scanHistoryEntries.size()));

    for (int row = 0; row < static_cast<int>(m_scanHistoryEntries.size()); ++row) {
        const auto &entry = m_scanHistoryEntries.at(static_cast<std::size_t>(row));
        m_scanHistoryTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry.completedAtUtc)));
        m_scanHistoryTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(entry.profile)));
        m_scanHistoryTable->setItem(row, 2, new QTableWidgetItem(QString::number(static_cast<qulonglong>(entry.itemCount))));
        m_scanHistoryTable->setItem(row, 3, new QTableWidgetItem(QString::number(static_cast<qulonglong>(entry.threatCount))));
        m_scanHistoryTable->setItem(row, 4, new QTableWidgetItem(QString::number(static_cast<qulonglong>(entry.warningCount))));
        m_scanHistoryTable->setItem(row, 5, new QTableWidgetItem(formatDuration(entry.durationMs)));
        m_scanHistoryTable->setItem(row, 6, new QTableWidgetItem(QString::fromStdString(entry.summaryText)));
    }
}

void MainWindow::populateExclusionsTable()
{
    m_exclusionsTable->clearContents();
    m_exclusionsTable->setRowCount(static_cast<int>(m_exclusionEntries.size()));

    for (int row = 0; row < static_cast<int>(m_exclusionEntries.size()); ++row) {
        const auto &entry = m_exclusionEntries.at(static_cast<std::size_t>(row));
        m_exclusionsTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry.matchType)));
        m_exclusionsTable->setItem(row, 1, new QTableWidgetItem(QString::fromStdString(entry.matchValue)));
        m_exclusionsTable->setItem(row, 2, new QTableWidgetItem(QString::fromStdString(entry.label)));
        m_exclusionsTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(entry.createdAtUtc)));
    }
}

void MainWindow::populateQuarantineTable()
{
    m_quarantineTable->clearContents();
    m_quarantineTable->setRowCount(static_cast<int>(m_quarantineEntries.size()));

    for (int row = 0; row < static_cast<int>(m_quarantineEntries.size()); ++row) {
        const auto &entry = m_quarantineEntries.at(static_cast<std::size_t>(row));
        m_quarantineTable->setItem(row, 0, new QTableWidgetItem(QString::fromStdString(entry.threatName)));
        m_quarantineTable->setItem(row, 1, new QTableWidgetItem(toQString(entry.originalPath)));
        m_quarantineTable->setItem(row, 2, new QTableWidgetItem(toQString(entry.quarantinedPath)));
        m_quarantineTable->setItem(row, 3, new QTableWidgetItem(QString::fromStdString(entry.status)));
        m_quarantineTable->setItem(row, 4, new QTableWidgetItem(QString::fromStdString(entry.createdAtUtc)));
        m_quarantineTable->setItem(row, 5, new QTableWidgetItem(QString::fromStdString(entry.restoredAtUtc)));
    }
}

void MainWindow::handleThreatActionChanged(const int recordIndex, const QString &actionText)
{
    if (actionText == QStringLiteral("Select Action")) {
        return;
    }

    const int sourceIndex = sourceThreatIndexForRow(recordIndex);
    if (sourceIndex < 0) {
        return;
    }

    if (actionText == tr("View Details")) {
        m_threatTable->selectRow(recordIndex);
        updateThreatDetails(sourceIndex);
    } else if (actionText == tr("Quarantine")) {
        quarantineThreat(sourceIndex);
    } else if (actionText == tr("Ignore")) {
        applyThreatStatuses({sourceIndex}, tr("Ignored by operator"), tr("ignored"));
    } else if (actionText == tr("Mark Reviewed")) {
        applyThreatStatuses({sourceIndex}, tr("Reviewed by operator"), tr("reviewed"));
    } else if (actionText == tr("Exclude File")) {
        QString statusText;
        if (addThreatRecordToExclusion(sourceIndex, false, statusText)) {
            applyThreatStatuses({sourceIndex}, statusText, tr("excluded"));
        }
    } else if (actionText == tr("Exclude Folder")) {
        QString statusText;
        if (addThreatRecordToExclusion(sourceIndex, true, statusText)) {
            applyThreatStatuses({sourceIndex}, statusText, tr("excluded"));
        }
    }

    if (auto *actionCombo = qobject_cast<QComboBox *>(m_threatTable->cellWidget(recordIndex, 7))) {
        const QSignalBlocker blocker(actionCombo);
        actionCombo->setCurrentIndex(0);
    }
}

void MainWindow::handleThreatSelectionChanged()
{
    const auto selectedRows = m_threatTable->selectionModel()->selectedRows();
    if (selectedRows.isEmpty()) {
        m_threatDetailsText->clear();
        return;
    }

    updateThreatDetails(sourceThreatIndexForRow(selectedRows.front().row()));
}

void MainWindow::updateThreatDetails(const int recordIndex)
{
    if (!m_lastFileScanReport.has_value() ||
        recordIndex < 0 ||
        recordIndex >= static_cast<int>(m_lastFileScanReport->records.size())) {
        m_threatDetailsText->clear();
        return;
    }

    const auto &record = m_lastFileScanReport->records.at(static_cast<std::size_t>(recordIndex));
    QString details;
    details += tr("Threat: %1\n").arg(toQString(record.name));
    details += tr("Path: %1\n").arg(toQString(record.path));
    details += tr("Class: %1\n").arg(categoryText(record.classification));
    details += tr("Severity: %1\n").arg(severityText(record.severity));
    details += tr("Detection method: %1\n").arg(detectionSourceText(record.detectionSource));
    details += tr("Engines: %1\n").arg(joinStrings(record.detectionEngines));
    details += tr("SHA-256: %1\n").arg(toQString(record.sha256));
    details += tr("Confidence: %1%\n").arg(QString::number(record.confidenceScore * 100.0, 'f', 1));
    details += tr("File size: %1 bytes\n").arg(static_cast<qulonglong>(record.fileSize));
    details += tr("Entropy: %1\n").arg(QString::number(record.entropy, 'f', 2));
    details += tr("Recommended action: %1\n\n").arg(toQString(record.recommendedAction));

    if (!record.operatorSummary.empty()) {
        details += tr("Operator summary:\n%1\n\n").arg(toQString(record.operatorSummary));
    }
    if (!record.description.empty()) {
        details += tr("Description:\n%1\n\n").arg(toQString(record.description));
    }
    if (!record.triggeredRules.empty()) {
        details += tr("Triggered rules:\n");
        for (const auto &rule : record.triggeredRules) {
            details += tr(" - %1\n").arg(toQString(rule));
        }
        details += QLatin1Char('\n');
    }
    if (!record.evidence.empty()) {
        details += tr("Evidence:\n");
        for (const auto &evidenceLine : record.evidence) {
            details += tr(" - %1\n").arg(toQString(evidenceLine));
        }
    }

    m_threatDetailsText->setPlainText(details.trimmed());
}

void MainWindow::applyThreatFilters()
{
    populateThreatTable();
    updateFileScanSummary();
}

void MainWindow::refreshThreatFilterOptions()
{
    const QString previousClass = m_fileClassFilterCombo->currentText();
    const QString previousSeverity = m_fileSeverityFilterCombo->currentText();
    const QString previousEngine = m_fileEngineFilterCombo->currentText();
    const QString previousExtension = m_fileExtensionFilterCombo->currentText();

    const QSignalBlocker classBlocker(m_fileClassFilterCombo);
    const QSignalBlocker severityBlocker(m_fileSeverityFilterCombo);
    const QSignalBlocker engineBlocker(m_fileEngineFilterCombo);
    const QSignalBlocker extensionBlocker(m_fileExtensionFilterCombo);

    std::set<QString> classes;
    std::set<QString> severities;
    std::set<QString> engines;
    std::set<QString> extensions;

    if (m_lastFileScanReport.has_value()) {
        for (const auto &record : m_lastFileScanReport->records) {
            if (recordMatchesExclusion(m_stateStore, record)) {
                continue;
            }
            classes.insert(categoryText(record.classification));
            severities.insert(severityText(record.severity));
            for (const auto &engine : record.detectionEngines) {
                if (!engine.empty()) {
                    engines.insert(QString::fromStdString(engine));
                }
            }
            extensions.insert(record.path.extension().empty() ? tr("(none)") : toQString(record.path.extension()));
        }
    }

    m_fileClassFilterCombo->clear();
    m_fileSeverityFilterCombo->clear();
    m_fileEngineFilterCombo->clear();
    m_fileExtensionFilterCombo->clear();

    m_fileClassFilterCombo->addItem(tr("All Classes"));
    m_fileSeverityFilterCombo->addItem(tr("All Severities"));
    m_fileEngineFilterCombo->addItem(tr("All Engines"));
    m_fileExtensionFilterCombo->addItem(tr("All Extensions"));

    for (const auto &value : classes) {
        m_fileClassFilterCombo->addItem(value);
    }
    for (const auto &value : severities) {
        m_fileSeverityFilterCombo->addItem(value);
    }
    for (const auto &value : engines) {
        m_fileEngineFilterCombo->addItem(value);
    }
    for (const auto &value : extensions) {
        m_fileExtensionFilterCombo->addItem(value);
    }

    const auto restoreSelection = [](QComboBox *combo, const QString &value) {
        const int index = combo->findText(value);
        combo->setCurrentIndex(index >= 0 ? index : 0);
    };

    restoreSelection(m_fileClassFilterCombo, previousClass);
    restoreSelection(m_fileSeverityFilterCombo, previousSeverity);
    restoreSelection(m_fileEngineFilterCombo, previousEngine);
    restoreSelection(m_fileExtensionFilterCombo, previousExtension);
}

void MainWindow::updateFileScanSummary()
{
    if (!m_lastFileScanReport.has_value()) {
        m_fileScanSummaryLabel->setText(tr("No filesystem report loaded."));
        return;
    }

    m_fileScanSummaryLabel->setText(
        tr("Visible results: %1 | Total results: %2 | Warnings: %3 | Duration: %4")
            .arg(m_threatTable->rowCount())
            .arg(m_lastFileScanReport->records.size())
            .arg(m_lastFileScanReport->warnings.size())
            .arg(formatDuration(m_lastFileScanReport->durationMs))
    );
}

int MainWindow::sourceThreatIndexForRow(const int recordIndex) const
{
    if (recordIndex < 0 || recordIndex >= static_cast<int>(m_visibleThreatIndices.size())) {
        return -1;
    }

    return m_visibleThreatIndices.at(static_cast<std::size_t>(recordIndex));
}

std::vector<int> MainWindow::selectedThreatSourceIndices() const
{
    std::vector<int> indices;
    if (m_threatTable->selectionModel() == nullptr) {
        return indices;
    }

    std::set<int> unique;
    for (const QModelIndex &index : m_threatTable->selectionModel()->selectedRows()) {
        const int sourceIndex = sourceThreatIndexForRow(index.row());
        if (sourceIndex >= 0) {
            unique.insert(sourceIndex);
        }
    }

    indices.assign(unique.begin(), unique.end());
    return indices;
}

void MainWindow::applyThreatStatuses(const std::vector<int> &sourceIndices,
                                     const QString &statusText,
                                     const QString &actionText)
{
    if (!m_lastFileScanReport.has_value()) {
        return;
    }

    for (const int sourceIndex : sourceIndices) {
        if (sourceIndex < 0 || sourceIndex >= static_cast<int>(m_recordStatuses.size())) {
            continue;
        }

        m_recordStatuses[static_cast<std::size_t>(sourceIndex)] = statusText;
        const auto &record = m_lastFileScanReport->records.at(static_cast<std::size_t>(sourceIndex));
        recordFileAction(toQString(record.id), actionText, statusText);
    }

    populateThreatTable();
    updateFileScanSummary();
}

bool MainWindow::addThreatRecordToExclusion(const int recordIndex,
                                            const bool excludeParentFolder,
                                            QString &statusText)
{
    if (!m_lastFileScanReport.has_value() ||
        recordIndex < 0 ||
        recordIndex >= static_cast<int>(m_lastFileScanReport->records.size())) {
        return false;
    }

    const auto &record = m_lastFileScanReport->records.at(static_cast<std::size_t>(recordIndex));
    warden::storage::ExclusionEntry entry;
    if (excludeParentFolder) {
        const std::filesystem::path parentPath = record.path.parent_path();
        if (parentPath.empty()) {
            QMessageBox::warning(this, tr("Exclusions"), tr("The selected finding does not have a parent folder to exclude."));
            return false;
        }
        entry.matchType = "path_prefix";
        entry.matchValue = parentPath.lexically_normal().generic_string();
        entry.label = "Parent folder: " + parentPath.filename().string();
        statusText = tr("Excluded parent folder");
    } else if (!record.path.empty()) {
        entry.matchType = "path";
        entry.matchValue = record.path.lexically_normal().generic_string();
        entry.label = "File: " + record.path.filename().string();
        statusText = tr("Excluded file");
    } else if (!record.sha256.empty()) {
        entry.matchType = "sha256";
        entry.matchValue = record.sha256;
        entry.label = "Hash: " + record.name;
        statusText = tr("Excluded SHA-256");
    } else {
        QMessageBox::warning(this, tr("Exclusions"), tr("The selected finding does not have a stable path or SHA-256 to exclude."));
        return false;
    }

    std::string errorMessage;
    if (!m_stateStore.addExclusion(entry, errorMessage)) {
        QMessageBox::warning(this,
                             tr("Exclusions"),
                             tr("Failed to add exclusion: %1").arg(QString::fromStdString(errorMessage)));
        return false;
    }

    refreshExclusionData();
    recordFileAction(toQString(record.id), tr("excluded"), statusText);
    applyThreatFilters();
    return true;
}

void MainWindow::ignoreSelectedThreats()
{
    const auto indices = selectedThreatSourceIndices();
    if (indices.empty()) {
        return;
    }

    applyThreatStatuses(indices, tr("Ignored by operator"), tr("ignored"));
}

void MainWindow::markSelectedThreatsReviewed()
{
    const auto indices = selectedThreatSourceIndices();
    if (indices.empty()) {
        return;
    }

    applyThreatStatuses(indices, tr("Reviewed by operator"), tr("reviewed"));
}

void MainWindow::addSelectedThreatsToExclusions()
{
    const auto indices = selectedThreatSourceIndices();
    if (indices.empty()) {
        return;
    }

    for (const int index : indices) {
        QString statusText;
        if (addThreatRecordToExclusion(index, false, statusText) &&
            index >= 0 &&
            index < static_cast<int>(m_recordStatuses.size())) {
            m_recordStatuses[static_cast<std::size_t>(index)] = statusText;
        }
    }

    populateThreatTable();
}

void MainWindow::exportFindingsToCsv()
{
    exportThreatRecordsToCsv(m_visibleThreatIndices, QStringLiteral("warden-free-findings"), tr("Export Visible Findings"));
}

void MainWindow::exportSelectedFindings()
{
    exportThreatRecordsToCsv(selectedThreatSourceIndices(), QStringLiteral("warden-free-selected"), tr("Export Selected Findings"));
}

void MainWindow::exportThreatRecordsToCsv(const std::vector<int> &sourceIndices,
                                          const QString &defaultNamePrefix,
                                          const QString &dialogTitle)
{
    if (!m_lastFileScanReport.has_value() || sourceIndices.empty()) {
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(this,
                                                          dialogTitle,
                                                          defaultNamePrefix + QStringLiteral(".csv"),
                                                          tr("CSV Files (*.csv)"));
    if (filePath.isEmpty()) {
        return;
    }

    QSaveFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Export"), tr("Unable to open %1 for writing.").arg(filePath));
        return;
    }

    QTextStream stream(&file);
    stream << "threat,path,class,severity,engines,confidence,sha256,recommended_action,status\n";
    for (const int index : sourceIndices) {
        if (index < 0 || index >= static_cast<int>(m_lastFileScanReport->records.size())) {
            continue;
        }
        const auto &record = m_lastFileScanReport->records.at(static_cast<std::size_t>(index));
        stream << csvEscape(toQString(record.name)) << ','
               << csvEscape(toQString(record.path)) << ','
               << csvEscape(categoryText(record.classification)) << ','
               << csvEscape(severityText(record.severity)) << ','
               << csvEscape(joinStrings(record.detectionEngines)) << ','
               << csvEscape(QString::number(record.confidenceScore * 100.0, 'f', 1)) << ','
               << csvEscape(toQString(record.sha256)) << ','
               << csvEscape(toQString(record.recommendedAction)) << ','
               << csvEscape(m_recordStatuses.at(static_cast<std::size_t>(index)))
               << '\n';
    }

    if (!file.commit()) {
        QMessageBox::warning(this, tr("Export"), tr("Failed to write %1.").arg(filePath));
    }
}

void MainWindow::saveCurrentReport()
{
    if (!m_lastFileScanReport.has_value()) {
        QMessageBox::information(this, tr("Save Report"), tr("There is no report to save."));
        return;
    }

    const QString filePath = QFileDialog::getSaveFileName(this,
                                                          tr("Save Report"),
                                                          QStringLiteral("warden-free-report.json"),
                                                          tr("JSON Files (*.json)"));
    if (filePath.isEmpty()) {
        return;
    }

    QSaveFile file(filePath);
    if (!file.open(QIODevice::WriteOnly | QIODevice::Truncate | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Save Report"), tr("Unable to open %1 for writing.").arg(filePath));
        return;
    }

    file.write(reportToJsonBytes(*m_lastFileScanReport));
    if (!file.commit()) {
        QMessageBox::warning(this, tr("Save Report"), tr("Failed to save %1.").arg(filePath));
    }
}

void MainWindow::loadSavedReport()
{
    const QString filePath = QFileDialog::getOpenFileName(this,
                                                          tr("Load Report"),
                                                          QString(),
                                                          tr("JSON Files (*.json)"));
    if (filePath.isEmpty()) {
        return;
    }

    QFile file(filePath);
    if (!file.open(QIODevice::ReadOnly | QIODevice::Text)) {
        QMessageBox::warning(this, tr("Load Report"), tr("Unable to open %1.").arg(filePath));
        return;
    }

    QString error;
    const auto report = reportFromJsonBytes(file.readAll(), error);
    if (!report.has_value()) {
        QMessageBox::warning(this, tr("Load Report"), tr("Failed to parse report: %1").arg(error));
        return;
    }

    m_lastFileScanReport = *report;
    m_recordStatuses.assign(m_lastFileScanReport->records.size(), tr("Loaded from saved report"));
    m_lastScanHistoryId = 0;
    refreshThreatFilterOptions();
    applyThreatFilters();
    updateHomeSummary();
}

void MainWindow::quarantineThreat(const int recordIndex)
{
    if (!m_lastFileScanReport.has_value() ||
        recordIndex < 0 ||
        recordIndex >= static_cast<int>(m_lastFileScanReport->records.size())) {
        return;
    }

    const auto &record = m_lastFileScanReport->records.at(static_cast<std::size_t>(recordIndex));
    const auto finding = representativeFinding(record);

    warden::scanner::QuarantineManager manager(warden::core::AppPaths::quarantineDirectory());
    const auto result = manager.quarantine(finding);
    if (!result.success) {
        QMessageBox::warning(this, tr("Quarantine"), tr("Failed to quarantine file: %1").arg(toQString(result.error)));
        return;
    }

    std::string errorMessage;
    m_stateStore.recordQuarantineEntry(warden::storage::QuarantineCatalogEntry {
                                           0,
                                           record.id,
                                           finding.path,
                                           result.quarantinedPath,
                                           result.metadataPath,
                                           finding.sha256,
                                           finding.name,
                                           "quarantined",
                                           "",
                                           "",
                                           {}
                                       },
                                       errorMessage);

    applyThreatStatuses({recordIndex},
                        tr("Quarantined to %1").arg(toQString(result.quarantinedPath.filename())),
                        tr("quarantined"));
    refreshQuarantineData();
}

void MainWindow::removeSelectedExclusions()
{
    const auto selectedRows = m_exclusionsTable->selectionModel()->selectedRows();
    if (selectedRows.isEmpty()) {
        return;
    }

    std::string errorMessage;
    for (const QModelIndex &index : selectedRows) {
        const int row = index.row();
        if (row < 0 || row >= static_cast<int>(m_exclusionEntries.size())) {
            continue;
        }
        m_stateStore.removeExclusion(m_exclusionEntries.at(static_cast<std::size_t>(row)).id, errorMessage);
    }

    refreshExclusionData();
    applyThreatFilters();
}

void MainWindow::restoreSelectedQuarantine()
{
    const auto selectedRows = m_quarantineTable->selectionModel()->selectedRows();
    if (selectedRows.isEmpty()) {
        return;
    }

    const int row = selectedRows.front().row();
    if (row < 0 || row >= static_cast<int>(m_quarantineEntries.size())) {
        return;
    }

    const auto &entry = m_quarantineEntries.at(static_cast<std::size_t>(row));
    if (entry.status == "restored") {
        QMessageBox::information(this, tr("Quarantine"), tr("The selected item has already been restored."));
        return;
    }

    warden::scanner::QuarantineManager manager(warden::core::AppPaths::quarantineDirectory());
    const auto result = manager.restore(entry.quarantinedPath, entry.originalPath);
    if (!result.success) {
        QMessageBox::warning(this, tr("Quarantine"), tr("Failed to restore file: %1").arg(toQString(result.error)));
        return;
    }

    std::string errorMessage;
    m_stateStore.markQuarantineRestored(entry.quarantinedPath, result.restoredPath, errorMessage);
    refreshQuarantineData();
}

void MainWindow::refreshHistoryData()
{
    m_scanHistoryEntries = m_stateStore.listScanHistory(100);
    populateHistoryTable();
}

void MainWindow::refreshExclusionData()
{
    m_exclusionEntries = m_stateStore.listExclusions();
    populateExclusionsTable();
}

void MainWindow::refreshQuarantineData()
{
    m_quarantinePathLabel->setText(tr("Quarantine directory: %1").arg(toQString(warden::core::AppPaths::quarantineDirectory())));
    m_quarantineEntries = m_stateStore.listQuarantineEntries();
    populateQuarantineTable();
}

void MainWindow::refreshFileWorkspaceViews()
{
    refreshThreatFilterOptions();
    applyThreatFilters();
    refreshHistoryData();
    refreshExclusionData();
    refreshQuarantineData();
    updateHomeSummary();
}

void MainWindow::recordFileAction(const QString &findingId, const QString &action, const QString &details)
{
    std::string errorMessage;
    m_stateStore.recordScanAction(m_lastScanHistoryId,
                                  findingId.toStdString(),
                                  action.toStdString(),
                                  details.toStdString(),
                                  errorMessage);
}

void MainWindow::startClamAvDefinitionUpdate()
{
    if (m_definitionUpdateWatcher->isRunning()) {
        return;
    }

    m_updateClamAvButton->setEnabled(false);
    m_homeUpdateDefsButton->setEnabled(false);
    m_clamAvUpdateStatusLabel->setText(tr("Updating ClamAV databases ..."));

    m_definitionUpdateWatcher->setFuture(QtConcurrent::run([]() {
        warden::network::DefinitionUpdater updater;
        return updater.updateClamAvDefinitions({});
    }));
}

void MainWindow::handleClamAvDefinitionUpdateFinished()
{
    const auto result = m_definitionUpdateWatcher->result();
    m_updateClamAvButton->setEnabled(true);
    m_homeUpdateDefsButton->setEnabled(true);

    if (result.success) {
        m_clamAvUpdateStatusLabel->setText(
            tr("ClamAV update succeeded. Databases touched: %1 | Directory: %2")
                .arg(result.updatedCount)
                .arg(toQString(result.databaseDirectory))
        );
        showTrayNotification(tr("Definitions Updated"),
                             tr("ClamAV definitions updated successfully."),
                             QSystemTrayIcon::Information);
    } else if (!result.supported && !result.error.empty()) {
        m_clamAvUpdateStatusLabel->setText(tr("ClamAV updater unavailable: %1").arg(toQString(result.error)));
    } else {
        m_clamAvUpdateStatusLabel->setText(tr("ClamAV update failed: %1").arg(toQString(result.error)));
    }

    std::string errorMessage;
    m_stateStore.setStatusSnapshot("definitions_status",
                                   m_clamAvUpdateStatusLabel->text().toStdString(),
                                   errorMessage);
    updateHomeSummary();
}

void MainWindow::updateHomeSummary()
{
    if (m_lastFileScanReport.has_value()) {
        m_homeFileScanStatusLabel->setText(
            tr("Last filesystem scan: %1 | Files: %2 | Results: %3 | Duration: %4")
                .arg(modeText(m_lastFileScanReport->options.mode))
                .arg(m_lastFileScanReport->stats.scannedFiles)
                .arg(m_lastFileScanReport->records.size())
                .arg(formatDuration(m_lastFileScanReport->durationMs))
        );
        m_homeThreatSummaryLabel->setText(
            tr("Warnings: %1 | ClamAV loaded: %2 | Signatures: %3")
                .arg(m_lastFileScanReport->warnings.size())
                .arg(m_lastFileScanReport->clamAvLoaded ? tr("yes") : tr("no"))
                .arg(m_lastFileScanReport->clamAvSignatures)
        );
    } else {
        const std::string storedLastScan = m_stateStore.statusSnapshotValue("last_scan_status");
        const std::string storedThreatStatus = m_stateStore.statusSnapshotValue("last_threat_status");
        m_homeFileScanStatusLabel->setText(storedLastScan.empty()
                                               ? tr("No filesystem scan has been run yet.")
                                               : QString::fromStdString(storedLastScan));
        m_homeThreatSummaryLabel->setText(storedThreatStatus.empty()
                                              ? tr("No findings are currently loaded.")
                                              : QString::fromStdString(storedThreatStatus));
    }

    m_homeDefinitionsStatusLabel->setText(tr("Definitions: %1").arg(m_clamAvUpdateStatusLabel->text()));
    m_homeHistorySummaryLabel->setText(
        tr("History entries: %1 | Exclusions: %2 | Quarantine entries: %3")
            .arg(m_scanHistoryEntries.size())
            .arg(m_exclusionEntries.size())
            .arg(m_quarantineEntries.size())
    );
}

void MainWindow::showTrayNotification(const QString &title,
                                      const QString &message,
                                      const QSystemTrayIcon::MessageIcon icon) const
{
    if (m_trayIcon != nullptr && m_trayIcon->isVisible()) {
        m_trayIcon->showMessage(title, message, icon, 6000);
    }
}
