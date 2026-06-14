#include "MainWindow.h"

#include "warden/scanner/ClamAvOnlyCoordinator.h"
#include "warden/scanner/QuarantineManager.h"

#include <QAbstractItemView>
#include <QAction>
#include <QApplication>
#include <QCloseEvent>
#include <QColor>
#include <QComboBox>
#include <QDebug>
#include <QFileDialog>
#include <QFormLayout>
#include <QFutureWatcher>
#include <QGridLayout>
#include <QGroupBox>
#include <QHeaderView>
#include <QHBoxLayout>
#include <QLabel>
#include <QLineEdit>
#include <QListWidget>
#include <QMenu>
#include <QMessageBox>
#include <QProgressBar>
#include <QPushButton>
#include <QSignalBlocker>
#include <QSizePolicy>
#include <QStyle>
#include <QSystemTrayIcon>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QStringList>
#include <QVBoxLayout>
#include <QtConcurrent>

#include <filesystem>

namespace {

QString toQString(const std::string &value)
{
    return QString::fromStdString(value);
}

QString toQString(const std::filesystem::path &value)
{
    return QString::fromStdString(value.string());
}

std::filesystem::path detectProjectRoot()
{
    const std::vector<std::filesystem::path> candidates = {
        std::filesystem::current_path(),
        (std::filesystem::current_path() / "..").lexically_normal()
    };

    for (const auto &candidate : candidates) {
        std::error_code errorCode;
        if (std::filesystem::exists(candidate / "CMakeLists.txt", errorCode) &&
            std::filesystem::exists(candidate / "headers", errorCode)) {
            return candidate;
        }
    }

    return candidates.front();
}

QString severityText(const warden::core::Severity severity)
{
    return QString::fromStdString(warden::core::toString(severity));
}

QString threatTypeText(const warden::core::ThreatType threatType)
{
    return QString::fromStdString(warden::core::toString(threatType));
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

QString modeText(const warden::core::ScanMode mode)
{
    return mode == warden::core::ScanMode::Full ? QStringLiteral("full") : QStringLiteral("quick");
}

QStringList actionChoices()
{
    return {
        QStringLiteral("Select Action"),
        QObject::tr("Quarantine"),
        QObject::tr("Ignore"),
        QObject::tr("View Details")
    };
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
        "QLineEdit, QComboBox, QListWidget, QTableWidget { background: #11151a; border: 1px solid #36414c; }"
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
        "QLineEdit, QComboBox, QListWidget, QTableWidget { background: #ffffff; border: 1px solid #cbd5df; }"
        "QHeaderView::section { background: #e8eef5; padding: 6px; border: 0; border-right: 1px solid #d3dde7; }"
    );
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
      m_fileScanTargetEdit(nullptr),
      m_fileScanBrowseButton(nullptr),
      m_fileScanQuickButton(nullptr),
      m_fileScanFullButton(nullptr),
      m_fileScanProgressBar(nullptr),
      m_fileScanStatusLabel(nullptr),
      m_threatTable(nullptr),
      m_updateClamAvButton(nullptr),
      m_clamAvUpdateStatusLabel(nullptr),
      m_quarantinePathLabel(nullptr),
      m_quarantineRefreshButton(nullptr),
      m_quarantineListWidget(nullptr),
      m_themeComboBox(nullptr),
      m_fileScanWatcher(new QFutureWatcher<warden::core::ScanReport>(this)),
      m_definitionUpdateWatcher(new QFutureWatcher<warden::network::DefinitionUpdateResult>(this)),
      m_allowClose(false),
      m_hasShownMinimizeNotice(false)
{
    QIcon appIcon(QStringLiteral(":/icons/Warden-Logo.png"));
    if (appIcon.isNull()) {
        appIcon = style()->standardIcon(QStyle::SP_MessageBoxInformation);
    }

    setWindowTitle(tr("Warden Free"));
    setWindowIcon(appIcon);
    resize(980, 680);

    createTabs();
    setCentralWidget(m_tabWidget);

    connect(m_fileScanWatcher, &QFutureWatcher<warden::core::ScanReport>::finished, this, &MainWindow::handleFileScanFinished);
    connect(m_definitionUpdateWatcher, &QFutureWatcher<warden::network::DefinitionUpdateResult>::finished, this, &MainWindow::handleClamAvDefinitionUpdateFinished);

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
        showTrayNotification(
            tr("Warden Free"),
            tr("Warden Free is still running in the system tray."),
            QSystemTrayIcon::Information
        );
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

    auto *actionsBox = new QGroupBox(tr("ClamAV Workflows"), tab);
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
    m_homeThreatSummaryLabel = new QLabel(tr("Threat queue is empty."), statusBox);
    m_homeDefinitionsStatusLabel = new QLabel(tr("Definition updater idle."), statusBox);
    m_homeDefinitionsStatusLabel->setWordWrap(true);
    m_homeDefinitionsStatusLabel->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Preferred);
    statusLayout->addWidget(m_homeFileScanStatusLabel);
    statusLayout->addWidget(m_homeThreatSummaryLabel);
    statusLayout->addWidget(m_homeDefinitionsStatusLabel);
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
    m_fileScanQuickButton = new QPushButton(tr("Quick Scan"), controlsBox);
    m_fileScanFullButton = new QPushButton(tr("Full Scan"), controlsBox);
    m_fileScanProgressBar = new QProgressBar(controlsBox);
    m_fileScanProgressBar->setRange(0, 100);
    m_fileScanProgressBar->setValue(0);
    m_fileScanStatusLabel = new QLabel(tr("Ready."), controlsBox);

    controlsLayout->addWidget(new QLabel(tr("Target:"), controlsBox), 0, 0);
    controlsLayout->addWidget(m_fileScanTargetEdit, 0, 1, 1, 3);
    controlsLayout->addWidget(m_fileScanBrowseButton, 0, 4);
    controlsLayout->addWidget(m_fileScanQuickButton, 1, 1);
    controlsLayout->addWidget(m_fileScanFullButton, 1, 2);
    controlsLayout->addWidget(m_fileScanStatusLabel, 2, 0, 1, 5);
    controlsLayout->addWidget(m_fileScanProgressBar, 3, 0, 1, 5);
    layout->addWidget(controlsBox);

    auto *resultsBox = new QGroupBox(tr("ClamAV Findings"), tab);
    auto *resultsLayout = new QVBoxLayout(resultsBox);
    m_threatTable = new QTableWidget(resultsBox);
    m_threatTable->setColumnCount(7);
    m_threatTable->setHorizontalHeaderLabels(
        {tr("Threat"), tr("Path"), tr("Severity"), tr("Type"), tr("Recommended Action"), tr("Status"), tr("Action")}
    );
    m_threatTable->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
    m_threatTable->verticalHeader()->setVisible(false);
    m_threatTable->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_threatTable->setSelectionBehavior(QAbstractItemView::SelectRows);
    resultsLayout->addWidget(m_threatTable);
    layout->addWidget(resultsBox, 1);

    connect(m_fileScanBrowseButton, &QPushButton::clicked, this, &MainWindow::browseFileScanTarget);
    connect(m_fileScanQuickButton, &QPushButton::clicked, this, &MainWindow::startQuickFileScan);
    connect(m_fileScanFullButton, &QPushButton::clicked, this, &MainWindow::startFullFileScan);

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

    auto *quarantineBox = new QGroupBox(tr("Quarantine Manager"), tab);
    auto *quarantineLayout = new QVBoxLayout(quarantineBox);
    m_quarantinePathLabel = new QLabel(quarantineBox);
    m_quarantineRefreshButton = new QPushButton(tr("Refresh Quarantine List"), quarantineBox);
    m_quarantineListWidget = new QListWidget(quarantineBox);
    quarantineLayout->addWidget(m_quarantinePathLabel);
    quarantineLayout->addWidget(m_quarantineRefreshButton);
    quarantineLayout->addWidget(m_quarantineListWidget);
    layout->addWidget(quarantineBox, 1);

    auto *appearanceBox = new QGroupBox(tr("Appearance"), tab);
    auto *appearanceLayout = new QFormLayout(appearanceBox);
    m_themeComboBox = new QComboBox(appearanceBox);
    m_themeComboBox->addItems({tr("Warden Dark"), tr("Clean Light"), tr("System Default")});
    appearanceLayout->addRow(tr("Theme:"), m_themeComboBox);
    layout->addWidget(appearanceBox);

    connect(m_updateClamAvButton, &QPushButton::clicked, this, &MainWindow::startClamAvDefinitionUpdate);
    connect(m_quarantineRefreshButton, &QPushButton::clicked, this, &MainWindow::refreshQuarantineList);
    connect(m_themeComboBox, &QComboBox::currentTextChanged, this, [this](const QString &themeName) {
        if (themeName == tr("Warden Dark")) {
            qApp->setStyleSheet(darkStylesheet());
        } else if (themeName == tr("Clean Light")) {
            qApp->setStyleSheet(lightStylesheet());
        } else {
            qApp->setStyleSheet(QString());
        }
    });

    return tab;
}

void MainWindow::createTrayIcon()
{
    if (!QSystemTrayIcon::isSystemTrayAvailable()) {
        qWarning() << "System tray is not available on this platform/session.";
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
    m_fileScanTargetEdit->setText(toQString(detectProjectRoot()));
    m_themeComboBox->setCurrentText(tr("Warden Dark"));
    refreshQuarantineList();
    updateHomeSummary();
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
    const QString selectedDirectory = QFileDialog::getExistingDirectory(
        this,
        tr("Select Scan Target"),
        m_fileScanTargetEdit->text()
    );

    if (!selectedDirectory.isEmpty()) {
        m_fileScanTargetEdit->setText(selectedDirectory);
    }
}

void MainWindow::startQuickFileScan()
{
    startFileScan(warden::core::ScanMode::Quick);
}

void MainWindow::startFullFileScan()
{
    startFileScan(warden::core::ScanMode::Full);
}

void MainWindow::startFileScan(const warden::core::ScanMode mode)
{
    if (m_fileScanWatcher->isRunning()) {
        QMessageBox::information(this, tr("Filesystem Scan"), tr("A filesystem scan is already running."));
        return;
    }

    if (m_fileScanTargetEdit->text().trimmed().isEmpty()) {
        QMessageBox::warning(this, tr("Filesystem Scan"), tr("Choose a scan target before starting the scan."));
        return;
    }

    warden::core::ScanOptions options;
    options.targetPath = std::filesystem::path(m_fileScanTargetEdit->text().toStdString());
    options.mode = mode;
    options.clamAvDatabasePath = warden::network::DefinitionUpdater::preferredDatabaseDirectory();
    options.quarantineDirectory = detectProjectRoot() / "quarantine";

    m_tabWidget->setCurrentWidget(m_fileScanTab);
    m_fileScanStatusLabel->setText(tr("Running %1 filesystem scan against %2 ...").arg(modeText(mode), m_fileScanTargetEdit->text()));
    m_fileScanProgressBar->setRange(0, 0);
    m_homeQuickScanButton->setEnabled(false);
    m_homeFullScanButton->setEnabled(false);
    m_fileScanQuickButton->setEnabled(false);
    m_fileScanFullButton->setEnabled(false);
    updateHomeSummary();

    m_fileScanWatcher->setFuture(QtConcurrent::run([options]() {
        warden::scanner::ClamAvOnlyCoordinator coordinator;
        return coordinator.runScan(options);
    }));
}

void MainWindow::handleFileScanFinished()
{
    const warden::core::ScanReport report = m_fileScanWatcher->result();
    m_lastFileScanReport = report;
    m_findingStatuses.assign(report.findings.size(), tr("Pending review"));

    m_fileScanProgressBar->setRange(0, 100);
    m_fileScanProgressBar->setValue(100);
    m_homeQuickScanButton->setEnabled(true);
    m_homeFullScanButton->setEnabled(true);
    m_fileScanQuickButton->setEnabled(true);
    m_fileScanFullButton->setEnabled(true);

    m_fileScanStatusLabel->setText(
        tr("Completed %1 scan. Files scanned: %2 | Threats: %3 | Warnings: %4")
            .arg(modeText(report.options.mode))
            .arg(report.stats.scannedFiles)
            .arg(report.stats.threatsFound)
            .arg(report.warnings.size())
    );

    populateThreatTable();
    updateHomeSummary();

    if (report.stats.threatsFound > 0) {
        showTrayNotification(
            tr("Threats Found"),
            tr("%1 threat(s) found during the %2 filesystem scan.")
                .arg(report.stats.threatsFound)
                .arg(modeText(report.options.mode)),
            QSystemTrayIcon::Warning
        );
    } else {
        showTrayNotification(
            tr("Scan Complete"),
            tr("Filesystem %1 scan completed with no threats found.").arg(modeText(report.options.mode)),
            QSystemTrayIcon::Information
        );
    }
}

void MainWindow::populateThreatTable()
{
    m_threatTable->clearContents();

    if (!m_lastFileScanReport.has_value()) {
        m_threatTable->setRowCount(0);
        return;
    }

    const auto &findings = m_lastFileScanReport->findings;
    m_threatTable->setRowCount(static_cast<int>(findings.size()));

    for (int row = 0; row < static_cast<int>(findings.size()); ++row) {
        const auto &finding = findings.at(static_cast<std::size_t>(row));
        auto *nameItem = new QTableWidgetItem(toQString(finding.name));
        auto *pathItem = new QTableWidgetItem(toQString(finding.path));
        auto *severityItem = new QTableWidgetItem(severityText(finding.severity));
        auto *typeItem = new QTableWidgetItem(threatTypeText(finding.threatType));
        auto *recommendedItem = new QTableWidgetItem(toQString(finding.recommendedAction));
        auto *statusItem = new QTableWidgetItem(m_findingStatuses.at(static_cast<std::size_t>(row)));

        severityItem->setBackground(severityColor(finding.severity));

        m_threatTable->setItem(row, 0, nameItem);
        m_threatTable->setItem(row, 1, pathItem);
        m_threatTable->setItem(row, 2, severityItem);
        m_threatTable->setItem(row, 3, typeItem);
        m_threatTable->setItem(row, 4, recommendedItem);
        m_threatTable->setItem(row, 5, statusItem);

        auto *actionCombo = new QComboBox(m_threatTable);
        actionCombo->addItems(actionChoices());
        connect(actionCombo, &QComboBox::currentTextChanged, this, [this, row](const QString &actionText) {
            handleThreatActionChanged(row, actionText);
        });
        m_threatTable->setCellWidget(row, 6, actionCombo);
    }
}

void MainWindow::handleThreatActionChanged(const int findingIndex, const QString &actionText)
{
    if (!m_lastFileScanReport.has_value() || actionText == QStringLiteral("Select Action")) {
        return;
    }

    if (findingIndex < 0 || findingIndex >= static_cast<int>(m_lastFileScanReport->findings.size())) {
        return;
    }

    if (actionText == tr("Quarantine")) {
        quarantineThreat(findingIndex);
    } else if (actionText == tr("Ignore")) {
        m_findingStatuses.at(static_cast<std::size_t>(findingIndex)) = tr("Ignored by operator");
        m_threatTable->item(findingIndex, 5)->setText(m_findingStatuses.at(static_cast<std::size_t>(findingIndex)));
    } else if (actionText == tr("View Details")) {
        showThreatDetails(findingIndex);
    }

    if (auto *actionCombo = qobject_cast<QComboBox *>(m_threatTable->cellWidget(findingIndex, 6))) {
        const QSignalBlocker blocker(actionCombo);
        actionCombo->setCurrentIndex(0);
    }
}

void MainWindow::quarantineThreat(const int findingIndex)
{
    const auto &finding = m_lastFileScanReport->findings.at(static_cast<std::size_t>(findingIndex));
    warden::scanner::QuarantineManager manager(detectProjectRoot() / "quarantine");
    const auto result = manager.quarantine(finding);
    if (!result.success) {
        QMessageBox::critical(this, tr("Quarantine Threat"), tr("Failed to quarantine file: %1").arg(toQString(result.error)));
        return;
    }

    m_findingStatuses.at(static_cast<std::size_t>(findingIndex)) =
        tr("Quarantined to %1").arg(toQString(result.quarantinedPath.filename()));
    m_threatTable->item(findingIndex, 5)->setText(m_findingStatuses.at(static_cast<std::size_t>(findingIndex)));
    refreshQuarantineList();
}

void MainWindow::showThreatDetails(const int findingIndex)
{
    const auto &finding = m_lastFileScanReport->findings.at(static_cast<std::size_t>(findingIndex));

    QString detailText;
    detailText += tr("Threat: %1\n").arg(toQString(finding.name));
    detailText += tr("Path: %1\n").arg(toQString(finding.path));
    detailText += tr("Severity: %1\n").arg(severityText(finding.severity));
    detailText += tr("Type: %1\n").arg(threatTypeText(finding.threatType));
    detailText += tr("Source: %1\n").arg(toQString(finding.source));
    detailText += tr("SHA-256: %1\n").arg(toQString(finding.sha256));
    detailText += tr("Recommended Action: %1\n\n").arg(toQString(finding.recommendedAction));
    detailText += tr("Description:\n%1").arg(toQString(finding.description));

    QMessageBox details(this);
    details.setWindowTitle(tr("Threat Details"));
    details.setIcon(QMessageBox::Information);
    details.setText(detailText);
    details.exec();
}

void MainWindow::refreshQuarantineList()
{
    const std::filesystem::path quarantineDirectory = detectProjectRoot() / "quarantine";
    m_quarantinePathLabel->setText(tr("Quarantine directory: %1").arg(toQString(quarantineDirectory)));
    m_quarantineListWidget->clear();

    std::error_code errorCode;
    if (!std::filesystem::exists(quarantineDirectory, errorCode)) {
        m_quarantineListWidget->addItem(tr("No quarantined items yet."));
        return;
    }

    bool foundEntries = false;
    for (const auto &entry : std::filesystem::directory_iterator(quarantineDirectory, errorCode)) {
        if (errorCode) {
            break;
        }

        foundEntries = true;
        m_quarantineListWidget->addItem(toQString(entry.path().filename()));
    }

    if (!foundEntries) {
        m_quarantineListWidget->addItem(tr("No quarantined items yet."));
    }
}

void MainWindow::startClamAvDefinitionUpdate()
{
    if (m_definitionUpdateWatcher->isRunning()) {
        return;
    }

    m_updateClamAvButton->setEnabled(false);
    m_homeUpdateDefsButton->setEnabled(false);
    m_clamAvUpdateStatusLabel->setText(tr("Updating ClamAV databases..."));
    updateHomeSummary();

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
        showTrayNotification(tr("Definitions Updated"), tr("ClamAV definitions updated successfully."), QSystemTrayIcon::Information);
    } else if (!result.supported && !result.error.empty()) {
        m_clamAvUpdateStatusLabel->setText(tr("ClamAV updater unavailable: %1").arg(toQString(result.error)));
    } else {
        m_clamAvUpdateStatusLabel->setText(tr("ClamAV update failed: %1").arg(toQString(result.error)));
    }

    updateHomeSummary();
}

void MainWindow::updateHomeSummary()
{
    if (m_lastFileScanReport.has_value()) {
        const auto &report = *m_lastFileScanReport;
        m_homeFileScanStatusLabel->setText(
            tr("Last filesystem scan: %1 | Files: %2 | Threats: %3")
                .arg(modeText(report.options.mode))
                .arg(report.stats.scannedFiles)
                .arg(report.stats.threatsFound)
        );
        m_homeThreatSummaryLabel->setText(
            tr("Warnings: %1 | ClamAV loaded: %2 | Signatures: %3")
                .arg(report.warnings.size())
                .arg(report.clamAvLoaded ? tr("yes") : tr("no"))
                .arg(report.clamAvSignatures)
        );
    } else {
        m_homeFileScanStatusLabel->setText(tr("No filesystem scan has been run yet."));
        m_homeThreatSummaryLabel->setText(tr("Threat queue is empty."));
    }

    m_homeDefinitionsStatusLabel->setText(tr("Definitions: %1").arg(m_clamAvUpdateStatusLabel->text()));
}

void MainWindow::showTrayNotification(const QString &title,
                                      const QString &message,
                                      const QSystemTrayIcon::MessageIcon icon) const
{
    if (m_trayIcon != nullptr && m_trayIcon->isVisible()) {
        m_trayIcon->showMessage(title, message, icon, 6000);
    }
}
