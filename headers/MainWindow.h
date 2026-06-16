#ifndef WARDEN_FREE_MAINWINDOW_H
#define WARDEN_FREE_MAINWINDOW_H

#include <optional>
#include <cstdint>
#include <memory>
#include <vector>

#include <QMainWindow>
#include <QSystemTrayIcon>

#include "warden/core/ScanTypes.h"
#include "warden/network/DefinitionUpdater.h"
#include "warden/scanner/ScanCoordinator.h"
#include "warden/storage/StateStore.h"

template<typename T>
class QFutureWatcher;

class QCheckBox;
class QCloseEvent;
class QComboBox;
class QLabel;
class QLineEdit;
class QMenu;
class QPlainTextEdit;
class QProgressBar;
class QPushButton;
class QTableWidget;
class QTabWidget;
class QThread;

namespace warden::scanner {
class FileScanWorker;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = nullptr);
    ~MainWindow() override = default;

protected:
    void closeEvent(QCloseEvent *event) override;

private:
    void createTabs();
    QWidget *createHomeTab();
    QWidget *createFileScanTab();
    QWidget *createSettingsTab();
    void createTrayIcon();
    void initializeUiState();
    void applyTheme(const QString &themeName);
    void showAndRaiseWindow();
    void quickScan();
    void exitApplication();
    void handleTrayIconActivated(QSystemTrayIcon::ActivationReason reason);

    void browseFileScanTarget();
    void handleFileProfileChanged();
    void startConfiguredFileScan();
    void startQuickFileScan();
    void startFullFileScan();
    void startFileScan(warden::core::ScanMode mode, bool overrideProfile);
    void cancelFileScan();
    warden::core::ScanOptions buildFileScanOptions(warden::core::ScanMode mode, bool overrideProfile) const;
    void handleFileScanProgress(const QString &phase,
                                const QString &currentItem,
                                int scannedFiles,
                                int totalFiles,
                                int threatsFound,
                                bool indeterminate,
                                const QStringList &activeEngines);
    void handleFileScanFinished(const warden::core::ScanReport &report);
    void populateThreatTable();
    void populateHistoryTable();
    void populateExclusionsTable();
    void populateQuarantineTable();
    void handleThreatActionChanged(int recordIndex, const QString &actionText);
    void handleThreatSelectionChanged();
    void updateThreatDetails(int recordIndex);
    void applyThreatFilters();
    void refreshThreatFilterOptions();
    void updateFileScanSummary();
    int sourceThreatIndexForRow(int recordIndex) const;
    std::vector<int> selectedThreatSourceIndices() const;
    void applyThreatStatuses(const std::vector<int> &sourceIndices,
                             const QString &statusText,
                             const QString &actionText);
    bool addThreatRecordToExclusion(int recordIndex, bool excludeParentFolder, QString &statusText);
    void ignoreSelectedThreats();
    void markSelectedThreatsReviewed();
    void addSelectedThreatsToExclusions();
    void exportFindingsToCsv();
    void exportSelectedFindings();
    void exportThreatRecordsToCsv(const std::vector<int> &sourceIndices,
                                  const QString &defaultNamePrefix,
                                  const QString &dialogTitle);
    void saveCurrentReport();
    void loadSavedReport();
    void quarantineThreat(int recordIndex);
    void removeSelectedExclusions();
    void restoreSelectedQuarantine();
    void refreshHistoryData();
    void refreshExclusionData();
    void refreshQuarantineData();
    void refreshFileWorkspaceViews();
    void recordFileAction(const QString &findingId, const QString &action, const QString &details);

    void startClamAvDefinitionUpdate();
    void handleClamAvDefinitionUpdateFinished();
    void updateHomeSummary();
    void showTrayNotification(const QString &title,
                              const QString &message,
                              QSystemTrayIcon::MessageIcon icon) const;

    QTabWidget *m_tabWidget;
    QWidget *m_homeTab;
    QWidget *m_fileScanTab;
    QWidget *m_settingsTab;

    QSystemTrayIcon *m_trayIcon;
    QMenu *m_trayMenu;

    QPushButton *m_homeQuickScanButton;
    QPushButton *m_homeFullScanButton;
    QPushButton *m_homeUpdateDefsButton;
    QLabel *m_homeFileScanStatusLabel;
    QLabel *m_homeThreatSummaryLabel;
    QLabel *m_homeDefinitionsStatusLabel;
    QLabel *m_homeHistorySummaryLabel;

    QLineEdit *m_fileScanTargetEdit;
    QPushButton *m_fileScanBrowseButton;
    QComboBox *m_fileScanProfileCombo;
    QPushButton *m_fileScanRunButton;
    QPushButton *m_fileScanQuickButton;
    QPushButton *m_fileScanFullButton;
    QPushButton *m_fileScanCancelButton;
    QCheckBox *m_fileScanClamAvCheckBox;
    QCheckBox *m_fileScanHeuristicCheckBox;
    QProgressBar *m_fileScanProgressBar;
    QLabel *m_fileScanStatusLabel;
    QLabel *m_fileScanCurrentItemLabel;
    QLabel *m_fileScanCountersLabel;
    QLabel *m_fileScanEnginesLabel;
    QLabel *m_fileScanSummaryLabel;
    QComboBox *m_fileClassFilterCombo;
    QComboBox *m_fileSeverityFilterCombo;
    QComboBox *m_fileEngineFilterCombo;
    QComboBox *m_fileExtensionFilterCombo;
    QPushButton *m_exportFindingsButton;
    QPushButton *m_exportSelectedFindingsButton;
    QPushButton *m_saveReportButton;
    QPushButton *m_loadReportButton;
    QPushButton *m_ignoreSelectedFindingsButton;
    QPushButton *m_markReviewedFindingsButton;
    QPushButton *m_addSelectedExclusionsButton;
    QTableWidget *m_threatTable;
    QPlainTextEdit *m_threatDetailsText;
    QTableWidget *m_scanHistoryTable;
    QTableWidget *m_exclusionsTable;
    QPushButton *m_removeExclusionButton;
    QLabel *m_quarantinePathLabel;
    QTableWidget *m_quarantineTable;
    QPushButton *m_refreshQuarantineButton;
    QPushButton *m_restoreQuarantineButton;

    QPushButton *m_updateClamAvButton;
    QLabel *m_clamAvUpdateStatusLabel;
    QComboBox *m_themeComboBox;

    warden::storage::StateStore m_stateStore;
    std::optional<warden::core::ScanReport> m_lastFileScanReport;
    std::vector<QString> m_recordStatuses;
    std::vector<int> m_visibleThreatIndices;
    std::vector<warden::storage::ScanHistoryEntry> m_scanHistoryEntries;
    std::vector<warden::storage::ExclusionEntry> m_exclusionEntries;
    std::vector<warden::storage::QuarantineCatalogEntry> m_quarantineEntries;
    std::int64_t m_lastScanHistoryId;

    QThread *m_fileScanThread;
    warden::scanner::FileScanWorker *m_fileScanWorker;
    warden::scanner::ScanCancelFlag m_fileScanCancelFlag;
    QFutureWatcher<warden::network::DefinitionUpdateResult> *m_definitionUpdateWatcher;

    bool m_allowClose;
    bool m_hasShownMinimizeNotice;
};

#endif
