#ifndef WARDEN_FREE_MAINWINDOW_H
#define WARDEN_FREE_MAINWINDOW_H

#include <optional>
#include <vector>

#include <QMainWindow>
#include <QSystemTrayIcon>

#include "warden/core/ScanTypes.h"
#include "warden/network/DefinitionUpdater.h"

template<typename T>
class QFutureWatcher;

class QCloseEvent;
class QComboBox;
class QLabel;
class QLineEdit;
class QListWidget;
class QMenu;
class QProgressBar;
class QPushButton;
class QTableWidget;
class QTabWidget;

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
    void showAndRaiseWindow();
    void quickScan();
    void exitApplication();
    void handleTrayIconActivated(QSystemTrayIcon::ActivationReason reason);

    void browseFileScanTarget();
    void startQuickFileScan();
    void startFullFileScan();
    void startFileScan(warden::core::ScanMode mode);
    void handleFileScanFinished();
    void populateThreatTable();
    void handleThreatActionChanged(int findingIndex, const QString &actionText);
    void quarantineThreat(int findingIndex);
    void showThreatDetails(int findingIndex);
    void refreshQuarantineList();

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

    QLineEdit *m_fileScanTargetEdit;
    QPushButton *m_fileScanBrowseButton;
    QPushButton *m_fileScanQuickButton;
    QPushButton *m_fileScanFullButton;
    QProgressBar *m_fileScanProgressBar;
    QLabel *m_fileScanStatusLabel;
    QTableWidget *m_threatTable;

    QPushButton *m_updateClamAvButton;
    QLabel *m_clamAvUpdateStatusLabel;
    QLabel *m_quarantinePathLabel;
    QPushButton *m_quarantineRefreshButton;
    QListWidget *m_quarantineListWidget;
    QComboBox *m_themeComboBox;

    std::optional<warden::core::ScanReport> m_lastFileScanReport;
    std::vector<QString> m_findingStatuses;

    QFutureWatcher<warden::core::ScanReport> *m_fileScanWatcher;
    QFutureWatcher<warden::network::DefinitionUpdateResult> *m_definitionUpdateWatcher;

    bool m_allowClose;
    bool m_hasShownMinimizeNotice;
};

#endif
