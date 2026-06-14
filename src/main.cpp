#include <QApplication>
#include <QIcon>

#include "MainWindow.h"

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);
    app.setApplicationName("Warden Free");
    app.setOrganizationName("Warden");
    app.setQuitOnLastWindowClosed(false);

    const QIcon appIcon(QStringLiteral(":/icons/Warden-Logo.png"));
    if (!appIcon.isNull()) {
        app.setWindowIcon(appIcon);
    }

    MainWindow window;
    window.show();

    return app.exec();
}
