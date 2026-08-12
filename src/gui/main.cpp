#include "gui/main_window.h"
#include "gui/settings.h"
#include <QApplication>
#include <QStringList>
#include <QTimer>

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setOrganizationName("DataExtractorPro");
    QApplication::setApplicationName("Data Extractor Pro");

    // Load persisted preferences and apply the theme (dark by default) before
    // the window is shown, so there's no light-mode flash on startup.
    de::gui::loadPrefs();
    de::gui::applyTheme(app, de::gui::prefs());

    MainWindow win;
    win.show();

    // An optional source on the command line, in the same form de-cli takes:
    // an image path, or a RAID set such as
    //   data-extractor raid:auto:/dev/sdc,/dev/sdd
    // Handy when the drives are already known and re-picking them through the
    // dialog every time would be tedious.
    //
    // Queued rather than called directly: opening puts up a modal progress
    // dialog and pumps events, which only works once the event loop is
    // running - doing it here would leave the main window unmapped.
    QStringList args = QApplication::arguments();
    if (args.size() > 1) {
        QString spec = args.at(1);
        QTimer::singleShot(0, &win, [&win, spec] { win.openSourceSpec(spec); });
    }

    return app.exec();
}
