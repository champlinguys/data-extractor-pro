#include "gui/main_window.h"
#include "gui/settings.h"
#include <QApplication>

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
    return app.exec();
}
