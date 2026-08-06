#pragma once
#include <QString>
#include <QColor>
#include <QList>

class QApplication;

// Application preferences, persisted via QSettings. A single global instance
// (prefs()) is loaded at startup and saved when the Preferences dialog is
// accepted. The engine layers never see this - it's GUI-only.
namespace de::gui {

enum class Theme { Dark, Light };
enum class HashKind { None, Md5, Sha256 };
enum class Collision { Rename, Overwrite, Skip };

// A named accent "color combo" - drives selection/highlight/links so the app
// reads as one system. Curated to look good in both dark and light themes.
struct Accent {
    QString name;
    QColor color;
    QColor onColor;   // text drawn on top of the accent (for contrast)
};

QList<Accent> accents();                 // the available color combos
Accent accentByName(const QString& name); // lookup, falls back to the default

struct Prefs {
    // Appearance
    Theme theme = Theme::Dark;            // dark is the default
    QString accentName = "Blue";
    int hexFontPt = 10;

    // Export
    HashKind hashOnExport = HashKind::None;
    Collision collision = Collision::Rename;
    int exportBufferMiB = 4;
    // Give exported files the dates they had on the source volume instead of
    // the time of extraction, so recovered data lands in cloud storage with a
    // sane timeline. On by default.
    bool preserveTimestamps = true;
    QString defaultExportDir;             // empty => ask each time / last used

    // Reading
    int previewKiB = 64;

    // Convenience
    bool rememberOptanePaths = true;
    QString lastQlcPath, lastOptanePath, lastCacheSector;
};

Prefs& prefs();          // the global, mutable preferences
void loadPrefs();        // populate prefs() from QSettings
void savePrefs();        // write prefs() back to QSettings

// Apply the current theme + accent to the whole application (palette-based, via
// the Fusion style so the colors are honored consistently).
void applyTheme(QApplication& app, const Prefs& p);

} // namespace de::gui
