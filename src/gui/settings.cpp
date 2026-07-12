#include "gui/settings.h"
#include <QApplication>
#include <QSettings>
#include <QStyleFactory>
#include <QPalette>

namespace de::gui {

QList<Accent> accents() {
    // Curated color combos, legible as a selection highlight on both bases.
    // {name, accent color, text-on-accent}.
    return {
        {"Blue",    QColor(0x3D, 0x8B, 0xFD), Qt::white},
        {"Teal",    QColor(0x17, 0xA2, 0xB8), Qt::white},
        {"Green",   QColor(0x2E, 0xA0, 0x43), Qt::white},
        {"Amber",   QColor(0xE0, 0x94, 0x20), Qt::black},
        {"Purple",  QColor(0x8E, 0x5B, 0xD0), Qt::white},
        {"Crimson", QColor(0xE0, 0x52, 0x4D), Qt::white},
        {"Magenta", QColor(0xD0, 0x50, 0xA0), Qt::white},
        {"Slate",   QColor(0x6C, 0x7A, 0x89), Qt::white},
    };
}

Accent accentByName(const QString& name) {
    for (const auto& a : accents())
        if (a.name.compare(name, Qt::CaseInsensitive) == 0) return a;
    return accents().front(); // default: Blue
}

Prefs& prefs() {
    static Prefs p;
    return p;
}

namespace {
QString themeStr(Theme t) { return t == Theme::Dark ? "dark" : "light"; }
Theme themeFromStr(const QString& s) { return s == "light" ? Theme::Light : Theme::Dark; }

QString hashStr(HashKind h) {
    switch (h) { case HashKind::Md5: return "md5"; case HashKind::Sha256: return "sha256";
                 default: return "none"; }
}
HashKind hashFromStr(const QString& s) {
    if (s == "md5") return HashKind::Md5;
    if (s == "sha256") return HashKind::Sha256;
    return HashKind::None;
}
QString collStr(Collision c) {
    switch (c) { case Collision::Overwrite: return "overwrite";
                 case Collision::Skip: return "skip"; default: return "rename"; }
}
Collision collFromStr(const QString& s) {
    if (s == "overwrite") return Collision::Overwrite;
    if (s == "skip") return Collision::Skip;
    return Collision::Rename;
}
} // namespace

void loadPrefs() {
    QSettings s;
    Prefs& p = prefs();
    p.theme         = themeFromStr(s.value("appearance/theme", "dark").toString());
    p.accentName    = s.value("appearance/accent", "Blue").toString();
    p.hexFontPt     = s.value("appearance/hexFontPt", 10).toInt();
    p.hashOnExport  = hashFromStr(s.value("export/hash", "none").toString());
    p.collision     = collFromStr(s.value("export/collision", "rename").toString());
    p.exportBufferMiB = s.value("export/bufferMiB", 4).toInt();
    p.defaultExportDir = s.value("export/defaultDir", "").toString();
    p.previewKiB    = s.value("reading/previewKiB", 64).toInt();
    p.rememberOptanePaths = s.value("optane/rememberPaths", true).toBool();
    p.lastQlcPath    = s.value("optane/lastQlc", "").toString();
    p.lastOptanePath = s.value("optane/lastOptane", "").toString();
    p.lastCacheSector = s.value("optane/lastCacheSector", "").toString();
}

void savePrefs() {
    QSettings s;
    const Prefs& p = prefs();
    s.setValue("appearance/theme", themeStr(p.theme));
    s.setValue("appearance/accent", p.accentName);
    s.setValue("appearance/hexFontPt", p.hexFontPt);
    s.setValue("export/hash", hashStr(p.hashOnExport));
    s.setValue("export/collision", collStr(p.collision));
    s.setValue("export/bufferMiB", p.exportBufferMiB);
    s.setValue("export/defaultDir", p.defaultExportDir);
    s.setValue("reading/previewKiB", p.previewKiB);
    s.setValue("optane/rememberPaths", p.rememberOptanePaths);
    s.setValue("optane/lastQlc", p.lastQlcPath);
    s.setValue("optane/lastOptane", p.lastOptanePath);
    s.setValue("optane/lastCacheSector", p.lastCacheSector);
}

void applyTheme(QApplication& app, const Prefs& p) {
    // Fusion honours QPalette consistently across platforms, which native
    // styles don't — required for a real dark mode.
    app.setStyle(QStyleFactory::create("Fusion"));

    Accent ac = accentByName(p.accentName);
    QPalette pal;
    if (p.theme == Theme::Dark) {
        const QColor window(0x2B, 0x2E, 0x33), base(0x1E, 0x21, 0x25),
                     alt(0x26, 0x2A, 0x2F), text(0xE6, 0xE6, 0xE6),
                     button(0x33, 0x37, 0x3D), disabled(0x7A, 0x7A, 0x7A);
        pal.setColor(QPalette::Window, window);
        pal.setColor(QPalette::WindowText, text);
        pal.setColor(QPalette::Base, base);
        pal.setColor(QPalette::AlternateBase, alt);
        pal.setColor(QPalette::ToolTipBase, window);
        pal.setColor(QPalette::ToolTipText, text);
        pal.setColor(QPalette::Text, text);
        pal.setColor(QPalette::Button, button);
        pal.setColor(QPalette::ButtonText, text);
        pal.setColor(QPalette::BrightText, Qt::red);
        pal.setColor(QPalette::Disabled, QPalette::Text, disabled);
        pal.setColor(QPalette::Disabled, QPalette::ButtonText, disabled);
        pal.setColor(QPalette::Disabled, QPalette::WindowText, disabled);
    } else {
        const QColor window(0xF2, 0xF3, 0xF5), base(Qt::white),
                     alt(0xEC, 0xEE, 0xF1), text(0x1E, 0x21, 0x25),
                     button(0xE7, 0xE9, 0xEC), disabled(0xA0, 0xA0, 0xA0);
        pal.setColor(QPalette::Window, window);
        pal.setColor(QPalette::WindowText, text);
        pal.setColor(QPalette::Base, base);
        pal.setColor(QPalette::AlternateBase, alt);
        pal.setColor(QPalette::ToolTipBase, base);
        pal.setColor(QPalette::ToolTipText, text);
        pal.setColor(QPalette::Text, text);
        pal.setColor(QPalette::Button, button);
        pal.setColor(QPalette::ButtonText, text);
        pal.setColor(QPalette::BrightText, Qt::red);
        pal.setColor(QPalette::Disabled, QPalette::Text, disabled);
        pal.setColor(QPalette::Disabled, QPalette::ButtonText, disabled);
        pal.setColor(QPalette::Disabled, QPalette::WindowText, disabled);
    }
    // Accent drives selection + links in both themes.
    pal.setColor(QPalette::Highlight, ac.color);
    pal.setColor(QPalette::HighlightedText, ac.onColor);
    pal.setColor(QPalette::Link, ac.color);
    app.setPalette(pal);

    // The Fusion checkbox indicators are near-invisible on a dark base (the box
    // is drawn in a color close to the background). Restyle the indicators with
    // the accent so selection checkboxes are clearly visible and theme-matched:
    //   unchecked = outlined box, checked = solid accent, partial = dim accent.
    const QString acHex = ac.color.name(QColor::HexRgb);
    const QString borderHex =
        (p.theme == Theme::Dark ? QColor(0x8A, 0x8A, 0x8A) : QColor(0x88, 0x88, 0x88)).name();
    const QString acDim = QString("rgba(%1,%2,%3,150)")
                              .arg(ac.color.red()).arg(ac.color.green()).arg(ac.color.blue());
    app.setStyleSheet(QString(
        "QTreeView::indicator, QCheckBox::indicator {"
        "  width:14px; height:14px; border:1px solid %1; border-radius:3px;"
        "  background:transparent; }"
        "QTreeView::indicator:hover, QCheckBox::indicator:hover { border:1px solid %2; }"
        "QTreeView::indicator:checked, QCheckBox::indicator:checked {"
        "  background:%2; border:1px solid %2; }"
        "QTreeView::indicator:indeterminate, QCheckBox::indicator:indeterminate {"
        "  background:%3; border:1px solid %2; }")
        .arg(borderHex, acHex, acDim));
}

} // namespace de::gui
