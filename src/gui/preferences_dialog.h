#pragma once
#include <QDialog>

class QComboBox;
class QSpinBox;
class QLineEdit;
class QCheckBox;

// Preferences dialog: Appearance (theme + accent color combos, default dark),
// Export, and Reading options. Appearance changes preview live; all changes are
// committed to QSettings on OK. Emits themeChanged() so the main window can
// re-apply the palette and refresh fonts immediately.
class PreferencesDialog : public QDialog {
    Q_OBJECT
public:
    explicit PreferencesDialog(QWidget* parent = nullptr);

signals:
    void themeChanged();   // theme/accent/font changed — re-apply now

private:
    void loadFromPrefs();
    void applyLive();      // push appearance choices into prefs() + re-theme
    void commit();         // save everything to QSettings

    QComboBox* theme_ = nullptr;
    QComboBox* accent_ = nullptr;
    QSpinBox*  hexFont_ = nullptr;
    QComboBox* hash_ = nullptr;
    QComboBox* collision_ = nullptr;
    QLineEdit* exportDir_ = nullptr;
    QComboBox* preview_ = nullptr;
    QCheckBox* rememberOptane_ = nullptr;
};
