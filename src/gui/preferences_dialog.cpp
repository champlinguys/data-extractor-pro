#include "gui/preferences_dialog.h"
#include "gui/settings.h"

#include <QApplication>
#include <QTabWidget>
#include <QVBoxLayout>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QComboBox>
#include <QSpinBox>
#include <QLineEdit>
#include <QCheckBox>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QFileDialog>
#include <QPixmap>
#include <QIcon>

using namespace de::gui;

namespace {
// A small colored square icon, so the accent combo shows the actual color.
QIcon swatch(const QColor& c) {
    QPixmap pm(14, 14);
    pm.fill(c);
    return QIcon(pm);
}
} // namespace

PreferencesDialog::PreferencesDialog(QWidget* parent) : QDialog(parent) {
    setWindowTitle("Preferences");
    setMinimumWidth(460);
    auto* root = new QVBoxLayout(this);
    auto* tabs = new QTabWidget(this);
    root->addWidget(tabs);

    // ---- Appearance ----
    auto* appear = new QWidget;
    auto* af = new QFormLayout(appear);
    theme_ = new QComboBox;
    theme_->addItem("Dark", "dark");
    theme_->addItem("Light", "light");
    af->addRow("Theme:", theme_);

    accent_ = new QComboBox;
    for (const auto& a : accents())
        accent_->addItem(swatch(a.color), a.name, a.name);
    af->addRow("Accent color:", accent_);

    hexFont_ = new QSpinBox;
    hexFont_->setRange(7, 24);
    hexFont_->setSuffix(" pt");
    af->addRow("Hex/mono font size:", hexFont_);
    tabs->addTab(appear, "Appearance");

    // Appearance changes preview immediately.
    connect(theme_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]{ applyLive(); });
    connect(accent_, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this]{ applyLive(); });
    connect(hexFont_, QOverload<int>::of(&QSpinBox::valueChanged),
            this, [this]{ applyLive(); });

    // ---- Export ----
    auto* exp = new QWidget;
    auto* ef = new QFormLayout(exp);
    hash_ = new QComboBox;
    hash_->addItem("None", "none");
    hash_->addItem("MD5 (write .md5 sidecar)", "md5");
    hash_->addItem("SHA-256 (write .sha256 sidecar)", "sha256");
    ef->addRow("Hash on export:", hash_);

    collision_ = new QComboBox;
    collision_->addItem("Rename (keep both)", "rename");
    collision_->addItem("Overwrite", "overwrite");
    collision_->addItem("Skip", "skip");
    ef->addRow("On name collision:", collision_);

    exportDir_ = new QLineEdit;
    exportDir_->setPlaceholderText("(ask each time)");
    auto* browse = new QPushButton("Browse…");
    auto* dirRow = new QWidget;
    auto* dh = new QHBoxLayout(dirRow);
    dh->setContentsMargins(0, 0, 0, 0);
    dh->addWidget(exportDir_, 1);
    dh->addWidget(browse);
    connect(browse, &QPushButton::clicked, this, [this]{
        QString d = QFileDialog::getExistingDirectory(this, "Default export folder");
        if (!d.isEmpty()) exportDir_->setText(d);
    });
    ef->addRow("Default export folder:", dirRow);
    tabs->addTab(exp, "Export");

    // ---- Reading ----
    auto* rd = new QWidget;
    auto* rf = new QFormLayout(rd);
    preview_ = new QComboBox;
    for (int kib : {16, 64, 256, 1024})
        preview_->addItem(kib >= 1024 ? "1 MiB" : QString("%1 KiB").arg(kib), kib);
    rf->addRow("Hex preview size:", preview_);

    rememberOptane_ = new QCheckBox("Remember last image paths && cache sector");
    rf->addRow("Optane:", rememberOptane_);
    tabs->addTab(rd, "Reading");

    // ---- Buttons ----
    auto* bb = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel);
    root->addWidget(bb);
    connect(bb, &QDialogButtonBox::accepted, this, [this]{ commit(); accept(); });
    connect(bb, &QDialogButtonBox::rejected, this, [this]{
        // Revert any live appearance preview to the saved state.
        loadPrefs();
        applyTheme(*qApp, prefs());
        emit themeChanged();
        reject();
    });

    loadFromPrefs();
}

void PreferencesDialog::loadFromPrefs() {
    const Prefs& p = prefs();
    theme_->setCurrentIndex(theme_->findData(p.theme == Theme::Dark ? "dark" : "light"));
    int ai = accent_->findData(p.accentName);
    accent_->setCurrentIndex(ai < 0 ? 0 : ai);
    hexFont_->setValue(p.hexFontPt);

    hash_->setCurrentIndex(hash_->findData(
        p.hashOnExport == HashKind::Md5 ? "md5" :
        p.hashOnExport == HashKind::Sha256 ? "sha256" : "none"));
    collision_->setCurrentIndex(collision_->findData(
        p.collision == Collision::Overwrite ? "overwrite" :
        p.collision == Collision::Skip ? "skip" : "rename"));
    exportDir_->setText(p.defaultExportDir);

    int pi = preview_->findData(p.previewKiB);
    preview_->setCurrentIndex(pi < 0 ? 1 : pi);
    rememberOptane_->setChecked(p.rememberOptanePaths);
}

void PreferencesDialog::applyLive() {
    Prefs& p = prefs();
    p.theme = theme_->currentData().toString() == "light" ? Theme::Light : Theme::Dark;
    p.accentName = accent_->currentData().toString();
    p.hexFontPt = hexFont_->value();
    applyTheme(*qApp, p);
    emit themeChanged();
}

void PreferencesDialog::commit() {
    applyLive(); // ensure appearance fields are in prefs()
    Prefs& p = prefs();
    QString h = hash_->currentData().toString();
    p.hashOnExport = h == "md5" ? HashKind::Md5 :
                     h == "sha256" ? HashKind::Sha256 : HashKind::None;
    QString c = collision_->currentData().toString();
    p.collision = c == "overwrite" ? Collision::Overwrite :
                  c == "skip" ? Collision::Skip : Collision::Rename;
    p.defaultExportDir = exportDir_->text();
    p.previewKiB = preview_->currentData().toInt();
    p.rememberOptanePaths = rememberOptane_->isChecked();
    savePrefs();
}
