#include "gui/main_window.h"
#include "gui/hex_view.h"
#include "gui/settings.h"
#include "gui/preferences_dialog.h"
#include "gui/device_picker.h"
#include "core/file_times.h"
#include "core/file_owner.h"
#include "partition/partition.h"
#include "raid/raid.h"
#include "raid/raid_detect.h"
#include "optane/span_map.h"
#include "bitlocker/volume.h"
#include "bitlocker/fve.h"
#include "corestorage/cs.h"
#include "corestorage/source.h"

#include <QApplication>
#include <QFileDialog>
#include <QMessageBox>
#include <QMenuBar>
#include <QToolBar>
#include <QSplitter>
#include <QLabel>
#include <QStatusBar>
#include <QHeaderView>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QDialog>
#include <QFormLayout>
#include <QHBoxLayout>
#include <QLineEdit>
#include <QInputDialog>
#include <QPushButton>
#include <QDialogButtonBox>
#include <QProgressDialog>
#include <QMenu>
#include <QListWidget>
#include <QComboBox>
#include <QVBoxLayout>
#include <QTimer>
#include <QRegularExpression>
#include <functional>
#include <algorithm>
#include <vector>
#include <thread>
#include <fstream>
#include <filesystem>
#include <openssl/evp.h>

using namespace de;

namespace {
constexpr int RoleKind    = Qt::UserRole;       // ItemKind
constexpr int RolePart    = Qt::UserRole + 1;   // partition ordinal
constexpr int RoleNodeId  = Qt::UserRole + 2;   // FsNode.id
constexpr int RoleIsDir   = Qt::UserRole + 3;
constexpr int RoleSize    = Qt::UserRole + 4;
constexpr int RoleLoaded  = Qt::UserRole + 5;   // lazy-load guard
constexpr int RoleName    = Qt::UserRole + 6;
constexpr int RoleLocked  = Qt::UserRole + 7;   // partition is a locked encrypted volume
constexpr int RoleCrypto  = Qt::UserRole + 8;   // "bitlocker" or "corestorage"

QString humanSize(uint64_t n) {
    const char* u[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double v = static_cast<double>(n);
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; ++i; }
    return i == 0 ? QString("%1 B").arg(n) : QString::asprintf("%.1f %s", v, u[i]);
}
} // namespace

MainWindow::MainWindow() {
    setWindowTitle("Data Extractor Pro");
    resize(1100, 720);

    auto* openAct = new QAction("&Open Image...", this);
    openAct->setShortcut(QKeySequence::Open);
    connect(openAct, &QAction::triggered, this, &MainWindow::openImage);

    auto* openOptaneAct = new QAction("Open &Optane Set...", this);
    openOptaneAct->setShortcut(QKeySequence("Ctrl+Shift+O"));
    connect(openOptaneAct, &QAction::triggered, this, &MainWindow::openOptaneSet);

    auto* openRaidAct = new QAction("Open &RAID Set...", this);
    openRaidAct->setShortcut(QKeySequence("Ctrl+R"));
    connect(openRaidAct, &QAction::triggered, this, &MainWindow::openRaidSet);

    auto* exportAct = new QAction("&Export Selected...", this);
    exportAct->setShortcut(QKeySequence("Ctrl+E"));
    connect(exportAct, &QAction::triggered, this, &MainWindow::exportSelected);

    auto* prefsAct = new QAction("&Preferences...", this);
    prefsAct->setShortcut(QKeySequence::Preferences);
    connect(prefsAct, &QAction::triggered, this, &MainWindow::openPreferences);

    auto* fileMenu = menuBar()->addMenu("&File");
    fileMenu->addAction(openAct);
    fileMenu->addAction(openOptaneAct);
    fileMenu->addAction(openRaidAct);
    fileMenu->addAction(exportAct);
    fileMenu->addSeparator();
    auto* quitAct = fileMenu->addAction("&Quit");
    connect(quitAct, &QAction::triggered, qApp, &QApplication::quit);

    auto* editMenu = menuBar()->addMenu("&Edit");
    editMenu->addAction(prefsAct);

    auto* tb = addToolBar("Main");
    tb->addAction(openAct);
    tb->addAction(openOptaneAct);
    tb->addAction(exportAct);

    tree_ = new QTreeWidget;
    tree_->setColumnCount(3);
    tree_->setHeaderLabels({"Name", "Size", "Record"});
    tree_->header()->setSectionResizeMode(0, QHeaderView::Stretch);
    tree_->setSelectionMode(QAbstractItemView::ExtendedSelection);
    // Large directories can hold thousands of rows; uniform row heights let Qt
    // skip per-row height computation, a big scroll/populate speedup.
    tree_->setUniformRowHeights(true);
    connect(tree_, &QTreeWidget::itemExpanded, this, &MainWindow::onItemExpanded);
    connect(tree_, &QTreeWidget::itemSelectionChanged, this, &MainWindow::onItemSelected);
    connect(tree_, &QTreeWidget::itemChanged, this, &MainWindow::onItemChanged);
    tree_->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(tree_, &QTreeWidget::customContextMenuRequested,
            this, &MainWindow::showTreeMenu);

    hex_ = new HexView;

    auto* split = new QSplitter(Qt::Horizontal);
    split->addWidget(tree_);
    split->addWidget(hex_);
    split->setStretchFactor(0, 3);
    split->setStretchFactor(1, 2);
    setCentralWidget(split);

    status_ = new QLabel("Open a disk image to begin (File -> Open Image)");
    statusBar()->addWidget(status_);

    applyPrefs(); // hex font size, etc. from persisted preferences
}

void MainWindow::openPreferences() {
    PreferencesDialog dlg(this);
    connect(&dlg, &PreferencesDialog::themeChanged, this, &MainWindow::applyPrefs);
    dlg.exec();
}

void MainWindow::applyPrefs() {
    // Apply the theme-driven bits the palette alone doesn't cover: the hex
    // view's monospace font size. Re-preview the current selection so the new
    // preview-size limit and font take effect immediately.
    QFont f = hex_->font();
    f.setPointSize(de::gui::prefs().hexFontPt);
    hex_->setFont(f);
    onItemSelected();
}

void MainWindow::openImage() {
    QString path = QFileDialog::getOpenFileName(
        this, "Open disk image", QString(),
        "Disk images (*.img *.dd *.raw *.bin *.dsk *.001);;All files (*)");
    if (!path.isEmpty()) loadImage(path);
}

void MainWindow::openOptaneSet() {
    QDialog dlg(this);
    dlg.setWindowTitle("Open Optane Set");
    dlg.setMinimumWidth(560);
    auto* form = new QFormLayout(&dlg);

    // A path field with a Browse button.
    auto pathRow = [&](const QString& title) -> QLineEdit* {
        auto* edit = new QLineEdit(&dlg);
        auto* browse = new QPushButton("Browse...", &dlg);
        auto* row = new QWidget(&dlg);
        auto* h = new QHBoxLayout(row);
        h->setContentsMargins(0, 0, 0, 0);
        h->addWidget(edit, 1);
        h->addWidget(browse);
        connect(browse, &QPushButton::clicked, this, [this, edit] {
            QString f = QFileDialog::getOpenFileName(
                this, "Select image", QString(),
                "Disk images (*.img *.dd *.raw *.bin *.001);;All files (*)");
            if (!f.isEmpty()) edit->setText(f);
        });
        form->addRow(title, row);
        return edit;
    };

    QLineEdit* qlcEdit = pathRow("QLC image:");
    QLineEdit* optEdit = pathRow("Optane image:");
    auto* hintEdit = new QLineEdit(&dlg);
    hintEdit->setPlaceholderText("Intel Cache start sector (blank = auto-scan, slow)");
    form->addRow("Cache sector:", hintEdit);

    // Pre-fill from the last session if the user enabled it (never the key).
    if (de::gui::prefs().rememberOptanePaths) {
        qlcEdit->setText(de::gui::prefs().lastQlcPath);
        optEdit->setText(de::gui::prefs().lastOptanePath);
        hintEdit->setText(de::gui::prefs().lastCacheSector);
    }
    auto* keyEdit = new QLineEdit(&dlg);
    keyEdit->setPlaceholderText("48-digit BitLocker recovery key (optional)");
    form->addRow("Recovery key:", keyEdit);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                         &dlg);
    form->addRow(buttons);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);

    if (dlg.exec() != QDialog::Accepted) return;
    if (qlcEdit->text().isEmpty() || optEdit->text().isEmpty()) {
        QMessageBox::warning(this, "Open Optane Set", "Both images are required.");
        return;
    }
    uint64_t hint = UINT64_MAX;
    QString h = hintEdit->text().trimmed();
    if (!h.isEmpty()) hint = h.toULongLong() * 512ull;

    // Remember paths + cache sector for next time (deliberately NOT the key).
    if (de::gui::prefs().rememberOptanePaths) {
        de::gui::prefs().lastQlcPath = qlcEdit->text();
        de::gui::prefs().lastOptanePath = optEdit->text();
        de::gui::prefs().lastCacheSector = h;
        de::gui::savePrefs();
    }

    loadOptaneSet(qlcEdit->text(), optEdit->text(), hint, keyEdit->text().trimmed());
}

void MainWindow::loadOptaneSet(const QString& qlcPath, const QString& optanePath,
                               uint64_t cacheHintBytes, const QString& recoveryKey) {
    std::shared_ptr<ImageSource> qlc, opt;
    try {
        qlc = std::make_shared<RawImageSource>(qlcPath.toStdString());
        opt = std::make_shared<RawImageSource>(optanePath.toStdString());
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Open failed", e.what());
        return;
    }
    std::string key = recoveryKey.toStdString();
    // The merge + BitLocker key-stretch + reads over a slow image take several
    // seconds - do them on the worker so the UI never freezes.
    runOpen("Optane reconstruction", [this, qlc, opt, cacheHintBytes, key] {
        std::string why;
        auto merged = de::optane::makeSpanMerge(qlc, opt, cacheHintBytes, &why);
        if (!merged) {
            // Not every Optane module has a linear span we can decode. Rather
            // than refuse the case, open the QLC on its own and warn: it is
            // usually current except for blocks written shortly before failure.
            openWarning_ = "Couldn't reconstruct the Optane cache (" + why + ").\n\n"
                           "Opening the QLC image on its own. Data written shortly "
                           "before the failure may be stale or missing.";
            merged = qlc;
        }
        openedSource_ = merged;
        openedVols_ = prepareVolumes(merged, key);
    });
}

void MainWindow::openSourceSpec(const QString& spec) {
    if (!spec.startsWith("raid:")) { loadImage(spec); return; }

    // raid:auto:dev1,dev2  |  raid:stripe:128k:dev1,dev2  |  raid:concat:...
    QStringList parts = spec.mid(5).split(':');
    if (parts.size() < 2) {
        QMessageBox::critical(this, "Open failed",
                              "Expected raid:auto:<drive>,<drive> or "
                              "raid:stripe:<size>:<drive>,<drive>");
        return;
    }
    const QString mode = parts.takeFirst();
    uint64_t stripeBytes = 128 * 1024;
    if (mode == "stripe" && parts.size() >= 2) {
        QString s = parts.takeFirst().toLower();
        uint64_t mult = s.endsWith('k') ? 1024 : s.endsWith('m') ? 1024 * 1024 : 1;
        stripeBytes = s.remove(QRegularExpression("[km]$")).toULongLong() * mult;
    }

    std::vector<std::shared_ptr<ImageSource>> devs;
    for (const QString& path : parts.join(':').split(',', Qt::SkipEmptyParts)) {
        try {
            devs.push_back(std::make_shared<RawImageSource>(path.toStdString()));
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "Open failed", e.what());
            return;
        }
    }
    if (devs.empty()) return;

    const int modeIndex = mode == "auto"     ? 0
                          : mode == "stripe" ? 1
                          : mode == "concat" ? 2
                                             : 3;
    openRaidDevices(devs, modeIndex, stripeBytes);
}

// Shared by the dialog and the command line: assemble the set (detecting the
// geometry if asked), check it, and populate the tree.
void MainWindow::openRaidDevices(std::vector<std::shared_ptr<ImageSource>> devs,
                                 int modeIndex, uint64_t stripeBytes) {
    runOpen("RAID set", [this, devs, modeIndex, stripeBytes] {
        std::shared_ptr<ImageSource> disk;
        if (modeIndex == 0) {
            auto r = de::raid::detect(devs);
            for (const auto& n : r.notes) openInfo_ += n + "\n";
            if (!r.assembled) {
                openError_ = "These drives could not be reassembled: " + r.summary +
                             "\n\nIf you know how the set was configured, choose "
                             "the geometry by hand instead.";
                return;
            }
            openInfo_ = "Reassembled as:\n  " + r.layout.describe() + "\n\n" +
                        "Confirmed by: " + r.summary + "\n" + openInfo_;
            disk = de::raid::assemble(r.layout);
        } else {
            de::raid::Layout layout;
            layout.level = modeIndex == 1   ? de::raid::Level::Stripe
                           : modeIndex == 2 ? de::raid::Level::Concat
                                            : de::raid::Level::Mirror;
            layout.stripeBytes = stripeBytes;
            layout.origin = "chosen by hand";
            for (const auto& d : devs) {
                de::raid::Member m;
                m.src = d;
                m.label = d->name();
                layout.members.push_back(std::move(m));
            }
            disk = de::raid::assemble(layout);
            if (!disk) {
                openError_ = "That geometry is not usable.";
                return;
            }
            // Check the chosen geometry rather than trusting it: a wrong stripe
            // size produces a browsable-looking volume full of shredded files.
            std::string ev;
            bool fsVerified = false;
            de::raid::scoreAssembled(disk, true, &ev, &fsVerified);
            if (fsVerified)
                openInfo_ = layout.describe() + "\n\nVerified: " + ev;
            else
                openWarning_ = "This geometry does not verify - the filesystems "
                               "on it do not read back correctly (" + ev +
                               ").\nAnything you export may be corrupt. Try "
                               "auto-detect, or a different stripe size.";
        }
        openedSource_ = disk;
        openedVols_ = prepareVolumes(disk, "");
    });
}

void MainWindow::openRaidSet() {
    QDialog dlg(this);
    dlg.setWindowTitle("Open RAID Set");
    dlg.setMinimumWidth(620);
    auto* layout = new QVBoxLayout(&dlg);

    layout->addWidget(new QLabel(
        "Add every drive in the set. Order only matters if you choose a "
        "geometry by hand -\nauto-detect works it out, then checks the result "
        "by reading the filesystem on it.", &dlg));

    auto* list = new QListWidget(&dlg);
    list->setSelectionMode(QAbstractItemView::ExtendedSelection);
    layout->addWidget(list);

    auto* buttonRow = new QHBoxLayout();
    auto* addDevice = new QPushButton("Add Drive...", &dlg);
    auto* addImage = new QPushButton("Add Image File...", &dlg);
    auto* moveUp = new QPushButton("Move Up", &dlg);
    auto* moveDown = new QPushButton("Move Down", &dlg);
    auto* remove = new QPushButton("Remove", &dlg);
    for (auto* b : {addDevice, addImage, moveUp, moveDown, remove})
        buttonRow->addWidget(b);
    layout->addLayout(buttonRow);

    connect(addDevice, &QPushButton::clicked, [&] {
        // A file browser is no way to choose a physical disk: show the drives
        // themselves, with the model, serial, size and what is actually on
        // each one, so the right two can be told apart.
        for (const QString& p : de::gui::pickBlockDevices(
                 &dlg, "Select drives in the set", true)) {
            bool already = false;
            for (int i = 0; i < list->count(); ++i)
                if (list->item(i)->text() == p) already = true;
            if (!already) list->addItem(p);
        }
    });
    connect(addImage, &QPushButton::clicked, [&] {
        QStringList ps = QFileDialog::getOpenFileNames(
            &dlg, "Add image files", QString(),
            "Disk images (*.img *.dd *.raw *.bin *.001);;All files (*)");
        for (const auto& p : ps) list->addItem(p);
    });
    connect(remove, &QPushButton::clicked, [&] {
        qDeleteAll(list->selectedItems());
    });
    auto move = [list](int delta) {
        int row = list->currentRow();
        int to = row + delta;
        if (row < 0 || to < 0 || to >= list->count()) return;
        auto* item = list->takeItem(row);
        list->insertItem(to, item);
        list->setCurrentRow(to);
    };
    connect(moveUp, &QPushButton::clicked, [&] { move(-1); });
    connect(moveDown, &QPushButton::clicked, [&] { move(1); });

    auto* form = new QFormLayout();
    auto* mode = new QComboBox(&dlg);
    mode->addItem("Work it out automatically (recommended)");
    mode->addItem("RAID 0 - striped");
    mode->addItem("Concatenated - JBOD / spanned");
    mode->addItem("RAID 1 - mirrored");
    form->addRow("Geometry:", mode);

    auto* stripe = new QComboBox(&dlg);
    for (const char* s : {"4 KiB", "8 KiB", "16 KiB", "32 KiB", "64 KiB",
                          "128 KiB", "256 KiB", "512 KiB", "1 MiB", "2 MiB"})
        stripe->addItem(s);
    stripe->setCurrentIndex(5);
    stripe->setEnabled(false);
    form->addRow("Stripe size:", stripe);
    connect(mode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            [stripe](int i) { stripe->setEnabled(i == 1); });
    layout->addLayout(form);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                         &dlg);
    connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    layout->addWidget(buttons);

    if (dlg.exec() != QDialog::Accepted) return;

    std::vector<std::shared_ptr<ImageSource>> devs;
    QStringList labels;
    for (int i = 0; i < list->count(); ++i) {
        QString path = list->item(i)->text();
        try {
            devs.push_back(std::make_shared<RawImageSource>(path.toStdString()));
            labels << path;
        } catch (const std::exception& e) {
            QMessageBox::critical(this, "Open failed",
                                  QString("%1\n\nReading a drive directly usually "
                                          "needs root - try starting the program "
                                          "with sudo.").arg(e.what()));
            return;
        }
    }
    if (devs.size() < 2) {
        QMessageBox::warning(this, "Open RAID Set",
                             "Add at least two drives.");
        return;
    }

    const int modeIndex = mode->currentIndex();
    const uint64_t stripeBytes = 4096ull << stripe->currentIndex();
    openRaidDevices(std::move(devs), modeIndex, stripeBytes);
}

void MainWindow::loadImage(const QString& path) {
    std::shared_ptr<ImageSource> src;
    try {
        src = std::make_shared<RawImageSource>(path.toStdString());
    } catch (const std::exception& e) {
        QMessageBox::critical(this, "Open failed", e.what());
        return;
    }
    runOpen(QFileInfo(path).fileName(), [this, src] {
        openedSource_ = src;
        openedVols_ = prepareVolumes(src, "");
    });
}

std::vector<MainWindow::PreparedVol>
MainWindow::prepareVolumes(std::shared_ptr<ImageSource> source, const std::string& key) {
    std::vector<PreparedVol> out;
    for (auto& p : scanPartitions(source)) {
        std::shared_ptr<ImageSource> vol = p.asSource(source);
        // A BitLocker volume records its own size; prefer it over a partition
        // table that may be a generation behind (see reconcileVolumeSize).
        std::string note;
        vol = de::bitlocker::reconcileVolumeSize(source, p.firstByte, vol, &note);
        if (!note.empty())
            openWarning_ += "Partition " + std::to_string(p.index) + ": " + note + "\n";
        QString fsName = QString::fromStdString(detectFilesystemName(*vol));
        if (!key.empty() && fsName.startsWith("BitLocker")) {
            // A cipher we can't decrypt would only yield garbage, so check the
            // method before trying the key (see methodSupported).
            auto md = de::bitlocker::parseFve(*vol);
            if (md && !de::bitlocker::methodSupported(md->method)) {
                fsName = QString("BitLocker %1 (cipher not supported yet)")
                             .arg(de::bitlocker::methodName(md->method));
            } else if (auto dec = de::bitlocker::unlockVolume(vol, key)) {
                vol = dec;
                fsName = QString::fromStdString(detectFilesystemName(*vol))
                             + "  (BitLocker unlocked)";
            } else {
                fsName = "BitLocker (unlock failed - wrong key?)";
            }
        }
        out.push_back({p.index, p.typeName, fsName.toStdString(), p.lengthBytes, vol});
    }
    return out;
}

void MainWindow::runOpen(const QString& label, std::function<void()> producer) {
    openDone_ = false;
    openError_.clear();
    openWarning_.clear();
    openInfo_.clear();
    openedSource_.reset();
    openedVols_.clear();

    // Not cancelable: the engine calls (merge/unlock) aren't interruptible.
    // The busy dialog exists so the event loop keeps running (no "not
    // responding") while the worker does the heavy lifting.
    QProgressDialog progress("Reconstructing and reading the volume...\nThis can take "
                             "a moment over a slow drive.", QString(), 0, 0, this);
    progress.setWindowTitle("Opening");
    progress.setWindowModality(Qt::ApplicationModal);
    progress.setCancelButton(nullptr);
    progress.setMinimumDuration(0);

    std::thread worker([this, producer] { producer(); openDone_ = true; });

    QTimer timer;
    connect(&timer, &QTimer::timeout, this, [this, &progress] {
        if (openDone_.load()) progress.accept();
    });
    timer.start(80);
    progress.exec();
    timer.stop();
    worker.join();

    if (!openError_.empty()) {
        QMessageBox::critical(this, "Open", QString::fromStdString(openError_));
        return;
    }
    if (!openWarning_.empty())
        QMessageBox::warning(this, "Open", QString::fromStdString(openWarning_));
    if (!openInfo_.empty())
        QMessageBox::information(this, "Open", QString::fromStdString(openInfo_));
    buildTree(openedVols_, label, openedSource_ ? openedSource_->size() : 0);
}

void MainWindow::buildTree(const std::vector<PreparedVol>& vols, const QString& label,
                           unsigned long long totalSize) {
    image_ = openedSource_;
    tree_->clear();
    mounts_.clear();
    volumes_.clear();
    hex_->clearData();

    for (const auto& v : vols) {
        volumes_[v.index] = v.source;
        QString fsName = QString::fromStdString(v.fsName);
        auto* item = new QTreeWidgetItem(tree_);
        item->setText(0, QString("[%1] %2  (%3)")
                             .arg(v.index)
                             .arg(QString::fromStdString(v.typeName))
                             .arg(fsName));
        item->setText(1, humanSize(v.lengthBytes));
        item->setData(0, RoleKind, static_cast<int>(ItemKind::Partition));
        item->setData(0, RolePart, v.index);
        item->setData(0, RoleLoaded, false);
        // Offer the right-click unlock only where a key can actually help: a
        // locked volume or a wrong-key attempt. A "cipher not supported yet"
        // row is a correct-key dead end, so it gets no unlock action.
        bool bdeLocked = fsName.startsWith("BitLocker (encrypted)") ||
                         fsName.startsWith("BitLocker (unlock failed");
        bool csLocked  = fsName.startsWith("CoreStorage / FileVault 2") ||
                         fsName.startsWith("FileVault 2 (unlock failed");
        bool unlockable = bdeLocked || csLocked;
        item->setData(0, RoleLocked, unlockable);
        item->setData(0, RoleCrypto,
                      csLocked ? QString("corestorage") : QString("bitlocker"));
        if (bdeLocked)
            item->setToolTip(0, "Locked BitLocker volume - right-click to enter "
                                "the recovery key");
        else if (csLocked)
            item->setToolTip(0, "Locked FileVault 2 volume - right-click to enter "
                                "the volume key");
        // Add the lazy-load placeholder (what gives the row its expand arrow)
        // only for a filesystem detectFilesystem() can mount: not a stub label
        // ("... not yet implemented"), not an unrecognised volume, and not any
        // BitLocker row that isn't actually unlocked (locked, wrong key, or a
        // cipher we can't decrypt).
        bool bitlockerNotBrowsable =
            fsName.startsWith("BitLocker") && !fsName.contains("unlocked");
        bool corestorageNotBrowsable =
            (fsName.startsWith("CoreStorage") || fsName.startsWith("FileVault 2")) &&
            !fsName.contains("unlocked");
        bool browsable = !fsName.contains("not yet implemented") &&
                          fsName != "Unknown" &&
                          !bitlockerNotBrowsable && !corestorageNotBrowsable;
        if (browsable)
            item->addChild(new QTreeWidgetItem({QString("...")}));
    }
    status_->setText(QString("%1 - %2, %3 partition(s)")
                         .arg(label).arg(humanSize(totalSize)).arg(vols.size()));
}

void MainWindow::showTreeMenu(const QPoint& pos) {
    QTreeWidgetItem* item = tree_->itemAt(pos);
    if (!item) return;
    // Only partition rows carry an unlock action, and only while still locked.
    auto kind = static_cast<ItemKind>(item->data(0, RoleKind).toInt());
    if (kind != ItemKind::Partition) return;

    QMenu menu(this);
    if (item->data(0, RoleLocked).toBool()) {
        bool cs = item->data(0, RoleCrypto).toString() == "corestorage";
        QAction* unlock = menu.addAction(cs ? "Unlock FileVault 2..."
                                            : "Unlock BitLocker...");
        if (cs)
            connect(unlock, &QAction::triggered, this,
                    [this, item] { unlockCoreStorageItem(item); });
        else
            connect(unlock, &QAction::triggered, this,
                    [this, item] { unlockBitLockerItem(item); });
    }
    if (!menu.isEmpty())
        menu.exec(tree_->viewport()->mapToGlobal(pos));
}

void MainWindow::unlockBitLockerItem(QTreeWidgetItem* partitionItem) {
    int part = partitionItem->data(0, RolePart).toInt();
    auto vit = volumes_.find(part);
    if (vit == volumes_.end() || !vit->second) return;

    bool ok = false;
    QString key = QInputDialog::getText(
        this, "Unlock BitLocker",
        "Enter the 48-digit BitLocker recovery key for this volume:",
        QLineEdit::Normal, QString(), &ok);
    key = key.trimmed();
    if (!ok || key.isEmpty()) return;

    // Key stretching (~1M SHA-256 rounds) plus reads over a slow (possibly
    // reconstructed Optane) image can take several seconds, so run the unlock on
    // a worker thread behind a modal busy dialog - same pattern as runOpen - to
    // keep the event loop responsive instead of freezing the window.
    std::shared_ptr<ImageSource> enc = vit->second;
    std::string keyStd = key.toStdString();
    std::shared_ptr<ImageSource> dec;
    bool cipherSupported = true;   // set from the volume's declared method
    std::string cipherName;
    std::atomic<bool> done{false};

    QProgressDialog progress("Deriving the key and unlocking the volume...\n"
                             "This can take a moment.", QString(), 0, 0, this);
    progress.setWindowTitle("Unlocking");
    progress.setWindowModality(Qt::ApplicationModal);
    progress.setCancelButton(nullptr);   // the unlock isn't interruptible
    progress.setMinimumDuration(0);

    std::thread worker([&] {
        // The cipher is a property of the volume, independent of the key: even a
        // correct key can't yield readable data for a method we can't decrypt
        // (e.g. the Elephant-diffuser CBC variants), so note it up front.
        if (auto md = de::bitlocker::parseFve(*enc)) {
            cipherName = de::bitlocker::methodName(md->method);
            cipherSupported = de::bitlocker::methodSupported(md->method);
        }
        dec = de::bitlocker::unlockVolume(enc, keyStd);
        done = true;
    });
    QTimer timer;
    connect(&timer, &QTimer::timeout, this, [&] {
        if (done.load()) progress.accept();
    });
    timer.start(80);
    progress.exec();
    timer.stop();
    worker.join();

    if (!dec) {
        QMessageBox::warning(this, "Unlock BitLocker",
            "Could not unlock this volume. Check the recovery key and try again.\n\n"
            "(The key must be the 48-digit recovery key, in eight groups of six "
            "digits.)");
        return;
    }

    if (!cipherSupported) {
        // Key was right (dec is non-null), but this build can't decrypt the
        // volume's cipher, so its plaintext would be garbage. Say so plainly and
        // mark the row rather than presenting an empty/unreadable filesystem.
        QString cn = QString::fromStdString(cipherName);
        QMessageBox::warning(this, "Unlock BitLocker",
            QString("The recovery key is correct, but this volume uses %1, which "
                    "this build cannot decrypt yet.\n\nSupport for that cipher is "
                    "still pending.").arg(cn));
        partitionItem->setData(0, RoleLocked, false);   // retrying won't help
        partitionItem->setToolTip(0, QString());
        QString typeName = QString(partitionItem->text(0)).section('(', 0, 0).trimmed();
        partitionItem->setText(0, QString("%1  (BitLocker %2 - cipher not supported yet)")
                                      .arg(typeName).arg(cn));
        return;
    }

    // Swap the decrypted view in, drop any stale mount, and turn the row into a
    // browsable one with a fresh lazy placeholder.
    volumes_[part] = dec;
    mounts_.erase(part);
    partitionItem->setData(0, RoleLocked, false);
    partitionItem->setData(0, RoleLoaded, false);
    partitionItem->setToolTip(0, QString());

    QString fsName = QString::fromStdString(detectFilesystemName(*dec))
                         + "  (BitLocker unlocked)";
    QString typeName = QString(partitionItem->text(0)).section('(', 0, 0).trimmed();
    partitionItem->setText(0, QString("%1  (%2)").arg(typeName).arg(fsName));

    while (partitionItem->childCount() > 0)
        delete partitionItem->takeChild(0);
    partitionItem->addChild(new QTreeWidgetItem({QString("...")}));
    partitionItem->setExpanded(true);
    status_->setText("BitLocker volume unlocked.");
}

void MainWindow::unlockCoreStorageItem(QTreeWidgetItem* partitionItem) {
    int part = partitionItem->data(0, RolePart).toInt();
    auto vit = volumes_.find(part);
    if (vit == volumes_.end() || !vit->second) return;

    bool ok = false;
    QString keyText = QInputDialog::getText(
        this, "Unlock FileVault 2",
        "Enter the CoreStorage volume key for this volume, in hex\n"
        "(64 characters for AES-XTS-128):",
        QLineEdit::Normal, QString(), &ok);
    keyText = keyText.trimmed();
    if (!ok || keyText.isEmpty()) return;

    auto key = de::corestorage::parseVolumeKey(keyText.toStdString());
    if (!key) {
        QMessageBox::warning(this, "Unlock FileVault 2",
            "That is not a usable volume key.\n\n"
            "It must be 64 hex characters for AES-XTS-128 (a 32-byte key), or "
            "128 for AES-XTS-256.");
        return;
    }

    // Finding the logical volume means trial-decrypting a sector per candidate
    // offset over what may be a slow image, so run it on a worker thread behind
    // a modal busy dialog - the same pattern as the BitLocker unlock above.
    std::shared_ptr<ImageSource> enc = vit->second;
    std::shared_ptr<ImageSource> dec;
    std::string note;
    std::atomic<bool> done{false};

    QProgressDialog progress("Looking for the logical volume and checking the key...\n"
                             "This can take a moment.", QString(), 0, 0, this);
    progress.setWindowTitle("Unlocking");
    progress.setWindowModality(Qt::ApplicationModal);
    progress.setCancelButton(nullptr);   // the unlock isn't interruptible
    progress.setMinimumDuration(0);

    std::thread worker([&] {
        dec = de::corestorage::unlockVolume(enc, *key, &note);
        done = true;
    });
    QTimer timer;
    connect(&timer, &QTimer::timeout, this, [&] {
        if (done.load()) progress.accept();
    });
    timer.start(80);
    progress.exec();
    timer.stop();
    worker.join();

    if (!dec) {
        QMessageBox::warning(this, "Unlock FileVault 2",
            QString("Could not unlock this volume.\n\n%1")
                .arg(QString::fromStdString(note)));
        QString typeName = QString(partitionItem->text(0)).section('(', 0, 0).trimmed();
        partitionItem->setText(0, QString("%1  (FileVault 2 (unlock failed - wrong key?))")
                                      .arg(typeName));
        return;
    }

    // Swap the decrypted view in, drop any stale mount, and turn the row into a
    // browsable one with a fresh lazy placeholder.
    volumes_[part] = dec;
    mounts_.erase(part);
    partitionItem->setData(0, RoleLocked, false);
    partitionItem->setData(0, RoleLoaded, false);
    partitionItem->setToolTip(0, QString());

    QString fsName = QString::fromStdString(detectFilesystemName(*dec))
                         + "  (FileVault 2 unlocked)";
    QString typeName = QString(partitionItem->text(0)).section('(', 0, 0).trimmed();
    partitionItem->setText(0, QString("%1  (%2)").arg(typeName).arg(fsName));

    while (partitionItem->childCount() > 0)
        delete partitionItem->takeChild(0);
    partitionItem->addChild(new QTreeWidgetItem({QString("...")}));
    partitionItem->setExpanded(true);
    status_->setText(QString::fromStdString("FileVault 2 volume unlocked - " + note));
}

Filesystem* MainWindow::mountFor(QTreeWidgetItem* partitionItem) {
    int part = partitionItem->data(0, RolePart).toInt();
    auto it = mounts_.find(part);
    if (it != mounts_.end()) return it->second.get();
    auto vit = volumes_.find(part);
    if (vit == volumes_.end()) return nullptr;
    auto fs = detectFilesystem(vit->second);
    Filesystem* raw = fs.get();
    mounts_[part] = std::move(fs);
    return raw;
}

QTreeWidgetItem* MainWindow::makeNode(const FsNode& node, int partIndex, ItemKind kind) {
    auto* item = new QTreeWidgetItem;
    item->setText(0, QString::fromStdString(node.name));
    item->setText(1, node.isDir ? QString() : humanSize(node.size));
    item->setText(2, QString::number(node.id));
    item->setData(0, RoleKind, static_cast<int>(kind));
    item->setData(0, RolePart, partIndex);
    item->setData(0, RoleNodeId, static_cast<qulonglong>(node.id));
    item->setData(0, RoleIsDir, node.isDir);
    item->setData(0, RoleSize, static_cast<qulonglong>(node.size));
    item->setData(0, RoleLoaded, false);
    item->setData(0, RoleName, QString::fromStdString(node.name));
    // Checkbox for export selection (folders included). Checking a folder
    // exports its whole subtree (walked from the filesystem, so lazy-unloaded
    // children are included). We manage tri-state manually rather than with
    // Qt::ItemIsAutoTristate, because that flag suppresses the folder's own
    // checkbox while its only child is the lazy "..." placeholder.
    item->setFlags(item->flags() | Qt::ItemIsUserCheckable);
    item->setCheckState(0, Qt::Unchecked);
    if (node.isDir)
        item->addChild(new QTreeWidgetItem({QString("...")})); // lazy placeholder
    return item;
}

void MainWindow::populateChildren(QTreeWidgetItem* item) {
    if (item->data(0, RoleLoaded).toBool()) return;
    item->setData(0, RoleLoaded, true);

    Filesystem* fs = mountFor(item);
    // Remove the placeholder child.
    while (item->childCount() > 0) delete item->takeChild(0);
    if (!fs) {
        item->addChild(new QTreeWidgetItem({QString("(no readable filesystem)")}));
        return;
    }

    int part = item->data(0, RolePart).toInt();
    auto kind = static_cast<ItemKind>(item->data(0, RoleKind).toInt());
    FsNode dir;
    if (kind == ItemKind::Partition) {
        dir = fs->root();
    } else {
        dir.id = item->data(0, RoleNodeId).toULongLong();
        dir.isDir = true;
    }

    auto children = fs->listDir(dir);
    // Directories first, then alphabetical - the usual browse ordering.
    std::sort(children.begin(), children.end(), [](const FsNode& a, const FsNode& b) {
        if (a.isDir != b.isDir) return a.isDir > b.isDir;
        return a.name < b.name;
    });

    // Bulk-insert: building the items then adding them in one addChildren()
    // call avoids a per-item layout/repaint (the cause of the hang on large
    // folders). Disabling updates and blocking the itemChanged signal during
    // the insert keeps it from doing thousands of redundant passes.
    tree_->setUpdatesEnabled(false);
    QSignalBlocker blocker(tree_);

    bool parentChecked = (item->flags() & Qt::ItemIsUserCheckable) &&
                         item->checkState(0) == Qt::Checked;
    QList<QTreeWidgetItem*> kids;
    kids.reserve(static_cast<int>(children.size()));
    for (const auto& c : children) {
        auto* child = makeNode(c, part, c.isDir ? ItemKind::Directory : ItemKind::File);
        // Newly-revealed children inherit a checked parent's export selection.
        if (parentChecked) child->setCheckState(0, Qt::Checked);
        kids.push_back(child);
    }
    if (kids.isEmpty())
        kids.push_back(new QTreeWidgetItem({QString("(empty)")}));
    item->addChildren(kids);

    tree_->setUpdatesEnabled(true);
}

void MainWindow::onItemExpanded(QTreeWidgetItem* item) {
    auto kind = static_cast<ItemKind>(item->data(0, RoleKind).toInt());
    if (kind == ItemKind::Partition || kind == ItemKind::Directory)
        populateChildren(item);
}

void MainWindow::onItemSelected() {
    auto items = tree_->selectedItems();
    if (items.size() != 1) return;
    auto* item = items.first();
    auto kind = static_cast<ItemKind>(item->data(0, RoleKind).toInt());
    if (kind != ItemKind::File) { hex_->clearData(); return; }

    Filesystem* fs = mountFor(item);
    if (!fs) return;
    FsNode f;
    f.id = item->data(0, RoleNodeId).toULongLong();
    f.size = item->data(0, RoleSize).toULongLong();
    // Preview only the head of the file, per the configured preview size, so
    // selecting a multi-GB file doesn't read it all into memory.
    const size_t kPreview = static_cast<size_t>(de::gui::prefs().previewKiB) * 1024;
    std::vector<uint8_t> head;
    fs->readFileStream(f, [&](const uint8_t* d, size_t n) -> bool {
        size_t take = std::min(n, kPreview - head.size());
        head.insert(head.end(), d, d + take);
        return head.size() < kPreview; // stop once we have enough
    });
    hex_->setData(head);
    status_->setText(QString("%1 - %2")
                         .arg(item->data(0, RoleName).toString())
                         .arg(humanSize(f.size)));
}

void MainWindow::onItemChanged(QTreeWidgetItem* item, int column) {
    if (column != 0 || updatingChecks_) return;
    if (!(item->flags() & Qt::ItemIsUserCheckable)) return;
    Qt::CheckState st = item->checkState(0);
    if (st == Qt::PartiallyChecked) return; // set by us, not a user toggle

    updatingChecks_ = true;
    // Down: apply the (un)check to all loaded descendants.
    std::function<void(QTreeWidgetItem*)> applyDown = [&](QTreeWidgetItem* it) {
        for (int i = 0; i < it->childCount(); ++i) {
            auto* c = it->child(i);
            if (c->flags() & Qt::ItemIsUserCheckable) {
                c->setCheckState(0, st);
                applyDown(c);
            }
        }
    };
    applyDown(item);

    // Up: recompute each ancestor's state from its (loaded) children.
    for (QTreeWidgetItem* p = item->parent(); p && (p->flags() & Qt::ItemIsUserCheckable);
         p = p->parent()) {
        int checked = 0, unchecked = 0, total = 0;
        for (int i = 0; i < p->childCount(); ++i) {
            auto* c = p->child(i);
            if (!(c->flags() & Qt::ItemIsUserCheckable)) continue;
            ++total;
            if (c->checkState(0) == Qt::Checked) ++checked;
            else if (c->checkState(0) == Qt::Unchecked) ++unchecked;
        }
        if (total == 0) continue;
        p->setCheckState(0, checked == total ? Qt::Checked
                            : unchecked == total ? Qt::Unchecked
                            : Qt::PartiallyChecked);
    }
    updatingChecks_ = false;
}

void MainWindow::collectExportRoots(QTreeWidgetItem* item,
                                    QList<QTreeWidgetItem*>& out) {
    for (int i = 0; i < item->childCount(); ++i) {
        auto* c = item->child(i);
        if (!(c->flags() & Qt::ItemIsUserCheckable)) { continue; }
        switch (c->checkState(0)) {
            case Qt::Checked:          out.push_back(c); break;      // whole subtree
            case Qt::PartiallyChecked: collectExportRoots(c, out); break; // dig in
            default: break;                                          // unchecked
        }
    }
}

namespace {
QString sanitizeName(const QString& name) {
    QString s = name;
    s.replace('/', '_').replace('\\', '_');
    s.remove(QChar(0));
    if (s.isEmpty() || s == "." || s == "..") s = "_";
    return s;
}
} // namespace

// Worker-thread recursion: mirror a node to disk. Touches no Qt widgets; talks
// to the UI only through the atomic counters and the mutex-guarded name.
void MainWindow::exportWalk(Filesystem* fs, const FsNode& node, const QString& destDir) {
    if (exportCancel_.load()) return;
    QString safe = sanitizeName(QString::fromStdString(node.name));
    QString outPath = QDir(destDir).filePath(safe);
    if (node.isDir) {
        QDir().mkpath(outPath);
        de::applyInvokingOwner(outPath.toStdString());
        for (const auto& c : fs->listDir(node)) {
            exportWalk(fs, c, outPath);
            if (exportCancel_.load()) return;
        }
        // After the children, not before: writing them bumps the directory's
        // own mtime, so stamping it first would be undone.
        if (exportKeepTimes_)
            de::applyFileTimes(outPath.toStdString(), fs->fileTimes(node));
    } else {
        {
            std::lock_guard<std::mutex> lk(exportNameMutex_);
            exportName_ = safe.toStdString();
        }
        // Name-collision policy.
        if (std::filesystem::exists(outPath.toStdString())) {
            if (exportCollision_ == 2) return;                 // skip
            if (exportCollision_ == 0) {                       // rename: file (1), (2)...
                QFileInfo fi(outPath);
                for (int n = 1; ; ++n) {
                    QString cand = QDir(fi.path()).filePath(
                        fi.completeBaseName() + QString(" (%1)").arg(n) +
                        (fi.suffix().isEmpty() ? "" : "." + fi.suffix()));
                    if (!std::filesystem::exists(cand.toStdString())) { outPath = cand; break; }
                }
            }
            // exportCollision_ == 1 (overwrite): fall through, truncating open.
        }

        // Optional hash-on-export.
        EVP_MD_CTX* md = nullptr;
        const char* sidecarExt = nullptr;
        if (exportHashKind_ == 1) { md = EVP_MD_CTX_new(); EVP_DigestInit_ex(md, EVP_md5(), nullptr); sidecarExt = ".md5"; }
        else if (exportHashKind_ == 2) { md = EVP_MD_CTX_new(); EVP_DigestInit_ex(md, EVP_sha256(), nullptr); sidecarExt = ".sha256"; }

        std::ofstream os(outPath.toStdString(), std::ios::binary | std::ios::trunc);
        if (!os) { ++exportFails_; if (md) EVP_MD_CTX_free(md); return; }
        bool ok = fs->readFileStream(node, [&](const uint8_t* d, size_t n) -> bool {
            os.write(reinterpret_cast<const char*>(d), static_cast<std::streamsize>(n));
            if (md) EVP_DigestUpdate(md, d, n);
            exportBytes_ += n;
            return static_cast<bool>(os) && !exportCancel_.load();
        });
        os.close();
        if (ok && !exportCancel_.load()) {
            ++exportFiles_;
            // Resource fork (classic HFS): write "<name>.rsrc" sidecar if present.
            bool wroteRsrc = false;
            if (auto rsrc = fs->readResourceFork(node); !rsrc.empty()) {
                std::ofstream rs((outPath + ".rsrc").toStdString(), std::ios::binary | std::ios::trunc);
                rs.write(reinterpret_cast<const char*>(rsrc.data()), static_cast<std::streamsize>(rsrc.size()));
                wroteRsrc = true;
            }
            // Restore the source dates once the data is on disk. The resource
            // fork is part of the same original file, so it gets them too; the
            // hash sidecar keeps the real time we computed it.
            if (exportKeepTimes_) {
                FsTimes t = fs->fileTimes(node);
                de::applyFileTimes(outPath.toStdString(), t);
                if (wroteRsrc) de::applyFileTimes((outPath + ".rsrc").toStdString(), t);
            }
            // Unconditional, unlike the dates: the customer needs to be able to
            // read the file whether or not they asked to keep the timeline.
            de::applyInvokingOwner(outPath.toStdString());
            if (wroteRsrc) de::applyInvokingOwner((outPath + ".rsrc").toStdString());
            if (md) {  // write "<hex>  <filename>" sidecar next to the file
                unsigned char dig[EVP_MAX_MD_SIZE]; unsigned int dl = 0;
                EVP_DigestFinal_ex(md, dig, &dl);
                std::string hex; hex.reserve(dl * 2);
                static const char* h = "0123456789abcdef";
                for (unsigned i = 0; i < dl; ++i) { hex += h[dig[i] >> 4]; hex += h[dig[i] & 0xF]; }
                std::ofstream sc((outPath + sidecarExt).toStdString());
                sc << hex << "  " << QFileInfo(outPath).fileName().toStdString() << "\n";
                sc.close();
                de::applyInvokingOwner((outPath + sidecarExt).toStdString());
            }
        } else {
            ++exportFails_;
            std::error_code ec;
            std::filesystem::remove(outPath.toStdString(), ec); // drop partial
        }
        if (md) EVP_MD_CTX_free(md);
    }
}

void MainWindow::exportSelected() {
    // Gather the roots of every checked subtree.
    QList<QTreeWidgetItem*> roots;
    for (int i = 0; i < tree_->topLevelItemCount(); ++i)
        collectExportRoots(tree_->topLevelItem(i), roots);
    if (roots.isEmpty()) {
        QMessageBox::information(this, "Export",
            "Tick the checkbox next to the files or folders you want to export.\n"
            "Checking a folder exports its entire contents, preserving structure.");
        return;
    }

    // Start the folder picker at the configured default, if any.
    QString destDir = QFileDialog::getExistingDirectory(
        this, "Export to folder", de::gui::prefs().defaultExportDir);
    if (destDir.isEmpty()) return;

    // Snapshot export options from preferences (worker won't touch prefs).
    switch (de::gui::prefs().hashOnExport) {
        case de::gui::HashKind::Md5:    exportHashKind_ = 1; break;
        case de::gui::HashKind::Sha256: exportHashKind_ = 2; break;
        default:                        exportHashKind_ = 0; break;
    }
    switch (de::gui::prefs().collision) {
        case de::gui::Collision::Overwrite: exportCollision_ = 1; break;
        case de::gui::Collision::Skip:      exportCollision_ = 2; break;
        default:                            exportCollision_ = 0; break;
    }
    exportKeepTimes_ = de::gui::prefs().preserveTimestamps;

    // Resolve the filesystem + node for each root on the UI thread (mounting
    // reads the image); the worker then owns all image access exclusively.
    struct Job { Filesystem* fs; FsNode node; };
    std::vector<Job> jobs;
    for (auto* root : roots) {
        Filesystem* fs = mountFor(root);
        if (!fs) continue;
        FsNode node;
        node.id = root->data(0, RoleNodeId).toULongLong();
        node.name = root->data(0, RoleName).toString().toStdString();
        node.isDir =
            static_cast<ItemKind>(root->data(0, RoleKind).toInt()) == ItemKind::Directory;
        jobs.push_back({fs, node});
    }

    exportCancel_ = false; exportDone_ = false; exportUserCancelled_ = false;
    exportBytes_ = 0; exportFiles_ = 0; exportFails_ = 0;
    { std::lock_guard<std::mutex> lk(exportNameMutex_); exportName_.clear(); }

    QProgressDialog progress("Starting export...", "Cancel", 0, 0, this);
    progress.setWindowTitle("Exporting");
    progress.setWindowModality(Qt::ApplicationModal);
    progress.setMinimumDuration(0);
    // Only a real Cancel click / Esc / close sets the flag - no processEvents
    // polling that could trip it spuriously.
    connect(&progress, &QProgressDialog::canceled, this, [this] {
        exportCancel_ = true;
        exportUserCancelled_ = true;
    });

    // Background worker: does all image I/O; never touches widgets.
    std::thread worker([this, jobs, destDir] {
        for (const auto& j : jobs) {
            exportWalk(j.fs, j.node, destDir);
            if (exportCancel_.load()) break;
        }
        exportDone_ = true;
    });

    // UI-thread timer drives the progress label and closes the dialog when done.
    QTimer timer;
    connect(&timer, &QTimer::timeout, this, [this, &progress] {
        std::string nm;
        { std::lock_guard<std::mutex> lk(exportNameMutex_); nm = exportName_; }
        progress.setLabelText(QString("Exporting: %1\n%2 in %3 files")
                                  .arg(QString::fromStdString(nm))
                                  .arg(humanSize(exportBytes_.load()))
                                  .arg(exportFiles_.load()));
        if (exportDone_.load()) progress.accept(); // ends exec() without cancel
    });
    timer.start(150);

    progress.exec();       // normal event loop runs here - UI stays responsive
    timer.stop();
    exportCancel_ = true;  // ensure the worker unwinds if the dialog closed early
    worker.join();

    bool cancelled = exportUserCancelled_.load();
    QMessageBox::information(this, "Export complete",
        QString("Exported %1 file(s), %2%3%4.")
            .arg(exportFiles_.load())
            .arg(humanSize(exportBytes_.load()))
            .arg(exportFails_.load() ? QString(", %1 failed").arg(exportFails_.load()) : QString())
            .arg(cancelled ? " (cancelled)" : ""));
}
