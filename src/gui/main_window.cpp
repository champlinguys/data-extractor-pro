#include "gui/main_window.h"
#include "gui/hex_view.h"
#include "gui/settings.h"
#include "gui/preferences_dialog.h"
#include "partition/partition.h"
#include "optane/span_map.h"
#include "bitlocker/volume.h"

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
#include <QPushButton>
#include <QDialogButtonBox>
#include <QProgressDialog>
#include <QTimer>
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

    auto* exportAct = new QAction("&Export Selected...", this);
    exportAct->setShortcut(QKeySequence("Ctrl+E"));
    connect(exportAct, &QAction::triggered, this, &MainWindow::exportSelected);

    auto* prefsAct = new QAction("&Preferences...", this);
    prefsAct->setShortcut(QKeySequence::Preferences);
    connect(prefsAct, &QAction::triggered, this, &MainWindow::openPreferences);

    auto* fileMenu = menuBar()->addMenu("&File");
    fileMenu->addAction(openAct);
    fileMenu->addAction(openOptaneAct);
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
        auto merged = de::optane::makeSpanMerge(qlc, opt, cacheHintBytes);
        if (!merged) {
            openError_ = "Couldn't detect a span-backed Optane device.\n"
                         "Check the Optane image, and if auto-scan is too slow, "
                         "provide the Intel Cache start sector (from de-cli imsm).";
            return;
        }
        openedSource_ = merged;
        openedVols_ = prepareVolumes(merged, key);
    });
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
        QString fsName = QString::fromStdString(detectFilesystemName(*vol));
        if (!key.empty() && fsName.startsWith("BitLocker")) {
            if (auto dec = de::bitlocker::unlockVolume(vol, key)) {
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
        // Add the lazy-load placeholder (what gives the row its expand arrow)
        // for any filesystem detectFilesystem() can actually mount - i.e.
        // anything other than a stub label ("... not yet implemented"), an
        // unrecognised volume, or BitLocker still locked/failed to unlock.
        bool browsable = !fsName.contains("not yet implemented") &&
                          fsName != "Unknown" &&
                          !fsName.startsWith("BitLocker (encrypted)") &&
                          !fsName.startsWith("BitLocker (unlock failed");
        if (browsable)
            item->addChild(new QTreeWidgetItem({QString("...")}));
    }
    status_->setText(QString("%1 - %2, %3 partition(s)")
                         .arg(label).arg(humanSize(totalSize)).arg(vols.size()));
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
        for (const auto& c : fs->listDir(node)) {
            exportWalk(fs, c, outPath);
            if (exportCancel_.load()) return;
        }
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
            if (auto rsrc = fs->readResourceFork(node); !rsrc.empty()) {
                std::ofstream rs((outPath + ".rsrc").toStdString(), std::ios::binary | std::ios::trunc);
                rs.write(reinterpret_cast<const char*>(rsrc.data()), static_cast<std::streamsize>(rsrc.size()));
            }
            if (md) {  // write "<hex>  <filename>" sidecar next to the file
                unsigned char dig[EVP_MAX_MD_SIZE]; unsigned int dl = 0;
                EVP_DigestFinal_ex(md, dig, &dl);
                std::string hex; hex.reserve(dl * 2);
                static const char* h = "0123456789abcdef";
                for (unsigned i = 0; i < dl; ++i) { hex += h[dig[i] >> 4]; hex += h[dig[i] & 0xF]; }
                std::ofstream sc((outPath + sidecarExt).toStdString());
                sc << hex << "  " << QFileInfo(outPath).fileName().toStdString() << "\n";
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
