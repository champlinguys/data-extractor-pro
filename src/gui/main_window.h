#pragma once
#include <QMainWindow>
#include <QTreeWidget>
#include <memory>
#include <map>
#include <atomic>
#include <mutex>
#include <string>
#include <vector>
#include <functional>
#include "core/image_source.h"
#include "fs/filesystem.h"

class HexView;
class QLabel;

// Kinds of node in the browse tree, stashed on each item via Qt::UserRole.
enum class ItemKind { Partition, Directory, File };

// Main application window: open an image, browse its partitions/filesystems in
// a lazy-loading tree, preview the selected file, and export files or folders.
class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    MainWindow();

    // Open a source given on the command line: an image path, or a RAID spec
    // like "raid:auto:/dev/sdc,/dev/sdd" (the same syntax de-cli accepts).
    void openSourceSpec(const QString& spec);

private slots:
    void openImage();
    void openOptaneSet();
    // Open two or more drives as one RAID set (the OWC/SoftRAID case).
    void openRaidSet();
    void openPreferences();
    void applyPrefs();          // re-apply theme-driven bits (fonts, etc.)
    void onItemExpanded(QTreeWidgetItem* item);
    void onItemSelected();
    void onItemChanged(QTreeWidgetItem* item, int column);
    void exportSelected();
    // Right-click menu on the tree: offers "Unlock BitLocker..." on a still-
    // locked BitLocker partition row.
    void showTreeMenu(const QPoint& pos);

private:
    // Prompt for a recovery key and, if it unlocks `partitionItem`'s volume,
    // swap in the decrypted source and turn the row into a browsable one.
    void unlockBitLockerItem(QTreeWidgetItem* partitionItem);
    void unlockCoreStorageItem(QTreeWidgetItem* partitionItem);
    void loadImage(const QString& path);
    // Assemble `devs` (modeIndex: 0 auto, 1 stripe, 2 concat, 3 mirror) and
    // load the result into the tree.
    void openRaidDevices(std::vector<std::shared_ptr<de::ImageSource>> devs,
                         int modeIndex, uint64_t stripeBytes);
    // Reconstruct a QLC+Optane pair and (optionally) unlock BitLocker, then
    // browse the result. `cacheHintBytes` is the Intel Cache region offset, or
    // UINT64_MAX to auto-scan (slow).
    void loadOptaneSet(const QString& qlcPath, const QString& optanePath,
                       uint64_t cacheHintBytes, const QString& recoveryKey);

    // One reconstructed/decrypted volume, computed off the UI thread.
    struct PreparedVol {
        int index = 0;
        std::string typeName;
        std::string fsName;
        unsigned long long lengthBytes = 0;
        std::shared_ptr<de::ImageSource> source;   // decrypted if BitLocker+key
    };
    // Heavy, non-Qt work: scan partitions, detect filesystems, unlock BitLocker.
    // Safe to call on a worker thread (touches no widgets).
    std::vector<PreparedVol> prepareVolumes(std::shared_ptr<de::ImageSource> source,
                                            const std::string& recoveryKey);
    // Run `producer` (heavy engine work) on a background thread behind a modal
    // busy dialog so the event loop stays responsive, then build the tree.
    void runOpen(const QString& label, std::function<void()> producer);
    void buildTree(const std::vector<PreparedVol>& vols, const QString& label,
                   unsigned long long totalSize);
    // Ensure a partition item's filesystem is mounted; returns nullptr if the
    // volume has no filesystem we can read.
    de::Filesystem* mountFor(QTreeWidgetItem* partitionItem);
    void populateChildren(QTreeWidgetItem* item);
    QTreeWidgetItem* makeNode(const de::FsNode& node, int partIndex, ItemKind kind);

    // Export: gather the checked subtree roots, then mirror each to disk by
    // walking the filesystem (so lazily-unloaded children are included too).
    void collectExportRoots(QTreeWidgetItem* item, QList<QTreeWidgetItem*>& out);
    // Runs on the export worker thread - must not touch any Qt widgets.
    // `ancestors` holds dirIdentity() for every directory currently open on
    // the recursion path, so a directory that points back into its own
    // ancestry is caught instead of being mirrored forever.
    void exportWalk(de::Filesystem* fs, const de::FsNode& node, const QString& destDir,
                    std::vector<uint64_t>& ancestors, int depth);

    bool updatingChecks_ = false;  // reentrancy guard for check propagation

    // Export runs on a background thread; the UI event loop stays responsive and
    // these carry state back to the progress dialog.
    std::atomic<bool> exportCancel_{false};   // stop signal to the worker
    std::atomic<bool> exportUserCancelled_{false}; // set only by the Cancel button
    std::atomic<bool> exportDone_{false};
    std::atomic<unsigned long long> exportBytes_{0};
    std::atomic<int> exportFiles_{0};
    std::atomic<int> exportFails_{0};
    std::atomic<int> exportCycles_{0};  // directory loops refused
    std::mutex exportNameMutex_;
    std::string exportName_;                  // current file, for the label
    // Export options snapshotted on the UI thread before the worker starts, so
    // the worker never touches QSettings/prefs.
    int exportHashKind_ = 0;   // 0 none, 1 md5, 2 sha256
    int exportCollision_ = 0;  // 0 rename, 1 overwrite, 2 skip
    bool exportKeepTimes_ = true; // stamp source mtime/atime onto exports

    // Async open (runOpen) results, filled by the worker thread.
    std::atomic<bool> openDone_{false};
    std::shared_ptr<de::ImageSource> openedSource_;
    std::vector<PreparedVol> openedVols_;
    std::string openError_;
    std::string openWarning_;  // non-fatal: shown, then the open continues
    std::string openInfo_;     // e.g. the RAID geometry we settled on

    QTreeWidget* tree_ = nullptr;
    HexView* hex_ = nullptr;
    QLabel* status_ = nullptr;

    std::shared_ptr<de::ImageSource> image_;
    // One mounted filesystem per partition ordinal, created on demand.
    std::map<int, std::unique_ptr<de::Filesystem>> mounts_;
    std::map<int, std::shared_ptr<de::ImageSource>> volumes_;
};
