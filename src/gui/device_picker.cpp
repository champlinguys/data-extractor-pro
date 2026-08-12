#include "gui/device_picker.h"
#include "core/image_source.h"
#include "fs/filesystem.h"
#include "partition/partition.h"
#include "raid/raid_detect.h"

#include <QDialogButtonBox>
#include <QHeaderView>
#include <QLabel>
#include <QPushButton>
#include <QTimer>
#include <QTreeWidget>
#include <QVBoxLayout>

#include <algorithm>
#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <thread>

#include <dirent.h>

namespace de::gui {

namespace {

std::string readSysFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) return {};
    std::string s;
    std::getline(in, s);
    // sysfs values are padded with spaces surprisingly often (SCSI model/vendor).
    while (!s.empty() && (s.back() == ' ' || s.back() == '\n' || s.back() == '\r'))
        s.pop_back();
    size_t start = s.find_first_not_of(' ');
    return start == std::string::npos ? std::string() : s.substr(start);
}

QString humanSize(uint64_t n) {
    if (n >= 1000000000000ull) return QString::asprintf("%.2f TB", n / 1e12);
    if (n >= 1000000000ull) return QString::asprintf("%.2f GB", n / 1e9);
    if (n >= 1000000ull) return QString::asprintf("%.2f MB", n / 1e6);
    return QString("%1 B").arg(n);
}

// udev caches the identifying strings the kernel does not expose in sysfs -
// notably the serial number of a SATA disk, which is the one thing that tells
// two identical drives apart. The file is plain "E:KEY=value" lines.
void readUdevProperties(const std::string& devNode, BlockDevice& dev) {
    std::string majMin = readSysFile("/sys/block/" + dev.name + "/dev");
    if (majMin.empty()) return;
    std::ifstream in("/run/udev/data/b" + majMin);
    if (!in) return;
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("E:", 0) != 0) continue;
        size_t eq = line.find('=');
        if (eq == std::string::npos) continue;
        std::string key = line.substr(2, eq - 2);
        std::string val = line.substr(eq + 1);
        if (key == "ID_SERIAL_SHORT" && dev.serial.empty()) dev.serial = val;
        else if (key == "ID_MODEL" && dev.model.empty()) dev.model = val;
        else if (key == "ID_VENDOR" && dev.vendor.empty()) dev.vendor = val;
        else if (key == "ID_BUS" && dev.bus.empty()) dev.bus = val;
    }
    (void)devNode;
}

void readMountPoints(std::vector<BlockDevice>& devs) {
    std::ifstream in("/proc/mounts");
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream ss(line);
        std::string src, target;
        if (!(ss >> src >> target)) continue;
        if (src.rfind("/dev/", 0) != 0) continue;
        for (auto& d : devs) {
            // A mounted partition counts as the whole drive being in use.
            if (src.rfind(d.path, 0) == 0) {
                d.mountPoints.push_back(target);
                break;
            }
        }
    }
}

bool isWholeDrive(const std::string& name) {
    // Skip memory-backed and mapper devices; keep loop devices only when they
    // are actually backing a file, since those are usually images under test.
    if (name.rfind("ram", 0) == 0 || name.rfind("zram", 0) == 0) return false;
    if (name.rfind("dm-", 0) == 0 || name.rfind("md", 0) == 0) return false;
    if (name.rfind("loop", 0) == 0) {
        std::string backing = readSysFile("/sys/block/" + name + "/loop/backing_file");
        if (backing.empty()) return false;
        // A desktop Linux box has dozens of loop devices mounted for installed
        // snaps. They are never recovery targets and burying the real drives
        // under thirty rows of them defeats the point of this list.
        if (backing.rfind("/var/lib/snapd/", 0) == 0) return false;
        return true;
    }
    return true;
}

} // namespace

std::vector<BlockDevice> enumerateBlockDevices() {
    std::vector<BlockDevice> out;
    DIR* dir = ::opendir("/sys/block");
    if (!dir) return out;
    while (dirent* e = ::readdir(dir)) {
        std::string name = e->d_name;
        if (name == "." || name == "..") continue;
        if (!isWholeDrive(name)) continue;

        BlockDevice d;
        d.name = name;
        d.path = "/dev/" + name;
        std::string base = "/sys/block/" + name;
        // The kernel reports size in 512-byte units regardless of sector size.
        d.sizeBytes = std::strtoull(readSysFile(base + "/size").c_str(), nullptr, 10) * 512ull;
        if (d.sizeBytes == 0) continue;
        d.model = readSysFile(base + "/device/model");
        d.vendor = readSysFile(base + "/device/vendor");
        d.serial = readSysFile(base + "/device/serial");
        d.removable = readSysFile(base + "/removable") == "1";
        d.rotational = readSysFile(base + "/queue/rotational") != "0";
        if (name.rfind("loop", 0) == 0) {
            d.model = "loop: " + readSysFile(base + "/loop/backing_file");
            d.bus = "loop";
        }
        readUdevProperties(d.path, d);

        // Partitions, as the kernel sees them. The engine fills in filesystems
        // later, when it actually reads the drive.
        if (DIR* sub = ::opendir(base.c_str())) {
            while (dirent* se = ::readdir(sub)) {
                std::string pname = se->d_name;
                if (pname.rfind(name, 0) != 0 || pname == name) continue;
                BlockDevice::Partition p;
                p.name = pname;
                p.startBytes = std::strtoull(
                    readSysFile(base + "/" + pname + "/start").c_str(), nullptr, 10) * 512ull;
                p.sizeBytes = std::strtoull(
                    readSysFile(base + "/" + pname + "/size").c_str(), nullptr, 10) * 512ull;
                if (p.sizeBytes) d.partitions.push_back(std::move(p));
            }
            ::closedir(sub);
        }
        std::sort(d.partitions.begin(), d.partitions.end(),
                  [](const auto& a, const auto& b) { return a.startBytes < b.startBytes; });
        out.push_back(std::move(d));
    }
    ::closedir(dir);
    std::sort(out.begin(), out.end(),
              [](const BlockDevice& a, const BlockDevice& b) { return a.name < b.name; });
    readMountPoints(out);
    return out;
}

void probeBlockDevice(BlockDevice& dev) {
    dev.probed = true;
    std::shared_ptr<ImageSource> src;
    try {
        src = std::make_shared<RawImageSource>(dev.path);
    } catch (const std::exception&) {
        dev.readable = false;
        dev.contents = "cannot read (needs root)";
        return;
    }
    dev.readable = true;

    auto parts = scanPartitions(src);
    bool wholeDisk = parts.size() == 1 && parts[0].firstByte == 0 &&
                     parts[0].scheme == "none";
    dev.partitions.clear();
    for (const auto& p : parts) {
        auto vol = p.asSource(src);
        std::string fs = detectFilesystemName(*vol);
        if (wholeDisk) {
            dev.contents = fs == "Unknown" ? "no partition table" : fs;
            break;
        }
        BlockDevice::Partition part;
        part.name = dev.name + std::to_string(p.index);
        part.startBytes = p.firstByte;
        part.sizeBytes = p.lengthBytes;
        part.typeName = p.typeName;
        part.fsName = fs;
        dev.partitions.push_back(std::move(part));
    }
    if (!wholeDisk)
        dev.contents = parts[0].scheme + ", " + std::to_string(parts.size()) +
                       " partition" + (parts.size() == 1 ? "" : "s");

    // Is this drive part of a set? Its own metadata says so outright; failing
    // that, a full-size drive with no partition table and no filesystem is the
    // classic look of a stripe member, which is worth saying out loud.
    auto md = de::raid::readMemberMetadata(*src);
    if (!md.format.empty()) {
        dev.raidHint = md.format + " member";
        if (!md.levelName.empty()) dev.raidHint += ", " + md.levelName;
        if (md.chunkSize)
            dev.raidHint += ", " + std::to_string(md.chunkSize / 1024) + " KiB chunk";
        if (md.memberIndex >= 0) {
            dev.raidHint += ", disk " + std::to_string(md.memberIndex + 1);
            if (md.memberCount > 0) dev.raidHint += " of " + std::to_string(md.memberCount);
        }
    } else if (dev.contents == "no partition table") {
        dev.raidHint = "no partition table - could be a RAID member";
    }
}

std::vector<QString> pickBlockDevices(QWidget* parent, const QString& title,
                                      bool allowMultiple) {
    QDialog dlg(parent);
    dlg.setWindowTitle(title);
    dlg.resize(1000, 460);
    auto* layout = new QVBoxLayout(&dlg);

    auto* hint = new QLabel(
        allowMultiple ? "Select the drives that belong to the set. Reading a "
                        "drive directly needs root - start the program with "
                        "sudo if a drive shows as unreadable."
                      : "Select a drive.", &dlg);
    hint->setWordWrap(true);
    layout->addWidget(hint);

    auto* tree = new QTreeWidget(&dlg);
    tree->setColumnCount(7);
    tree->setHeaderLabels({"Device", "Size", "Model", "Serial", "Bus",
                           "Contents", "Mounted"});
    tree->setSelectionMode(allowMultiple ? QAbstractItemView::ExtendedSelection
                                         : QAbstractItemView::SingleSelection);
    tree->setRootIsDecorated(true);
    tree->header()->setSectionResizeMode(2, QHeaderView::Stretch);
    layout->addWidget(tree, 1);

    auto* status = new QLabel("Reading drives...", &dlg);
    layout->addWidget(status);

    auto* buttons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel,
                                         &dlg);
    auto* refresh = buttons->addButton("Refresh", QDialogButtonBox::ActionRole);
    QObject::connect(buttons, &QDialogButtonBox::accepted, &dlg, &QDialog::accept);
    QObject::connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    layout->addWidget(buttons);

    // Probing reads from every drive, which can take a moment on sleeping
    // spinning disks, so the list appears immediately from sysfs and the
    // content columns fill in behind it.
    struct State {
        std::mutex mutex;
        std::vector<BlockDevice> devices;
        std::atomic<bool> stop{false};
        std::atomic<bool> done{false};
    };
    auto state = std::make_shared<State>();

    auto startScan = [state, tree, status] {
        state->stop = true; // stop any previous scan before replacing the list
        {
            std::lock_guard<std::mutex> lk(state->mutex);
            state->devices = enumerateBlockDevices();
        }
        state->stop = false;
        state->done = false;
        status->setText("Reading drives...");
        std::thread([state] {
            size_t i = 0;
            while (!state->stop) {
                BlockDevice copy;
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    if (i >= state->devices.size()) break;
                    copy = state->devices[i];
                }
                probeBlockDevice(copy);
                {
                    std::lock_guard<std::mutex> lk(state->mutex);
                    if (i < state->devices.size()) state->devices[i] = copy;
                }
                ++i;
            }
            state->done = true;
        }).detach();
        (void)tree;
    };

    auto repaint = [state, tree, status] {
        std::lock_guard<std::mutex> lk(state->mutex);
        // Remember the selection across refreshes so a slow probe does not
        // yank a drive out from under the user's click.
        QStringList selected;
        for (auto* item : tree->selectedItems())
            selected << item->data(0, Qt::UserRole).toString();

        tree->clear();
        for (const auto& d : state->devices) {
            auto* row = new QTreeWidgetItem(tree);
            row->setData(0, Qt::UserRole, QString::fromStdString(d.path));
            row->setText(0, QString::fromStdString(d.path));
            row->setText(1, humanSize(d.sizeBytes));
            QString model = QString::fromStdString(
                d.vendor.empty() ? d.model : d.vendor + " " + d.model);
            if (d.removable) model += "  [removable]";
            if (!d.rotational) model += "  [SSD]";
            row->setText(2, model.trimmed());
            row->setText(3, QString::fromStdString(d.serial));
            row->setText(4, QString::fromStdString(d.bus));
            QString contents = QString::fromStdString(
                d.probed ? d.contents : std::string("reading..."));
            if (!d.raidHint.empty())
                contents += "  -  " + QString::fromStdString(d.raidHint);
            row->setText(5, contents);
            row->setText(6, QString::fromStdString(
                                d.mountPoints.empty() ? std::string()
                                                      : d.mountPoints.front()));
            if (!d.mountPoints.empty()) {
                // Mounted drives are still readable, but the user should know
                // the system has them in use.
                row->setToolTip(6, "This drive is mounted. Unmount it before "
                                   "recovery work if you can.");
            }
            for (const auto& p : d.partitions) {
                auto* child = new QTreeWidgetItem(row);
                child->setText(0, "  " + QString::fromStdString(p.name));
                child->setText(1, humanSize(p.sizeBytes));
                child->setText(2, QString::fromStdString(p.typeName));
                child->setText(5, QString::fromStdString(p.fsName));
                child->setFlags(child->flags() & ~Qt::ItemIsSelectable);
            }
            row->setExpanded(true);
            if (selected.contains(QString::fromStdString(d.path)))
                row->setSelected(true);
        }
        for (int c = 0; c < 5; ++c) tree->resizeColumnToContents(c);
        if (state->done) status->setText(QString("%1 drive(s) found.")
                                             .arg(state->devices.size()));
    };

    QObject::connect(refresh, &QPushButton::clicked, [startScan] { startScan(); });

    QTimer timer;
    QObject::connect(&timer, &QTimer::timeout, &dlg, [repaint] { repaint(); });
    timer.start(400);
    startScan();
    repaint();

    int result = dlg.exec();
    state->stop = true; // the detached probe thread checks this and exits

    std::vector<QString> chosen;
    if (result == QDialog::Accepted) {
        for (auto* item : tree->selectedItems()) {
            QString path = item->data(0, Qt::UserRole).toString();
            if (!path.isEmpty() && std::find(chosen.begin(), chosen.end(), path) ==
                                       chosen.end())
                chosen.push_back(path);
        }
    }
    return chosen;
}

} // namespace de::gui
