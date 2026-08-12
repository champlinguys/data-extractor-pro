#pragma once
#include <QDialog>
#include <QString>
#include <cstdint>
#include <string>
#include <vector>

namespace de::gui {

// One physical drive as the system describes it, plus what we can tell about
// its contents by reading it.
//
// Picking the right drives is the first thing that has to go right in a
// multi-drive recovery, and "/dev/sdc" alone is not enough to go on when four
// similar disks are attached. So the picker shows what is printed on the drive
// (model, serial, size) next to what is actually on it.
struct BlockDevice {
    std::string path;   // /dev/sdc
    std::string name;   // sdc
    uint64_t sizeBytes = 0;
    std::string model;
    std::string vendor;
    std::string serial;
    std::string bus;       // ata, usb, nvme, ...
    bool removable = false;
    bool rotational = true;
    std::vector<std::string> mountPoints; // non-empty = in use right now

    struct Partition {
        std::string name;
        uint64_t startBytes = 0;
        uint64_t sizeBytes = 0;
        std::string typeName; // from the partition table
        std::string fsName;   // what our own detector makes of it
    };
    std::vector<Partition> partitions;

    // Filled in by a background probe that actually reads the drive.
    bool probed = false;
    bool readable = false;
    std::string contents; // "GPT, 2 partitions" / "no partition table"
    std::string raidHint; // "SoftRAID member", "looks like a RAID member", ...
};

// Everything the system currently reports as a whole drive (partitions and
// virtual devices excluded).
std::vector<BlockDevice> enumerateBlockDevices();

// Read `dev` to fill in its partitions, filesystems and RAID hints. Safe to
// call off the UI thread; only ever reads.
void probeBlockDevice(BlockDevice& dev);

// Show the picker. Returns the chosen device paths, or empty if cancelled.
std::vector<QString> pickBlockDevices(QWidget* parent, const QString& title,
                                      bool allowMultiple);

} // namespace de::gui
