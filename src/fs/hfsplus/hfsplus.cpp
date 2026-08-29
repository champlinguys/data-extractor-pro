#include "fs/hfsplus/hfsplus.h"
#include "core/byte_reader.h"
#include "fs/hfs/hfs_wrapper.h"
#include "fs/compression/decmpfs.h"
#include <algorithm>
#include <cstring>

namespace de {

namespace {

// Volume header, at a fixed 1024 bytes into the volume.
constexpr uint64_t VH_OFFSET = 1024;
constexpr uint16_t SIG_HFSPLUS = 0x482B; // 'H+'
constexpr uint16_t SIG_HFSX = 0x4858;    // 'HX'
constexpr uint16_t SIG_HFS = 0x4244;     // 'BD' - classic HFS, possibly a wrapper

// Volume header field offsets.
constexpr size_t VH_ATTRIBUTES = 4;
constexpr size_t VH_CREATE_DATE = 16;
constexpr size_t VH_MODIFY_DATE = 20;
constexpr size_t VH_FILE_COUNT = 32;
constexpr size_t VH_FOLDER_COUNT = 36;
constexpr size_t VH_BLOCK_SIZE = 40;
constexpr size_t VH_TOTAL_BLOCKS = 44;
constexpr size_t VH_EXTENTS_FILE = 192;
constexpr size_t VH_CATALOG_FILE = 272;
constexpr size_t VH_ATTRIBUTES_FILE = 352;

// kHFSVolumeUnmountedBit: clear means the volume was not cleanly unmounted, so
// the journal may hold newer metadata than the structures we are about to read.
constexpr uint32_t VOL_UNMOUNTED = 1u << 8;

// Well-known CNIDs.
constexpr uint32_t CNID_ROOT = 2;
constexpr uint32_t CNID_EXTENTS = 3;
constexpr uint32_t CNID_CATALOG = 4;
constexpr uint32_t CNID_ATTRIBUTES = 8;

constexpr uint8_t FORK_DATA = 0x00;
constexpr uint8_t FORK_RSRC = 0xFF;

// Catalog record types.
constexpr uint16_t REC_FOLDER = 1;
constexpr uint16_t REC_FILE = 2;
constexpr uint16_t REC_FOLDER_THREAD = 3;
constexpr uint16_t REC_FILE_THREAD = 4;

// Attribute record types.
constexpr uint32_t ATTR_INLINE_DATA = 0x10;
constexpr uint32_t ATTR_FORK_DATA = 0x20;

// B-tree node kinds.
constexpr int8_t NODE_LEAF = -1;
constexpr int8_t NODE_INDEX = 0;

constexpr uint32_t BTREE_BIG_KEYS = 0x00000002;

// HFS timestamps count seconds from 1904; Unix counts from 1970.
constexpr int64_t HFS_EPOCH_OFFSET = 2082844800LL;

int64_t hfsTimeToNs(uint32_t t) {
    if (t == 0) return 0;
    return (static_cast<int64_t>(t) - HFS_EPOCH_OFFSET) * 1000000000LL;
}

uint64_t rdBE64(const uint8_t* p) {
    return (static_cast<uint64_t>(rdBE32(p)) << 32) | rdBE32(p + 4);
}

// HFS+ stores names as UTF-16, big-endian, with an explicit length.
std::string utf16beToUtf8(const uint8_t* p, size_t units) {
    std::string out;
    out.reserve(units);
    for (size_t i = 0; i < units; ++i) {
        uint32_t c = rdBE16(p + i * 2);
        if (c >= 0xD800 && c < 0xDC00 && i + 1 < units) {
            uint32_t lo = rdBE16(p + (i + 1) * 2);
            if (lo >= 0xDC00 && lo < 0xE000) {
                c = 0x10000 + ((c - 0xD800) << 10) + (lo - 0xDC00);
                ++i;
            }
        }
        if (c < 0x80) {
            out += static_cast<char>(c);
        } else if (c < 0x800) {
            out += static_cast<char>(0xC0 | (c >> 6));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else if (c < 0x10000) {
            out += static_cast<char>(0xE0 | (c >> 12));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (c >> 18));
            out += static_cast<char>(0x80 | ((c >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((c >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (c & 0x3F));
        }
    }
    return out;
}

std::string fourCC(const uint8_t* p) {
    std::string s;
    for (int i = 0; i < 4; ++i)
        s += (p[i] >= 0x20 && p[i] < 0x7F) ? static_cast<char>(p[i]) : '.';
    return s;
}

// The hidden folders Mac OS keeps hard-link targets in.
const std::string PRIVATE_DATA_DIR("\0\0\0\0HFS+ Private Data", 21);

// Names shown to the user and used for export. HFS+ permits control
// characters in names - Apple's own private folders start with four NULs -
// and those cannot be written to any destination filesystem, so they are
// replaced for display while the catalog keeps the real name for lookups.
std::string displayName(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (unsigned char c : raw) out += (c < 0x20 || c == 0x7F) ? '_' : static_cast<char>(c);
    return out;
}

} // namespace

// ------------------------------------------------------------------ B-tree

std::vector<uint8_t> HfsPlusFilesystem::BTree::node(uint32_t nodeNo) const {
    if (totalNodes_ && nodeNo >= totalNodes_) return {};
    return fs_->readFork(fork_, static_cast<uint64_t>(nodeNo) * nodeSize_, nodeSize_);
}

bool HfsPlusFilesystem::BTree::record(const std::vector<uint8_t>& node, uint16_t i,
                                      uint16_t nodeSize, Rec& out) {
    if (node.size() < nodeSize) return false;
    // The record offsets live at the end of the node, counting backwards.
    size_t offPos = static_cast<size_t>(nodeSize) - 2 * (static_cast<size_t>(i) + 1);
    size_t endPos = static_cast<size_t>(nodeSize) - 2 * (static_cast<size_t>(i) + 2);
    if (offPos + 2 > node.size() || endPos + 2 > node.size()) return false;
    size_t recOff = rdBE16(node.data() + offPos);
    size_t recEnd = rdBE16(node.data() + endPos);
    if (recOff < 14 || recEnd > nodeSize || recEnd <= recOff) return false;

    size_t keyLen = rdBE16(node.data() + recOff);
    size_t keyStart = recOff + 2;
    if (keyStart + keyLen > recEnd) return false;
    size_t valOff = keyStart + keyLen;
    valOff += valOff & 1; // values are aligned to an even offset
    if (valOff > recEnd) return false;

    out.key = node.data() + keyStart;
    out.keyLen = keyLen;
    out.val = node.data() + valOff;
    out.valLen = recEnd - valOff;
    return true;
}

bool HfsPlusFilesystem::BTree::init(HfsPlusFilesystem* fs, Fork fork, const char* what) {
    fs_ = fs;
    fork_ = std::move(fork);
    // The header node is the first node in the file; the node size is inside
    // it, so read a minimum-size node first and then trust what it says.
    auto head = fs_->readFork(fork_, 0, 512);
    if (head.size() < 512) return false;
    if (static_cast<int8_t>(head[8]) != 1 /* header node */) {
        fs_->note(std::string(what) + " B-tree header node is missing or damaged");
        return false;
    }
    const uint8_t* h = head.data() + 14; // BTHeaderRec follows the node descriptor
    rootNode_ = rdBE32(h + 2);
    nodeSize_ = rdBE16(h + 18);
    totalNodes_ = rdBE32(h + 22);
    uint32_t attributes = rdBE32(h + 38);
    if (nodeSize_ < 512 || nodeSize_ > 32768 || (nodeSize_ & (nodeSize_ - 1))) {
        fs_->note(std::string(what) + " B-tree has an implausible node size");
        return false;
    }
    if (!(attributes & BTREE_BIG_KEYS)) {
        // Every HFS+ tree sets this; a tree without it is something else.
        fs_->note(std::string(what) + " B-tree uses an unsupported key format");
        return false;
    }
    ok_ = rootNode_ != 0 || totalNodes_ <= 1;
    return ok_;
}

HfsPlusFilesystem::BTree::Cursor
HfsPlusFilesystem::BTree::lowerBound(const Compare& cmp) const {
    Cursor c;
    c.tree_ = this;
    if (!ok_) return c;

    uint32_t nodeNo = rootNode_;
    for (int depth = 0; depth < 64; ++depth) {
        auto blk = node(nodeNo);
        if (blk.size() < nodeSize_) return c;
        int8_t kind = static_cast<int8_t>(blk[8]);
        uint16_t count = rdBE16(blk.data() + 10);
        if (count == 0) return c;

        // First record whose key sorts strictly after the target.
        uint16_t lo = 0, hi = count;
        while (lo < hi) {
            uint16_t mid = static_cast<uint16_t>(lo + (hi - lo) / 2);
            Rec r;
            if (!record(blk, mid, nodeSize_, r)) { hi = mid; continue; }
            if (cmp(r.key, r.keyLen) > 0) hi = mid; else lo = static_cast<uint16_t>(mid + 1);
        }

        if (kind == NODE_LEAF) {
            // Records equal to or after the target start here. `lo` counted the
            // records sorting before it, and our comparators never report
            // equality, so `lo` is exactly the lower bound.
            c.node_ = std::move(blk);
            c.nodeNo_ = nodeNo;
            c.count_ = count;
            c.index_ = lo;
            c.load();
            return c;
        }
        if (kind != NODE_INDEX) return c;
        // Descend into the last child whose key is not after the target.
        uint16_t idx = lo > 0 ? static_cast<uint16_t>(lo - 1) : 0;
        Rec r;
        if (!record(blk, idx, nodeSize_, r) || r.valLen < 4) return c;
        uint32_t child = rdBE32(r.val);
        if (child == nodeNo) return c; // self-reference: damaged tree
        nodeNo = child;
    }
    return c;
}

void HfsPlusFilesystem::BTree::Cursor::load() {
    valid_ = false;
    while (true) {
        if (index_ < count_) {
            if (BTree::record(node_, index_, tree_->nodeSize_, rec_)) valid_ = true;
            return;
        }
        // Leaves are chained, so walking past the end of one just follows the
        // forward link rather than climbing back up the tree.
        if (node_.size() < 4) return;
        uint32_t next = rdBE32(node_.data());
        if (next == 0 || next == nodeNo_) return;
        auto blk = tree_->node(next);
        if (blk.size() < tree_->nodeSize_) return;
        if (static_cast<int8_t>(blk[8]) != NODE_LEAF) return;
        nodeNo_ = next;
        count_ = rdBE16(blk.data() + 10);
        node_ = std::move(blk);
        index_ = 0;
        if (count_ == 0) continue;
    }
}

bool HfsPlusFilesystem::BTree::Cursor::next() {
    if (!valid_) return false;
    ++index_;
    load();
    return valid_;
}

// ------------------------------------------------------------------- mount

bool HfsPlusFilesystem::probe(ImageSource& vol) {
    uint8_t vh[8];
    if (vol.readAt(VH_OFFSET, vh, sizeof vh) < sizeof vh) return false;
    uint16_t sig = rdBE16(vh);
    if (sig == SIG_HFSPLUS || sig == SIG_HFSX) return true;
    // A Mac OS 8/9-compatible drive holds 'BD' here and the real volume header
    // further in. That is still an HFS+ volume, and claiming otherwise hands
    // the disk to the classic-HFS reader, which mounts the wrapper's handful
    // of Apple files instead of the volume the customer cares about.
    if (auto embedded = hfswrapper::find(vol)) {
        if (vol.readAt(embedded->offset + VH_OFFSET, vh, sizeof vh) < sizeof vh)
            return false;
        uint16_t inner = rdBE16(vh);
        return inner == SIG_HFSPLUS || inner == SIG_HFSX;
    }
    return false;
}

std::unique_ptr<HfsPlusFilesystem> HfsPlusFilesystem::open(std::shared_ptr<ImageSource> vol) {
    if (!vol) return nullptr;
    // Unwrap first, so everything below - the volume header, the forks, the
    // backup-header check, every allocation-block offset - is resolved against
    // the embedded volume rather than the wrapper around it.
    if (auto embedded = hfswrapper::open(vol)) vol = std::move(embedded);
    auto fs = std::unique_ptr<HfsPlusFilesystem>(new HfsPlusFilesystem());
    fs->vol_ = std::move(vol);
    if (!fs->mount()) return nullptr;
    return fs;
}

bool HfsPlusFilesystem::mount() {
    auto vh = vol_->read(VH_OFFSET, 512);
    uint16_t sig = rdBE16(vh.data());
    if (sig == SIG_HFS) {
        // A wrapper was already unwrapped in open(), so 'BD' here means a
        // genuine classic-HFS volume: the plain-HFS reader's job, not ours.
        return false;
    }
    if (sig != SIG_HFSPLUS && sig != SIG_HFSX) return false;
    typeName_ = sig == SIG_HFSX ? "HFSX" : "HFS+";

    blockSize_ = rdBE32(vh.data() + VH_BLOCK_SIZE);
    totalBlocks_ = rdBE32(vh.data() + VH_TOTAL_BLOCKS);
    if (blockSize_ < 512 || blockSize_ > (1u << 20) || (blockSize_ & (blockSize_ - 1))) {
        note("volume header has an implausible allocation block size");
        return false;
    }
    uint32_t attributes = rdBE32(vh.data() + VH_ATTRIBUTES);
    stats_.blockSize = blockSize_;
    stats_.totalBlocks = totalBlocks_;
    stats_.sizeBytes = totalBlocks_ * static_cast<uint64_t>(blockSize_);
    stats_.fileCount = rdBE32(vh.data() + VH_FILE_COUNT);
    stats_.folderCount = rdBE32(vh.data() + VH_FOLDER_COUNT);
    stats_.cleanlyUnmounted = (attributes & VOL_UNMOUNTED) != 0;
    if (!stats_.cleanlyUnmounted)
        note("this volume was not cleanly unmounted; if it was journalled, a "
             "few recently written files may be missing or stale");

    // HFS+ keeps a second copy of the volume header 1024 bytes from the end of
    // the volume. Checking it costs one read and proves the volume really does
    // extend as far as it says - which is exactly the thing a mis-assembled
    // RAID gets wrong.
    //
    // "End of the volume" means the end of the space the volume was given, not
    // the end of its allocation blocks: the last few sectors of a partition
    // are usually left out of the block count, and the backup header lives in
    // those. Check there first, then fall back to the end of the allocated
    // area for volumes whose container we only know approximately.
    auto altMatches = [&](uint64_t at) {
        if (at < 1024) return false;
        auto alt = vol_->read(at, 512);
        uint16_t altSig = rdBE16(alt.data());
        return (altSig == SIG_HFSPLUS || altSig == SIG_HFSX) &&
               rdBE32(alt.data() + VH_BLOCK_SIZE) == blockSize_ &&
               rdBE32(alt.data() + VH_TOTAL_BLOCKS) == totalBlocks_;
    };
    if (vol_->size() >= 2048 && altMatches(vol_->size() - 1024))
        stats_.alternateHeaderMatches = true;
    else if (stats_.sizeBytes >= 2048 && altMatches(stats_.sizeBytes - 1024))
        stats_.alternateHeaderMatches = true;
    if (!stats_.alternateHeaderMatches)
        note("the backup copy of the volume header at the end of the volume is "
             "missing or does not match the one at the start");

    auto readForkData = [&](size_t off, uint32_t cnid, uint8_t type) {
        Fork f;
        f.cnid = cnid;
        f.forkType = type;
        f.logicalSize = rdBE64(vh.data() + off);
        f.totalBlocks = rdBE32(vh.data() + off + 12);
        for (int i = 0; i < 8; ++i) {
            Extent e;
            e.startBlock = rdBE32(vh.data() + off + 16 + i * 8);
            e.blockCount = rdBE32(vh.data() + off + 16 + i * 8 + 4);
            if (e.blockCount) f.extents.push_back(e);
        }
        return f;
    };

    // The extents-overflow tree comes first: everything else may need it to
    // find forks with more than eight extents. Its own fork is guaranteed to
    // fit in the eight the volume header carries.
    extentsFork_ = readForkData(VH_EXTENTS_FILE, CNID_EXTENTS, FORK_DATA);
    extentsTree_.init(this, extentsFork_, "extents overflow");

    auto catalogFork = readForkData(VH_CATALOG_FILE, CNID_CATALOG, FORK_DATA);
    if (!catalog_.init(this, catalogFork, "catalog")) return false;

    auto attrFork = readForkData(VH_ATTRIBUTES_FILE, CNID_ATTRIBUTES, FORK_DATA);
    if (attrFork.logicalSize) attributes_.init(this, attrFork, "attributes");

    // The volume name is the root folder's name, held in its thread record.
    if (auto r = recordByCnid(CNID_ROOT)) volName_ = r->name;
    return true;
}

// -------------------------------------------------------------------- forks

void HfsPlusFilesystem::ensureExtents(Fork& fork, uint64_t neededBlocks) const {
    if (!extentsTree_.ok() || fork.cnid == CNID_EXTENTS) return;
    uint64_t have = 0;
    for (const auto& e : fork.extents) have += e.blockCount;
    while (have < neededBlocks) {
        const uint32_t startBlock = static_cast<uint32_t>(have);
        const uint32_t cnid = fork.cnid;
        const uint8_t forkType = fork.forkType;
        // HFSPlusExtentKey: forkType, pad, fileID, startBlock.
        auto cur = extentsTree_.lowerBound([&](const uint8_t* k, size_t kl) -> int {
            if (kl < 10) return -1;
            uint32_t kf = rdBE32(k + 2);
            if (kf != cnid) return kf < cnid ? -1 : 1;
            uint8_t kt = k[0];
            if (kt != forkType) return kt < forkType ? -1 : 1;
            uint32_t kb = rdBE32(k + 6);
            return kb < startBlock ? -1 : 1;
        });
        if (!cur.valid()) break;
        const auto& r = cur.rec();
        if (r.keyLen < 10 || rdBE32(r.key + 2) != cnid || r.key[0] != forkType) break;
        if (r.valLen < 64) break;
        uint64_t added = 0;
        for (int i = 0; i < 8; ++i) {
            Extent e;
            e.startBlock = rdBE32(r.val + i * 8);
            e.blockCount = rdBE32(r.val + i * 8 + 4);
            if (!e.blockCount) break;
            fork.extents.push_back(e);
            added += e.blockCount;
        }
        if (!added) break;
        have += added;
    }
}

std::vector<uint8_t> HfsPlusFilesystem::readFork(const Fork& fork, uint64_t off,
                                                 size_t len) const {
    std::vector<uint8_t> out(len, 0);
    if (len == 0) return out;
    // Make sure the extent list reaches far enough for this read.
    Fork& mut = const_cast<Fork&>(fork);
    ensureExtents(mut, (off + len + blockSize_ - 1) / blockSize_);

    uint64_t pos = 0; // logical position of the current extent's start
    size_t done = 0;
    for (const auto& e : fork.extents) {
        uint64_t extLen = static_cast<uint64_t>(e.blockCount) * blockSize_;
        if (off + done < pos + extLen) {
            uint64_t within = (off + done) - pos;
            size_t take = static_cast<size_t>(
                std::min<uint64_t>(extLen - within, len - done));
            uint64_t devOff = static_cast<uint64_t>(e.startBlock) * blockSize_ + within;
            vol_->readAt(devOff, out.data() + done, take);
            done += take;
            if (done == len) break;
        }
        pos += extLen;
    }
    return out;
}

bool HfsPlusFilesystem::streamFork(const Fork& fork, uint64_t size,
                                   const DataSink& sink) {
    Fork& mut = const_cast<Fork&>(fork);
    ensureExtents(mut, (size + blockSize_ - 1) / blockSize_);

    // Start with a small chunk and grow: a caller that only wants the first
    // few bytes (a preview, or the RAID prober checking a file signature)
    // then pays for 64 KiB rather than several megabytes.
    std::vector<uint8_t> buf(64u << 10);
    const size_t maxChunk = 4u << 20;
    uint64_t pos = 0, produced = 0;
    for (const auto& e : fork.extents) {
        if (produced >= size) break;
        uint64_t extLen = static_cast<uint64_t>(e.blockCount) * blockSize_;
        uint64_t want = std::min<uint64_t>(extLen, size - produced);
        uint64_t devOff = static_cast<uint64_t>(e.startBlock) * blockSize_;
        uint64_t off = 0;
        while (want > 0) {
            size_t n = static_cast<size_t>(std::min<uint64_t>(want, buf.size()));
            size_t got = vol_->readAt(devOff + off, buf.data(), n);
            if (got < n) {
                // Unreadable media: keep the file's shape and say so once,
                // rather than truncating the export at the first bad sector.
                std::fill(buf.begin() + got, buf.begin() + n, 0);
                note("some sectors could not be read; the affected parts of "
                     "those files were filled with zeros");
            }
            if (!sink(buf.data(), n)) return false;
            want -= n;
            off += n;
            produced += n;
            if (buf.size() < maxChunk) buf.resize(std::min(buf.size() * 8, maxChunk));
        }
        pos += extLen;
    }
    if (produced < size) {
        // The extent list did not cover the whole logical size.
        note("a file's extent list is incomplete; the missing tail was filled "
             "with zeros");
        std::fill(buf.begin(), buf.end(), 0);
        while (produced < size) {
            size_t n = static_cast<size_t>(std::min<uint64_t>(size - produced, buf.size()));
            if (!sink(buf.data(), n)) return false;
            produced += n;
        }
    }
    return true;
}

// ------------------------------------------------------------------ catalog

bool HfsPlusFilesystem::parseCatalogRecord(const BTree::Rec& r, Record& out) {
    if (r.keyLen < 6 || r.valLen < 2) return false;
    out.parentId = rdBE32(r.key);
    uint16_t nameLen = rdBE16(r.key + 4);
    if (6 + static_cast<size_t>(nameLen) * 2 > r.keyLen) return false;
    out.name = utf16beToUtf8(r.key + 6, nameLen);

    uint16_t type = rdBE16(r.val);
    if (type == REC_FOLDER) {
        if (r.valLen < 88) return false;
        out.isDir = true;
        out.valence = rdBE32(r.val + 4);
        out.cnid = rdBE32(r.val + 8);
        out.times.crtime = hfsTimeToNs(rdBE32(r.val + 12));
        out.times.mtime = hfsTimeToNs(rdBE32(r.val + 16));
        out.times.atime = hfsTimeToNs(rdBE32(r.val + 24));
        out.mode = rdBE16(r.val + 42);
        return true;
    }
    if (type == REC_FILE) {
        if (r.valLen < 248) return false;
        out.isDir = false;
        out.cnid = rdBE32(r.val + 8);
        out.times.crtime = hfsTimeToNs(rdBE32(r.val + 12));
        out.times.mtime = hfsTimeToNs(rdBE32(r.val + 16));
        out.times.atime = hfsTimeToNs(rdBE32(r.val + 24));
        out.mode = rdBE16(r.val + 42);
        out.linkTarget = rdBE32(r.val + 44); // permissions.special
        out.typeCode = fourCC(r.val + 48);
        out.creatorCode = fourCC(r.val + 52);

        auto fork = [&](size_t off, uint8_t forkType, Fork& f) {
            f.cnid = out.cnid;
            f.forkType = forkType;
            f.logicalSize = rdBE64(r.val + off);
            f.totalBlocks = rdBE32(r.val + off + 12);
            f.extents.clear();
            for (int i = 0; i < 8; ++i) {
                Extent e;
                e.startBlock = rdBE32(r.val + off + 16 + i * 8);
                e.blockCount = rdBE32(r.val + off + 16 + i * 8 + 4);
                if (e.blockCount) f.extents.push_back(e);
            }
        };
        fork(88, FORK_DATA, out.data);
        fork(168, FORK_RSRC, out.rsrc);
        return true;
    }
    return false; // thread records are not entries in their own right
}

// Every catalog search descends on the parent id alone and then scans the
// group: children of one folder are contiguous in the tree. Doing it this way
// avoids having to reimplement HFS+ name ordering, which differs between
// case-folding HFS+ and binary-compare HFSX and is a classic source of
// silently missed files.
std::vector<FsNode> HfsPlusFilesystem::listDir(const FsNode& dir) {
    std::vector<FsNode> out;
    const uint32_t parent = static_cast<uint32_t>(dir.id ? dir.id : CNID_ROOT);
    auto cur = catalog_.lowerBound([parent](const uint8_t* k, size_t kl) -> int {
        if (kl < 4) return -1;
        uint32_t p = rdBE32(k);
        return p < parent ? -1 : 1;
    });
    for (; cur.valid(); cur.next()) {
        const auto& r = cur.rec();
        if (r.keyLen < 4 || rdBE32(r.key) != parent) break;
        if (r.valLen >= 2) {
            uint16_t type = rdBE16(r.val);
            if (type == REC_FOLDER_THREAD || type == REC_FILE_THREAD) continue;
        }
        Record rec;
        if (!parseCatalogRecord(r, rec)) continue;

        FsNode n;
        n.id = rec.cnid;
        n.name = displayName(rec.name);
        n.isDir = rec.isDir;
        n.times = rec.times;
        if (!rec.isDir) {
            n.size = rec.data.logicalSize;
            if (rec.typeCode == "hlnk" && rec.creatorCode == "hfs+") {
                // A hard link: the bytes live on the inode it points at.
                if (auto target = resolveHardLink(rec)) {
                    n.size = target->data.logicalSize;
                    rec.data = target->data;
                    rec.rsrc = target->rsrc;
                }
            }
            if (n.size == 0) {
                // Possibly transparently compressed: the real length is in the
                // decmpfs attribute, and the data fork is empty.
                if (auto attr = readAttribute(rec.cnid, "com.apple.decmpfs")) {
                    compression::DecmpfsHeader h;
                    if (compression::parseDecmpfsHeader(attr->data(), attr->size(), h))
                        n.size = h.uncompressedSize;
                }
            }
        }
        {
            std::lock_guard<std::mutex> lk(cacheMutex_);
            if (cache_.size() > 300000) cache_.clear();
            cache_[rec.cnid] = rec;
        }
        out.push_back(std::move(n));
    }
    return out;
}

std::optional<HfsPlusFilesystem::Record> HfsPlusFilesystem::recordByCnid(uint32_t cnid) {
    {
        std::lock_guard<std::mutex> lk(cacheMutex_);
        auto it = cache_.find(cnid);
        if (it != cache_.end()) return it->second;
    }
    // Not seen yet: the thread record keyed by (cnid, empty name) names the
    // object's parent, and its siblings are then a group scan away.
    auto cur = catalog_.lowerBound([cnid](const uint8_t* k, size_t kl) -> int {
        if (kl < 4) return -1;
        uint32_t p = rdBE32(k);
        return p < cnid ? -1 : 1;
    });
    if (!cur.valid()) return std::nullopt;
    const auto& r = cur.rec();
    if (r.keyLen < 4 || rdBE32(r.key) != cnid || r.valLen < 8) return std::nullopt;
    uint16_t type = rdBE16(r.val);
    if (type != REC_FOLDER_THREAD && type != REC_FILE_THREAD) return std::nullopt;

    uint32_t parent = rdBE32(r.val + 4);
    if (r.valLen < 10) return std::nullopt;
    uint16_t nameLen = rdBE16(r.val + 8);
    if (10 + static_cast<size_t>(nameLen) * 2 > r.valLen) return std::nullopt;
    std::string name = utf16beToUtf8(r.val + 10, nameLen);
    if (cnid == CNID_ROOT) {
        Record root;
        root.cnid = CNID_ROOT;
        root.isDir = true;
        root.name = name;
        return root;
    }
    return childByName(parent, name);
}

std::optional<HfsPlusFilesystem::Record>
HfsPlusFilesystem::childByName(uint32_t parent, const std::string& name) {
    auto cur = catalog_.lowerBound([parent](const uint8_t* k, size_t kl) -> int {
        if (kl < 4) return -1;
        uint32_t p = rdBE32(k);
        return p < parent ? -1 : 1;
    });
    for (; cur.valid(); cur.next()) {
        const auto& r = cur.rec();
        if (r.keyLen < 4 || rdBE32(r.key) != parent) break;
        Record rec;
        if (!parseCatalogRecord(r, rec)) continue;
        if (rec.name != name) continue;
        std::lock_guard<std::mutex> lk(cacheMutex_);
        cache_[rec.cnid] = rec;
        return rec;
    }
    return std::nullopt;
}

std::optional<HfsPlusFilesystem::Record>
HfsPlusFilesystem::resolveHardLink(const Record& rec) {
    if (privateDirCnid_ == 0) {
        auto dir = childByName(CNID_ROOT, PRIVATE_DATA_DIR);
        if (!dir || !dir->isDir) {
            note("this volume uses hard links but its private link folder is "
                 "missing; linked files may read as empty");
            return std::nullopt;
        }
        privateDirCnid_ = dir->cnid;
    }
    return childByName(privateDirCnid_, "iNode" + std::to_string(rec.linkTarget));
}

FsNode HfsPlusFilesystem::root() {
    FsNode n;
    n.id = CNID_ROOT;
    n.isDir = true;
    n.name = volName_.empty() ? "HFS+ volume" : displayName(volName_);
    return n;
}

FsTimes HfsPlusFilesystem::fileTimes(const FsNode& node) {
    if (auto r = recordByCnid(static_cast<uint32_t>(node.id))) return r->times;
    return node.times;
}

// --------------------------------------------------------------- attributes

std::optional<std::vector<uint8_t>>
HfsPlusFilesystem::readAttribute(uint32_t cnid, const std::string& name) {
    if (!attributes_.ok()) return std::nullopt;
    auto cur = attributes_.lowerBound([cnid](const uint8_t* k, size_t kl) -> int {
        if (kl < 10) return -1;
        uint32_t f = rdBE32(k + 2); // after the 2-byte pad
        return f < cnid ? -1 : 1;
    });
    for (; cur.valid(); cur.next()) {
        const auto& r = cur.rec();
        if (r.keyLen < 12 || rdBE32(r.key + 2) != cnid) break;
        uint16_t nameLen = rdBE16(r.key + 10);
        if (12 + static_cast<size_t>(nameLen) * 2 > r.keyLen) continue;
        if (utf16beToUtf8(r.key + 12, nameLen) != name) continue;
        if (r.valLen < 16) return std::nullopt;

        uint32_t recType = rdBE32(r.val);
        if (recType == ATTR_INLINE_DATA) {
            uint32_t size = rdBE32(r.val + 12);
            if (16 + static_cast<size_t>(size) > r.valLen) return std::nullopt;
            return std::vector<uint8_t>(r.val + 16, r.val + 16 + size);
        }
        if (recType == ATTR_FORK_DATA) {
            if (r.valLen < 88) return std::nullopt;
            Fork f;
            f.cnid = cnid;
            f.forkType = FORK_DATA;
            f.logicalSize = rdBE64(r.val + 8);
            f.totalBlocks = rdBE32(r.val + 8 + 12);
            for (int i = 0; i < 8; ++i) {
                Extent e;
                e.startBlock = rdBE32(r.val + 8 + 16 + i * 8);
                e.blockCount = rdBE32(r.val + 8 + 16 + i * 8 + 4);
                if (e.blockCount) f.extents.push_back(e);
            }
            // Attribute forks do not use the extents-overflow file.
            return readFork(f, 0, static_cast<size_t>(f.logicalSize));
        }
        return std::nullopt;
    }
    return std::nullopt;
}

// ------------------------------------------------------------------ reading

bool HfsPlusFilesystem::streamCompressed(const Record& rec, const DataSink& sink) {
    auto attr = readAttribute(rec.cnid, "com.apple.decmpfs");
    if (!attr) return false;
    std::string err;
    bool ok = compression::decmpfsDecompress(
        *attr,
        [&]() -> std::vector<uint8_t> {
            // The resource fork carries the compressed blocks for the larger
            // schemes; it is a real fork here, not an attribute.
            return readFork(rec.rsrc, 0, static_cast<size_t>(rec.rsrc.logicalSize));
        },
        [&](const uint8_t* d, size_t n) { return sink(d, n); }, &err);
    if (!ok && !err.empty() && err != "aborted")
        note("compressed file '" + rec.name + "' could not be decoded: " + err);
    return ok;
}

bool HfsPlusFilesystem::readFileStream(const FsNode& file, const DataSink& sink) {
    auto rec = recordByCnid(static_cast<uint32_t>(file.id));
    if (!rec) return false;
    if (rec->isDir) return false;
    if (rec->typeCode == "hlnk" && rec->creatorCode == "hfs+") {
        if (auto target = resolveHardLink(*rec)) rec = target;
    }
    if (rec->data.logicalSize == 0 && attributes_.ok()) {
        // An empty data fork on a Mac volume usually means the contents are
        // compressed into the decmpfs attribute rather than that the file is
        // empty - exporting it as zero bytes would look like a clean recovery
        // of nothing.
        if (auto attr = readAttribute(rec->cnid, "com.apple.decmpfs")) {
            (void)attr;
            return streamCompressed(*rec, sink);
        }
    }
    return streamFork(rec->data, rec->data.logicalSize, sink);
}

std::vector<uint8_t> HfsPlusFilesystem::readFile(const FsNode& file) {
    std::vector<uint8_t> out;
    readFileStream(file, [&](const uint8_t* d, size_t n) {
        out.insert(out.end(), d, d + n);
        return true;
    });
    return out;
}

std::vector<uint8_t> HfsPlusFilesystem::readResourceFork(const FsNode& file) {
    auto rec = recordByCnid(static_cast<uint32_t>(file.id));
    if (!rec || rec->isDir || rec->rsrc.logicalSize == 0) return {};
    // When a file is compressed the resource fork holds the compressed blocks,
    // not a resource fork the user would want beside the file.
    if (rec->data.logicalSize == 0 && attributes_.ok() &&
        readAttribute(rec->cnid, "com.apple.decmpfs"))
        return {};
    return readFork(rec->rsrc, 0, static_cast<size_t>(rec->rsrc.logicalSize));
}

// -------------------------------------------------------------------- notes

void HfsPlusFilesystem::note(const std::string& msg) {
    std::lock_guard<std::mutex> lk(noteMutex_);
    if (std::find(notes_.begin(), notes_.end(), msg) == notes_.end())
        notes_.push_back(msg);
}

std::vector<std::string> HfsPlusFilesystem::notes() const {
    std::lock_guard<std::mutex> lk(noteMutex_);
    return notes_;
}

} // namespace de
