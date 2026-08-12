#include "fs/apfs/apfs.h"
#include "core/byte_reader.h"
#include "fs/compression/decmpfs.h"
#include <algorithm>
#include <cstring>

namespace de {

using namespace de::apfs;
using namespace de::compression;

namespace {

constexpr const char* DECMPFS_XATTR = "com.apple.decmpfs";
constexpr const char* RSRC_XATTR = "com.apple.ResourceFork";

// j_xattr_val_t flags.
constexpr uint16_t XATTR_DATA_STREAM = 0x0001;
constexpr uint16_t XATTR_DATA_EMBEDDED = 0x0002;

// Search comparator for a filesystem-tree key.
//
// APFS orders these keys by object id first and record type second - which is
// *not* the order a plain 64-bit compare of obj_id_and_type would give,
// because the type sits in the top four bits.
//
// The target is "(oid, type) with an empty tail", i.e. the position just
// before the first record of that group, so this never reports equality: every
// stored key that shares the (oid, type) prefix has some tail and therefore
// sorts *after* the target. That matters. A comparator that answered "equal"
// for the whole group would leave the B-tree descent free to pick any node
// holding a group member, and on a tree deep enough to have several of them we
// would silently start reading from the middle of a directory.
int cmpJKeyLower(const uint8_t* k, size_t klen, uint64_t oid, uint8_t type) {
    if (klen < 8) return -1;
    uint64_t v = rd64(k);
    uint64_t o = v & OBJ_ID_MASK;
    uint8_t t = static_cast<uint8_t>(v >> OBJ_TYPE_SHIFT);
    if (o != oid) return o < oid ? -1 : 1;
    if (t != type) return t < type ? -1 : 1;
    return 1; // same group: sorts after the group's starting position
}

// Does this leaf entry still belong to the (oid, type) group we are scanning?
bool inGroup(const BTreeEntry& e, uint64_t oid, uint8_t type) {
    if (!e.key || e.keyLen < 8) return false;
    uint64_t v = rd64(e.key);
    return (v & OBJ_ID_MASK) == oid &&
           static_cast<uint8_t>(v >> OBJ_TYPE_SHIFT) == type;
}

// Extended fields ("xfields") trailing an inode record. The blob is a small
// header, then a table of {type, flags, size}, then the values themselves,
// each padded out to an 8-byte boundary.
struct XField {
    const uint8_t* data = nullptr;
    size_t size = 0;
};

bool parseXfields(const uint8_t* val, size_t len, size_t base,
                  std::map<uint8_t, XField>& out) {
    if (base + 4 > len) return false;
    uint16_t num = rd16(val + base);
    uint16_t used = rd16(val + base + 2);
    if (num == 0 || num > 64) return false;
    size_t arrEnd = base + 4 + static_cast<size_t>(num) * 4;
    if (arrEnd > len) return false;
    if (used > len - arrEnd + 8) return false; // allow for tail padding
    size_t off = arrEnd;
    std::map<uint8_t, XField> found;
    for (uint16_t i = 0; i < num; ++i) {
        const uint8_t* ent = val + base + 4 + i * 4;
        uint8_t type = ent[0];
        uint16_t size = rd16(ent + 2);
        if (off + size > len) return false;
        found[type] = XField{val + off, size};
        off += (size + 7) & ~size_t(7);
        if (off > len) return false;
    }
    out.swap(found);
    return true;
}

// APFS grew a field in the middle of j_inode_val_t over its lifetime, so the
// extended fields do not start at a single fixed offset across all versions.
// Rather than guess from a version number that damaged volumes may not have,
// try the known offsets and keep the first blob that describes itself
// consistently - a wrong guess fails the bounds checks above almost every time.
bool parseInodeXfields(const uint8_t* val, size_t len,
                       std::map<uint8_t, XField>& out) {
    for (size_t base : {size_t(96), size_t(92), size_t(84)})
        if (base < len && parseXfields(val, len, base, out)) return true;
    return false;
}

std::string trimName(const uint8_t* p, size_t len) {
    // APFS stores names NUL-terminated, with the terminator counted in the
    // recorded length.
    while (len > 0 && p[len - 1] == 0) --len;
    return std::string(reinterpret_cast<const char*>(p), len);
}

} // namespace

// --------------------------------------------------------------- lifecycle

bool ApfsFilesystem::probe(ImageSource& vol) { return Container::probe(vol); }

std::unique_ptr<ApfsFilesystem> ApfsFilesystem::open(std::shared_ptr<ImageSource> vol,
                                                     std::shared_ptr<ImageSource> tier2) {
    std::string why;
    auto c = Container::open(std::move(vol), std::move(tier2), &why);
    if (!c) return nullptr;

    auto fs = std::unique_ptr<ApfsFilesystem>(new ApfsFilesystem());
    fs->container_ = c;
    for (auto& n : c->notes()) fs->notes_.push_back(n);

    for (const auto& vi : c->volumes()) {
        Volume v;
        v.info = vi;
        // The volume's object map is a physical object, so its oid is already
        // a block address; the filesystem tree is virtual and has to be looked
        // up through that map.
        v.omap = std::make_shared<Omap>(c->reader(), vi.omapOid);
        if (v.omap->ok()) {
            if (auto rootPaddr = v.omap->lookup(vi.rootTreeOid, c->xid())) {
                auto omap = v.omap;
                uint64_t xid = c->xid();
                v.tree = std::make_shared<BTree>(
                    c->reader(), *rootPaddr,
                    [omap, xid](uint64_t oid) -> uint64_t {
                        return omap->lookup(oid, xid).value_or(0);
                    });
                v.ok = true;
            }
        }
        if (!v.ok)
            fs->notes_.push_back("volume '" + vi.name +
                                 "': filesystem tree could not be located");
        if (vi.encrypted)
            fs->notes_.push_back("volume '" + vi.name +
                                 "' is FileVault-encrypted; its file names and "
                                 "contents cannot be read without the password");
        fs->volumes_.push_back(std::move(v));
    }
    return fs;
}

std::string ApfsFilesystem::typeName() const {
    return container_ && container_->fusion() ? "APFS (Fusion)" : "APFS";
}

std::vector<std::string> ApfsFilesystem::notes() const {
    std::lock_guard<std::mutex> lk(noteMutex_);
    return notes_;
}

void ApfsFilesystem::note(const std::string& msg) {
    std::lock_guard<std::mutex> lk(noteMutex_);
    // Keep the list useful rather than exhaustive: one line per distinct
    // problem, not one per affected file.
    if (std::find(notes_.begin(), notes_.end(), msg) == notes_.end())
        notes_.push_back(msg);
}

FsNode ApfsFilesystem::root() {
    FsNode n;
    n.id = 0;
    n.isDir = true;
    n.name = "APFS container";
    return n;
}

ApfsFilesystem::Volume* ApfsFilesystem::volumeFor(uint64_t nodeId) {
    uint32_t vi = volIndexOf(nodeId);
    if (vi == 0 || vi > volumes_.size()) return nullptr;
    Volume* v = &volumes_[vi - 1];
    return v->ok ? v : nullptr;
}

// ------------------------------------------------------------- tree records

std::optional<ApfsFilesystem::Inode> ApfsFilesystem::findInode(Volume& v,
                                                               uint64_t oid) {
    auto cur = v.tree->lowerBound([oid](const uint8_t* k, size_t kl) {
        return cmpJKeyLower(k, kl, oid, APFS_TYPE_INODE);
    });
    if (!cur.valid() || !inGroup(cur.entry(), oid, APFS_TYPE_INODE))
        return std::nullopt;
    const auto& e = cur.entry();
    if (e.valLen < 84) return std::nullopt;

    Inode in;
    in.oid = oid;
    in.parentId = rd64(e.val);
    in.privateId = rd64(e.val + 8);
    in.times.crtime = static_cast<int64_t>(rd64(e.val + 16));
    in.times.mtime = static_cast<int64_t>(rd64(e.val + 24));
    in.times.atime = static_cast<int64_t>(rd64(e.val + 40));
    in.internalFlags = rd64(e.val + 48);
    in.mode = rd16(e.val + 80);
    if (e.valLen >= 96) in.uncompressedSize = rd64(e.val + 88);

    std::map<uint8_t, XField> xf;
    if (parseInodeXfields(e.val, e.valLen, xf)) {
        if (auto it = xf.find(INO_EXT_TYPE_DSTREAM);
            it != xf.end() && it->second.size >= 16) {
            Dstream ds;
            ds.size = rd64(it->second.data);
            ds.allocedSize = rd64(it->second.data + 8);
            in.dstream = ds;
        }
        if (auto it = xf.find(INO_EXT_TYPE_NAME); it != xf.end())
            in.name = trimName(it->second.data, it->second.size);
    }
    return in;
}

std::vector<ApfsFilesystem::Extent> ApfsFilesystem::extentsFor(Volume& v,
                                                               uint64_t streamId) {
    std::vector<Extent> out;
    auto cur = v.tree->lowerBound([streamId](const uint8_t* k, size_t kl) {
        return cmpJKeyLower(k, kl, streamId, APFS_TYPE_FILE_EXTENT);
    });
    for (; cur.valid(); cur.next()) {
        const auto& e = cur.entry();
        if (!inGroup(e, streamId, APFS_TYPE_FILE_EXTENT)) break;
        if (e.keyLen < 16 || e.valLen < 16) continue;
        Extent ex;
        ex.logical = rd64(e.key + 8);
        // j_file_extent_val_t: the low 56 bits of the first word are the
        // length in bytes; the top bits are flags (crypto id presence).
        ex.length = rd64(e.val) & 0x00FFFFFFFFFFFFFFULL;
        ex.physBlock = rd64(e.val + 8);
        out.push_back(ex);
    }
    std::sort(out.begin(), out.end(),
              [](const Extent& a, const Extent& b) { return a.logical < b.logical; });
    return out;
}

std::optional<std::vector<uint8_t>> ApfsFilesystem::readXattr(Volume& v, uint64_t oid,
                                                              const std::string& name) {
    auto cur = v.tree->lowerBound([oid](const uint8_t* k, size_t kl) {
        return cmpJKeyLower(k, kl, oid, APFS_TYPE_XATTR);
    });
    for (; cur.valid(); cur.next()) {
        const auto& e = cur.entry();
        if (!inGroup(e, oid, APFS_TYPE_XATTR)) break;
        if (e.keyLen < 10) continue;
        uint16_t nameLen = rd16(e.key + 8);
        if (10 + static_cast<size_t>(nameLen) > e.keyLen) continue;
        if (trimName(e.key + 10, nameLen) != name) continue;
        if (e.valLen < 4) return std::nullopt;

        uint16_t flags = rd16(e.val);
        uint16_t xdataLen = rd16(e.val + 2);
        const uint8_t* xdata = e.val + 4;
        if (flags & XATTR_DATA_STREAM) {
            // The attribute is too big to inline: it has its own data stream,
            // keyed by the object id in front of the embedded dstream record.
            if (xdataLen < 48 || e.valLen < 4u + 48u) return std::nullopt;
            uint64_t streamId = rd64(xdata);
            uint64_t size = rd64(xdata + 8); // j_dstream_t.size
            std::vector<uint8_t> buf;
            buf.reserve(static_cast<size_t>(std::min<uint64_t>(size, 64u << 20)));
            if (!streamExtents(v, streamId, size,
                               [&](const uint8_t* d, size_t n) {
                                   buf.insert(buf.end(), d, d + n);
                                   return true;
                               }))
                return std::nullopt;
            return buf;
        }
        if (flags & XATTR_DATA_EMBEDDED) {
            if (4u + xdataLen > e.valLen) return std::nullopt;
            return std::vector<uint8_t>(xdata, xdata + xdataLen);
        }
        return std::nullopt;
    }
    return std::nullopt;
}

// ------------------------------------------------------------------ listing

std::vector<FsNode> ApfsFilesystem::listDir(const FsNode& dir) {
    std::vector<FsNode> out;

    // The synthetic root: one entry per volume in the container.
    if (dir.id == 0) {
        for (size_t i = 0; i < volumes_.size(); ++i) {
            const auto& vi = volumes_[i].info;
            FsNode n;
            n.id = makeId(static_cast<uint32_t>(i), ROOT_DIR_INO_NUM);
            n.isDir = true;
            n.name = vi.name.empty() ? ("volume " + std::to_string(i + 1)) : vi.name;
            if (!vi.role.empty()) n.name += " (" + vi.role + ")";
            if (vi.encrypted) n.name += " [encrypted]";
            n.times.mtime = vi.lastModTime;
            out.push_back(std::move(n));
        }
        return out;
    }

    Volume* v = volumeFor(dir.id);
    if (!v) return out;
    const uint32_t vidx = volIndexOf(dir.id) - 1;
    const uint64_t oid = oidOf(dir.id);

    auto cur = v->tree->lowerBound([oid](const uint8_t* k, size_t kl) {
        return cmpJKeyLower(k, kl, oid, APFS_TYPE_DIR_REC);
    });
    for (; cur.valid(); cur.next()) {
        const auto& e = cur.entry();
        if (!inGroup(e, oid, APFS_TYPE_DIR_REC)) break;
        if (e.valLen < 18) continue;

        // Two directory-record key layouts exist: the hashed one (a 32-bit
        // word holding the name length and a hash) used by case-insensitive
        // volumes, and the plain one with a 16-bit length. Tell them apart by
        // which reading accounts for the whole key.
        std::string name;
        if (e.keyLen >= 12) {
            uint32_t hashed = rd32(e.key + 8);
            size_t hlen = hashed & 0x3FF;
            if (12 + hlen == e.keyLen) name = trimName(e.key + 12, hlen);
        }
        if (name.empty() && e.keyLen >= 10) {
            size_t plen = rd16(e.key + 8);
            if (10 + plen == e.keyLen) name = trimName(e.key + 10, plen);
        }
        if (name.empty()) continue;

        uint64_t childId = rd64(e.val);
        uint16_t flags = rd16(e.val + 16);

        FsNode n;
        n.id = makeId(vidx, childId);
        n.name = name;
        n.isDir = (flags & DREC_TYPE_MASK) == DT_DIR;
        n.times.mtime = static_cast<int64_t>(rd64(e.val + 8)); // date added

        // Size and real timestamps come from the child's inode.
        if (auto in = findInode(*v, childId)) {
            n.times = in->times;
            if (!n.isDir) n.isDir = (in->mode & S_IFMT_) == S_IFDIR_;
            if (in->dstream)
                n.size = in->dstream->size;
            else if (in->uncompressedSize)
                n.size = in->uncompressedSize;
            else if (!n.isDir)
                n.size = compressedSize(*v, childId);
        }
        out.push_back(std::move(n));
    }
    return out;
}

uint64_t ApfsFilesystem::compressedSize(Volume& v, uint64_t oid) {
    auto attr = readXattr(v, oid, DECMPFS_XATTR);
    if (!attr) return 0;
    DecmpfsHeader h;
    if (!parseDecmpfsHeader(attr->data(), attr->size(), h)) return 0;
    return h.uncompressedSize;
}

// ------------------------------------------------------------------ reading

bool ApfsFilesystem::streamExtents(Volume& v, uint64_t streamId, uint64_t size,
                                   const DataSink& sink) {
    const uint32_t bs = container_->blockSize();
    auto extents = extentsFor(v, streamId);
    // Small first chunk, growing: readHead() then costs 64 KiB, not a megabyte.
    std::vector<uint8_t> buf(64u << 10);
    const size_t maxChunk = 1u << 20;
    uint64_t pos = 0;

    for (const auto& ex : extents) {
        if (pos >= size) break;
        // A gap between extents is a sparse hole; so is an extent with no
        // physical block. Both read back as zeros.
        if (ex.logical > pos) {
            uint64_t hole = std::min<uint64_t>(ex.logical - pos, size - pos);
            std::fill(buf.begin(), buf.end(), 0);
            while (hole > 0) {
                size_t n = static_cast<size_t>(std::min<uint64_t>(hole, buf.size()));
                if (!sink(buf.data(), n)) return false;
                hole -= n;
                pos += n;
            }
        }
        if (pos >= size) break;
        uint64_t want = std::min<uint64_t>(ex.length, size - pos);
        if (ex.physBlock == 0) {
            std::fill(buf.begin(), buf.end(), 0);
            while (want > 0) {
                size_t n = static_cast<size_t>(std::min<uint64_t>(want, buf.size()));
                if (!sink(buf.data(), n)) return false;
                want -= n;
                pos += n;
            }
            continue;
        }
        uint64_t off = 0;
        while (want > 0) {
            size_t n = static_cast<size_t>(std::min<uint64_t>(want, buf.size()));
            size_t got = container_->reader().readBytes(ex.physBlock, off, buf.data(), n);
            if (got < n) {
                // A short read means unreadable media, not end of file: zero the
                // tail so the export keeps its shape, and say so once.
                std::fill(buf.begin() + got, buf.begin() + n, 0);
                note("some blocks could not be read from the device; the "
                     "affected parts of those files were filled with zeros");
            }
            if (!sink(buf.data(), n)) return false;
            want -= n;
            off += n;
            pos += n;
            if (buf.size() < maxChunk) buf.resize(std::min(buf.size() * 8, maxChunk));
        }
        (void)bs;
    }
    // Trailing hole in a sparse file.
    if (pos < size) {
        std::fill(buf.begin(), buf.end(), 0);
        while (pos < size) {
            size_t n = static_cast<size_t>(std::min<uint64_t>(size - pos, buf.size()));
            if (!sink(buf.data(), n)) return false;
            pos += n;
        }
    }
    return true;
}

bool ApfsFilesystem::readFileStream(const FsNode& file, const DataSink& sink) {
    Volume* v = volumeFor(file.id);
    if (!v) return false;
    uint64_t oid = oidOf(file.id);
    auto in = findInode(*v, oid);
    if (!in) return false;

    // Transparently compressed files have an empty data fork; their contents
    // live in the decmpfs attribute (and, for larger ones, the resource fork).
    if (auto attr = readXattr(*v, oid, DECMPFS_XATTR)) {
        std::string err;
        bool ok = decmpfsDecompress(
            *attr,
            [&]() -> std::vector<uint8_t> {
                auto rsrc = readXattr(*v, oid, RSRC_XATTR);
                return rsrc ? *rsrc : std::vector<uint8_t>{};
            },
            [&](const uint8_t* d, size_t n) { return sink(d, n); }, &err);
        if (!ok && !err.empty() && err != "aborted")
            note("compressed file could not be decoded: " + err);
        return ok;
    }

    uint64_t size = in->dstream ? in->dstream->size : 0;
    if (size == 0) return true; // genuinely empty file
    return streamExtents(*v, in->privateId ? in->privateId : oid, size, sink);
}

std::vector<uint8_t> ApfsFilesystem::readFile(const FsNode& file) {
    std::vector<uint8_t> out;
    readFileStream(file, [&](const uint8_t* d, size_t n) {
        out.insert(out.end(), d, d + n);
        return true;
    });
    return out;
}

std::vector<uint8_t> ApfsFilesystem::readResourceFork(const FsNode& file) {
    Volume* v = volumeFor(file.id);
    if (!v) return {};
    uint64_t oid = oidOf(file.id);
    // When a file is decmpfs-compressed its resource fork holds the compressed
    // data, not a real resource fork - exporting that as a sidecar would just
    // be confusing, so skip it.
    if (readXattr(*v, oid, DECMPFS_XATTR)) return {};
    auto rsrc = readXattr(*v, oid, RSRC_XATTR);
    return rsrc ? *rsrc : std::vector<uint8_t>{};
}

FsTimes ApfsFilesystem::fileTimes(const FsNode& node) {
    Volume* v = volumeFor(node.id);
    if (!v) return node.times;
    if (auto in = findInode(*v, oidOf(node.id))) return in->times;
    return node.times;
}

} // namespace de
