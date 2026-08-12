#include "fs/apfs/apfs_container.h"
#include "core/byte_reader.h"
#include <algorithm>
#include <cstring>

namespace de::apfs {

// ---------------------------------------------------------------- checksums

uint64_t fletcher64(const uint8_t* data, size_t len, uint64_t init) {
    uint64_t sum1 = init & 0xFFFFFFFFULL;
    uint64_t sum2 = init >> 32;
    const size_t words = len / 4;
    for (size_t i = 0; i < words; ++i) {
        sum1 = (sum1 + rd32(data + i * 4)) % 0xFFFFFFFFULL;
        sum2 = (sum2 + sum1) % 0xFFFFFFFFULL;
    }
    return sum1 | (sum2 << 32);
}

bool verifyBlock(const uint8_t* block, size_t size) {
    if (size < OBJ_HDR_SIZE || (size % 4) != 0) return false;
    // Fold the body in first, then the stored checksum word pair; a block whose
    // checksum is correct sums back to zero.
    uint64_t cs = fletcher64(block + 8, size - 8, 0);
    cs = fletcher64(block, 8, cs);
    return cs == 0;
}

uint64_t computeChecksum(const uint8_t* block, size_t size) {
    uint64_t cs = fletcher64(block + 8, size - 8, 0);
    uint64_t sum1 = cs & 0xFFFFFFFFULL, sum2 = cs >> 32;
    uint64_t c1 = 0xFFFFFFFFULL - ((sum1 + sum2) % 0xFFFFFFFFULL);
    uint64_t c2 = 0xFFFFFFFFULL - ((sum1 + c1) % 0xFFFFFFFFULL);
    return c1 | (c2 << 32);
}

// -------------------------------------------------------------- BlockReader

ImageSource* BlockReader::deviceFor(uint64_t& paddr) const {
    if (tier2_ && (paddr & FUSION_TIER2_MARKER)) {
        paddr &= ~FUSION_TIER2_MARKER;
        return tier2_.get();
    }
    // Without a tier-2 device we still mask the marker off: reading the wrong
    // block is better than reading at an absurd offset, and the checksum will
    // flag it as unusable anyway.
    paddr &= ~FUSION_TIER2_MARKER;
    return main_.get();
}

std::vector<uint8_t> BlockReader::read(uint64_t paddr, uint32_t count) const {
    std::vector<uint8_t> buf(static_cast<size_t>(blockSize_) * count, 0);
    uint64_t p = paddr;
    ImageSource* dev = deviceFor(p);
    dev->readAt(p * blockSize_, buf.data(), buf.size());
    return buf;
}

size_t BlockReader::readBytes(uint64_t paddr, uint64_t byteOff, void* buf,
                              size_t len) const {
    uint64_t p = paddr;
    ImageSource* dev = deviceFor(p);
    return dev->readAt(p * blockSize_ + byteOff, buf, len);
}

// ---------------------------------------------------------------- BTreeNode

std::optional<BTreeNode> BTreeNode::parse(std::vector<uint8_t> block) {
    if (block.size() < BTN_DATA) return std::nullopt;
    BTreeNode n;
    n.checksumOk_ = verifyBlock(block.data(), block.size());
    n.flags_ = rd16(block.data() + BTN_FLAGS);
    n.level_ = rd16(block.data() + BTN_LEVEL);
    n.nkeys_ = rd32(block.data() + BTN_NKEYS);
    uint16_t tocOff = rd16(block.data() + BTN_TABLE_SPACE);
    uint16_t tocLen = rd16(block.data() + BTN_TABLE_SPACE + 2);
    n.fixed_ = (n.flags_ & BTNODE_FIXED_KV_SIZE) != 0;
    n.tocOff_ = BTN_DATA + tocOff;
    n.tocLen_ = tocLen;
    n.keyBase_ = BTN_DATA + tocOff + tocLen;
    // Values grow down from the end of the node; a root node reserves the
    // trailing btree_info_t, so they stop short of it.
    size_t end = block.size();
    if (n.flags_ & BTNODE_ROOT) {
        if (end < BTREE_INFO_SIZE) return std::nullopt;
        end -= BTREE_INFO_SIZE;
    }
    n.valEnd_ = end;
    // A plausible node: the tables fit inside the block and the key count is
    // not wilder than the table can describe.
    if (n.keyBase_ > block.size() || n.tocOff_ > block.size()) return std::nullopt;
    size_t perEntry = n.fixed_ ? 4u : 8u;
    if (static_cast<size_t>(n.nkeys_) * perEntry > n.tocLen_) return std::nullopt;
    n.block_ = std::move(block);
    return n;
}

BTreeEntry BTreeNode::entry(uint32_t i) const {
    BTreeEntry e;
    if (i >= nkeys_) return e;
    const uint8_t* b = block_.data();
    size_t keyOff, keyLen, valOff, valLen;
    if (fixed_) {
        // kvoff_t: offsets only; the sizes come from the tree's btree_info,
        // which the caller folds in via the fixed key/value sizes below.
        size_t t = tocOff_ + static_cast<size_t>(i) * 4;
        if (t + 4 > block_.size()) return e;
        keyOff = rd16(b + t);
        valOff = rd16(b + t + 2);
        keyLen = fixedKeySize_;
        valLen = isLeaf() ? fixedValSize_ : 8u;
    } else {
        // kvloc_t: offset+length for both halves.
        size_t t = tocOff_ + static_cast<size_t>(i) * 8;
        if (t + 8 > block_.size()) return e;
        keyOff = rd16(b + t);
        keyLen = rd16(b + t + 2);
        valOff = rd16(b + t + 4);
        valLen = rd16(b + t + 6);
    }
    size_t kStart = keyBase_ + keyOff;
    if (kStart + keyLen > block_.size() || kStart < keyBase_) return e;
    // Values are addressed as a distance back from the end of the node.
    if (valOff > valEnd_ || valLen > valEnd_) return e;
    size_t vStart = valEnd_ - valOff;
    if (vStart + valLen > block_.size()) return e;
    e.key = b + kStart;
    e.keyLen = keyLen;
    e.val = b + vStart;
    e.valLen = valLen;
    return e;
}

// -------------------------------------------------------------------- BTree

std::shared_ptr<BTreeNode> BTree::nodeAt(uint64_t paddr) const {
    auto blk = br_->read(paddr);
    // Only a B-tree node is a valid child; anything else means the tree (or
    // our idea of the disk layout) is broken, and we stop rather than walk off
    // into unrelated data.
    uint32_t type = rd32(blk.data() + O_TYPE) & OBJ_TYPE_MASK;
    if (type != OBJECT_TYPE_BTREE && type != OBJECT_TYPE_BTREE_NODE) return nullptr;
    auto n = BTreeNode::parse(std::move(blk));
    if (!n) return nullptr;
    auto sp = std::make_shared<BTreeNode>(std::move(*n));
    sp->setFixedSizes(fixedKeySize_, fixedValSize_);
    return sp;
}

void BTree::loadRootInfo() const {
    if (rootLoaded_) return;
    rootLoaded_ = true;
    auto blk = br_->read(rootPaddr_);
    if (blk.size() < BTREE_INFO_SIZE) return;
    // btree_info_t sits at the tail of the root node: bt_fixed {flags,
    // node_size, key_size, val_size} then the longest-key/value stats.
    const uint8_t* info = blk.data() + blk.size() - BTREE_INFO_SIZE;
    fixedKeySize_ = rd32(info + 8);
    fixedValSize_ = rd32(info + 12);
}

bool BTree::valid() const {
    loadRootInfo();
    auto n = nodeAt(rootPaddr_);
    return n && n->checksumOk();
}

// First index whose key compares strictly greater than the target (cmp > 0).
static uint32_t firstGreater(const BTreeNode& n, const BTree::Compare& cmp) {
    uint32_t lo = 0, hi = n.count();
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        auto e = n.entry(mid);
        if (!e.key) { hi = mid; continue; }
        if (cmp(e.key, e.keyLen) > 0) hi = mid; else lo = mid + 1;
    }
    return lo;
}

// First index whose key is not less than the target (cmp >= 0).
static uint32_t firstNotLess(const BTreeNode& n, const BTree::Compare& cmp) {
    uint32_t lo = 0, hi = n.count();
    while (lo < hi) {
        uint32_t mid = lo + (hi - lo) / 2;
        auto e = n.entry(mid);
        if (!e.key) { hi = mid; continue; }
        if (cmp(e.key, e.keyLen) >= 0) hi = mid; else lo = mid + 1;
    }
    return lo;
}

BTree::Cursor BTree::lowerBound(const Compare& cmp) const {
    loadRootInfo();
    Cursor c;
    c.tree_ = this;
    auto node = nodeAt(rootPaddr_);
    if (!node) return c;
    while (true) {
        if (node->isLeaf()) {
            c.path_.push_back({node, firstNotLess(*node, cmp)});
            break;
        }
        // Descend into the last child whose separator key is <= the target.
        uint32_t g = firstGreater(*node, cmp);
        uint32_t idx = g > 0 ? g - 1 : 0;
        c.path_.push_back({node, idx});
        auto e = node->entry(idx);
        if (!e.val || e.valLen < 8) return c;
        uint64_t child = resolve_ ? resolve_(rd64(e.val)) : rd64(e.val);
        if (child == 0) return c;
        auto next = nodeAt(child);
        if (!next) return c;
        node = next;
    }
    c.load();
    return c;
}

BTree::Cursor BTree::first() const {
    return lowerBound([](const uint8_t*, size_t) { return 1; });
}

void BTree::Cursor::load() {
    valid_ = false;
    entry_ = BTreeEntry{};
    while (!path_.empty()) {
        auto& top = path_.back();
        if (top.index < top.node->count()) {
            entry_ = top.node->entry(top.index);
            valid_ = entry_.key != nullptr;
            if (valid_) return;
        }
        // Ran off the end of this node: step the parent and re-descend.
        path_.pop_back();
        if (path_.empty()) return;
        path_.back().index++;
        if (!descend()) return;
    }
}

bool BTree::Cursor::descend() {
    // path_.back() is an index node positioned on a child pointer; walk down to
    // that child's leftmost leaf.
    while (!path_.empty()) {
        auto& top = path_.back();
        if (top.index >= top.node->count()) {
            path_.pop_back();
            if (path_.empty()) return false;
            path_.back().index++;
            continue;
        }
        if (top.node->isLeaf()) return true;
        auto e = top.node->entry(top.index);
        if (!e.val || e.valLen < 8) return false;
        uint64_t oid = rd64(e.val);
        uint64_t child = tree_->resolve_ ? tree_->resolve_(oid) : oid;
        if (child == 0) return false;
        auto n = tree_->nodeAt(child);
        if (!n) return false;
        path_.push_back({n, 0});
    }
    return false;
}

bool BTree::Cursor::next() {
    if (path_.empty()) { valid_ = false; return false; }
    path_.back().index++;
    load();
    return valid_;
}

// --------------------------------------------------------------------- Omap

Omap::Omap(const BlockReader& br, uint64_t omapPaddr) : br_(&br) {
    auto blk = br.read(omapPaddr);
    if ((rd32(blk.data() + O_TYPE) & OBJ_TYPE_MASK) != OBJECT_TYPE_OMAP) return;
    // omap_phys_t: om_tree_oid at offset 48. The tree is physical, so its oid
    // is already a block address.
    treePaddr_ = rd64(blk.data() + 48);
    if (treePaddr_ == 0) return;
    ok_ = true;
}

std::optional<uint64_t> Omap::lookup(uint64_t oid, uint64_t maxXid) const {
    if (!ok_) return std::nullopt;
    BTree tree(*br_, treePaddr_, nullptr); // physical tree: oid == paddr
    // omap_key_t {oid, xid}; seek to the first record for this oid, then take
    // the newest transaction not newer than the one we are reading.
    //
    // The target is "(oid, xid 0)", strictly before any real record for that
    // oid, so the comparator never reports equality. Reporting equality for a
    // whole oid group would let the descent stop at any node containing one of
    // its records and skip the earlier ones.
    auto cmp = [oid](const uint8_t* k, size_t klen) -> int {
        if (klen < 16) return -1;
        uint64_t ko = rd64(k);
        return ko < oid ? -1 : 1;
    };
    std::optional<uint64_t> best;
    uint64_t bestXid = 0;
    for (auto c = tree.lowerBound(cmp); c.valid(); c.next()) {
        const auto& e = c.entry();
        if (e.keyLen < 16) break;
        uint64_t ko = rd64(e.key);
        if (ko != oid) break;
        uint64_t kx = rd64(e.key + 8);
        if (kx > maxXid) break;
        if (e.valLen < 16) continue;
        // omap_val_t {flags u32, size u32, paddr u64}
        if (!best || kx >= bestXid) {
            bestXid = kx;
            best = rd64(e.val + 8);
        }
    }
    return best;
}

// ---------------------------------------------------------------- Container

namespace {

std::string roleName(uint16_t role) {
    switch (role) {
        case 0x0000: return "";
        case 0x0001: return "System";
        case 0x0002: return "User";
        case 0x0004: return "Recovery";
        case 0x0008: return "VM";
        case 0x0010: return "Preboot";
        case 0x0020: return "Installer";
        case 0x0040: return "Data";
        case 0x0080: return "Baseband";
        case 0x0100: return "Update";
        default: return "role 0x" + std::to_string(role);
    }
}

// NUL-terminated fixed-width string out of a metadata block.
std::string fixedStr(const uint8_t* p, size_t max) {
    size_t n = 0;
    while (n < max && p[n]) ++n;
    return std::string(reinterpret_cast<const char*>(p), n);
}

} // namespace

bool Container::probe(ImageSource& src) {
    uint8_t b[64];
    if (src.readAt(0, b, sizeof b) < sizeof b) return false;
    if (rd32(b + NX_MAGIC_OFF) != NX_MAGIC) return false;
    uint32_t bs = rd32(b + NX_BLOCK_SIZE);
    return bs >= 512 && bs <= 65536 && (bs & (bs - 1)) == 0;
}

std::shared_ptr<Container> Container::open(std::shared_ptr<ImageSource> main,
                                           std::shared_ptr<ImageSource> tier2,
                                           std::string* why) {
    auto fail = [&](const char* msg) -> std::shared_ptr<Container> {
        if (why) *why = msg;
        return nullptr;
    };
    if (!main) return fail("no device");
    auto head = main->read(0, 4096);
    if (rd32(head.data() + NX_MAGIC_OFF) != NX_MAGIC)
        return fail("no NXSB container superblock at offset 0");
    uint32_t bs = rd32(head.data() + NX_BLOCK_SIZE);
    if (bs < 512 || bs > 65536 || (bs & (bs - 1)) != 0)
        return fail("implausible container block size");

    auto c = std::make_shared<Container>();
    c->br_ = std::make_shared<BlockReader>(main, tier2, bs);

    auto sb = c->br_->read(0);
    if (!verifyBlock(sb.data(), sb.size()))
        c->notes_.push_back("block 0 superblock failed its checksum; "
                            "using the newest checkpoint copy instead");

    // The live superblock is the newest checksum-clean NXSB in the checkpoint
    // descriptor area - block 0 is only a starting point and is often stale.
    uint32_t descBlocks = rd32(sb.data() + NX_XP_DESC_BLOCKS);
    uint64_t descBase = rd64(sb.data() + NX_XP_DESC_BASE);
    std::vector<uint8_t> best = sb;
    uint64_t bestXid = verifyBlock(sb.data(), sb.size()) ? rd64(sb.data() + O_XID) : 0;
    if (descBlocks & 0x80000000u) {
        c->notes_.push_back("checkpoint descriptor area is a tree, not a linear "
                            "run; only block 0's superblock was considered");
    } else {
        uint32_t scan = std::min<uint32_t>(descBlocks, 10000);
        for (uint32_t i = 0; i < scan; ++i) {
            auto blk = c->br_->read(descBase + i);
            if (rd32(blk.data() + NX_MAGIC_OFF) != NX_MAGIC) continue;
            if ((rd32(blk.data() + O_TYPE) & OBJ_TYPE_MASK) != OBJECT_TYPE_NX_SUPERBLOCK)
                continue;
            if (!verifyBlock(blk.data(), blk.size())) continue;
            uint64_t xid = rd64(blk.data() + O_XID);
            if (xid >= bestXid) { bestXid = xid; best = std::move(blk); }
        }
    }
    if (bestXid == 0)
        c->notes_.push_back("no checksum-clean container superblock found; "
                            "reading with block 0 as-is");

    c->xid_ = bestXid ? bestXid : rd64(best.data() + O_XID);
    c->blockCount_ = rd64(best.data() + NX_BLOCK_COUNT);
    uint64_t incompat = rd64(best.data() + NX_INCOMPAT_FEATURES);
    c->fusion_ = (incompat & NX_INCOMPAT_FUSION) != 0;
    if (c->fusion_ && !tier2)
        c->notes_.push_back("this is a Fusion container: without its second "
                            "(tier-2) device, files stored there cannot be read");
    if (!c->fusion_ && tier2)
        c->notes_.push_back("a second device was supplied but this container is "
                            "not a Fusion set; it was ignored");

    uint64_t omapOid = rd64(best.data() + NX_OMAP_OID);
    c->omap_ = std::make_shared<Omap>(*c->br_, omapOid);
    if (!c->omap_->ok())
        c->notes_.push_back("container object map is unreadable; volumes cannot "
                            "be located from this checkpoint");

    uint32_t maxFs = rd32(best.data() + NX_MAX_FILE_SYSTEMS);
    maxFs = std::min<uint32_t>(maxFs ? maxFs : NX_FS_OID_COUNT, NX_FS_OID_COUNT);
    for (uint32_t i = 0; i < maxFs; ++i) {
        uint64_t oid = rd64(best.data() + NX_FS_OID + i * 8);
        if (!oid) continue;
        auto paddr = c->omap_->lookup(oid, c->xid_);
        if (!paddr) {
            c->notes_.push_back("volume slot " + std::to_string(i) +
                                " could not be located in the object map");
            continue;
        }
        auto vb = c->br_->read(*paddr);
        if (rd32(vb.data() + APFS_MAGIC_OFF) != APFS_MAGIC) {
            c->notes_.push_back("volume slot " + std::to_string(i) +
                                " does not hold a volume superblock");
            continue;
        }
        VolumeInfo v;
        v.index = i;
        v.apsbOid = oid;
        v.apsbPaddr = *paddr;
        v.name = fixedStr(vb.data() + APFS_VOLNAME, 256);
        v.role = roleName(rd16(vb.data() + APFS_ROLE));
        uint64_t flags = rd64(vb.data() + APFS_FS_FLAGS);
        v.encrypted = (flags & APFS_FS_UNENCRYPTED) == 0;
        v.omapOid = rd64(vb.data() + APFS_OMAP_OID);
        v.rootTreeOid = rd64(vb.data() + APFS_ROOT_TREE_OID);
        v.numFiles = rd64(vb.data() + APFS_NUM_FILES);
        v.numDirectories = rd64(vb.data() + APFS_NUM_DIRECTORIES);
        v.lastModTime = static_cast<int64_t>(rd64(vb.data() + APFS_LAST_MOD_TIME));
        v.formattedBy = fixedStr(vb.data() + APFS_FORMATTED_BY, 32);
        c->volumes_.push_back(std::move(v));
    }
    if (c->volumes_.empty() && why)
        *why = "APFS container found, but no volumes could be read from it";
    return c;
}

} // namespace de::apfs
