#include "raid/raid.h"
#include <algorithm>
#include <cstring>

namespace de::raid {

const char* levelName(Level l) {
    switch (l) {
        case Level::Concat: return "Concatenated (JBOD/span)";
        case Level::Stripe: return "RAID 0 (striped)";
        case Level::Mirror: return "RAID 1 (mirrored)";
    }
    return "unknown";
}

namespace {

std::string humanSize(uint64_t bytes) {
    char buf[64];
    if (bytes >= (1ull << 40))
        std::snprintf(buf, sizeof buf, "%.2f TB", bytes / 1e12);
    else if (bytes >= (1ull << 30))
        std::snprintf(buf, sizeof buf, "%.2f GB", bytes / 1e9);
    else
        std::snprintf(buf, sizeof buf, "%.2f MB", bytes / 1e6);
    return buf;
}

} // namespace

uint64_t Layout::logicalSize() const {
    uint64_t size = rawLogicalSize();
    return sizeLimitBytes && sizeLimitBytes < size ? sizeLimitBytes : size;
}

uint64_t Layout::rawLogicalSize() const {
    if (members.empty()) return 0;
    switch (level) {
        case Level::Concat: {
            uint64_t total = 0;
            for (const auto& m : members) total += m.dataLength();
            return total;
        }
        case Level::Stripe: {
            // A stripe set can only use as much of each member as its smallest
            // member has; the tail of a larger disk is unused.
            uint64_t smallest = UINT64_MAX;
            for (const auto& m : members) smallest = std::min(smallest, m.dataLength());
            if (smallest == UINT64_MAX) return 0;
            // Round down to a whole stripe so no read straddles the end.
            if (stripeBytes) smallest -= smallest % stripeBytes;
            return smallest * members.size();
        }
        case Level::Mirror: {
            uint64_t smallest = UINT64_MAX;
            for (const auto& m : members) smallest = std::min(smallest, m.dataLength());
            return smallest == UINT64_MAX ? 0 : smallest;
        }
    }
    return 0;
}

std::string Layout::describe() const {
    std::string s = levelName(level);
    s += ", " + std::to_string(members.size()) + " member";
    if (members.size() != 1) s += "s";
    if (level == Level::Stripe)
        s += ", " + std::to_string(stripeBytes / 1024) + " KiB stripe";
    s += ", " + humanSize(logicalSize()) + " logical";
    if (!origin.empty()) s += " [" + origin + "]";
    return s;
}

RaidSource::RaidSource(Layout layout)
    : layout_(std::move(layout)), memberErrors_(layout_.members.size(), 0) {
    size_ = layout_.logicalSize();
    name_ = levelName(layout_.level);
    name_ += " set of " + std::to_string(layout_.members.size());
}

size_t RaidSource::readAt(uint64_t off, void* buf, size_t len) {
    if (off >= size_) return 0;
    if (off + len > size_) len = static_cast<size_t>(size_ - off);
    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < len) {
        size_t n = readRun(off + done, out + done, len - done);
        if (n == 0) break;
        done += n;
    }
    return done;
}

size_t RaidSource::readRun(uint64_t off, uint8_t* out, size_t len) {
    const size_t n = layout_.members.size();
    if (n == 0) return 0;

    size_t memberIdx = 0;
    uint64_t memberOff = 0;
    size_t run = len;

    switch (layout_.level) {
        case Level::Concat: {
            uint64_t base = 0;
            for (size_t i = 0; i < n; ++i) {
                uint64_t mlen = layout_.members[i].dataLength();
                if (off < base + mlen) {
                    memberIdx = i;
                    memberOff = off - base;
                    run = static_cast<size_t>(std::min<uint64_t>(len, mlen - memberOff));
                    break;
                }
                base += mlen;
                if (i == n - 1) return 0; // past the end
            }
            break;
        }
        case Level::Stripe: {
            const uint64_t stripe = layout_.stripeBytes;
            if (stripe == 0) return 0;
            uint64_t stripeNo = off / stripe;
            uint64_t inStripe = off % stripe;
            memberIdx = static_cast<size_t>(stripeNo % n);
            memberOff = (stripeNo / n) * stripe + inStripe;
            // Never read across a stripe boundary in one go: the next byte
            // lives on a different disk.
            run = static_cast<size_t>(std::min<uint64_t>(len, stripe - inStripe));
            break;
        }
        case Level::Mirror: {
            memberIdx = 0;
            memberOff = off;
            break;
        }
    }

    const Member& m = layout_.members[memberIdx];
    if (!m.src) return 0;
    size_t got = m.src->readAt(m.offset + memberOff, out, run);
    if (got == run) return got;

    if (layout_.level == Level::Mirror) {
        // The whole point of a mirror: if one disk cannot give us these bytes,
        // ask the others. This is what makes a mirrored set with one dying
        // drive fully recoverable.
        for (size_t i = 1; i < n; ++i) {
            const Member& alt = layout_.members[i];
            if (!alt.src) continue;
            size_t g2 = alt.src->readAt(alt.offset + memberOff, out, run);
            if (g2 > got) {
                {
                    std::lock_guard<std::mutex> lk(errMutex_);
                    memberErrors_[0] += run - got;
                }
                return g2;
            }
        }
    }
    if (got < run) {
        std::lock_guard<std::mutex> lk(errMutex_);
        memberErrors_[memberIdx] += run - got;
        // Zero-fill the unreadable tail so a bad sector costs the caller that
        // sector, not the rest of the file.
        std::memset(out + got, 0, run - got);
    }
    return run;
}

std::vector<std::string> RaidSource::readErrors() const {
    std::lock_guard<std::mutex> lk(errMutex_);
    std::vector<std::string> out;
    for (size_t i = 0; i < memberErrors_.size(); ++i) {
        if (!memberErrors_[i]) continue;
        std::string label = layout_.members[i].label.empty()
                                ? ("member " + std::to_string(i + 1))
                                : layout_.members[i].label;
        out.push_back(label + ": " + humanSize(memberErrors_[i]) +
                      " could not be read (filled with zeros)");
    }
    return out;
}

std::shared_ptr<ImageSource> assemble(const Layout& layout) {
    if (layout.members.empty()) return nullptr;
    if (layout.level == Level::Stripe &&
        (layout.stripeBytes == 0 || (layout.stripeBytes & (layout.stripeBytes - 1))))
        return nullptr;
    for (const auto& m : layout.members)
        if (!m.src) return nullptr;
    return std::make_shared<RaidSource>(layout);
}

} // namespace de::raid
