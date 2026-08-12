#pragma once
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "core/image_source.h"
#include "raid/raid.h"

// Working out how somebody else's RAID was configured.
//
// Two drives out of an enclosure tell you almost nothing on their own: the
// same pair of disks could be a mirror, a stripe with any of a dozen chunk
// sizes, or a plain span - and getting it wrong produces a volume that looks
// almost right and hands back shredded files. So we do two things:
//
//   1. Read whatever the RAID implementation left behind. Apple's software
//      RAID writes a plist-bearing header on each member; SoftRAID (which is
//      what OWC ships with its enclosures) leaves its own signature.
//   2. Verify by reconstruction. Every candidate geometry is assembled and
//      then judged on whether real structures - GPT CRCs, APFS checksummed
//      objects deep in the tree, a directory that actually lists - come out
//      intact. A wrong stripe size fails this immediately, because APFS
//      metadata blocks are scattered across the whole address space.
//
// Verification is what we trust; metadata only decides what to try first.
namespace de::raid {

// What a member's own RAID metadata claims, when it has any.
struct MemberMetadata {
    std::string format;      // "AppleRAID", "SoftRAID", or empty
    std::string setName;
    std::string setUuid;
    std::string memberUuid;
    std::string levelName;   // as written by the RAID implementation
    std::optional<Level> level;
    uint64_t chunkSize = 0;  // stripe size in bytes, if stated
    int memberIndex = -1;    // position in the set
    int memberCount = -1;
    uint64_t sequence = 0;   // higher = more recently updated
    uint64_t dataOffset = 0; // where member data starts, if stated
    std::vector<std::string> notes;
};

// A geometry we tried, with the evidence for it.
struct Candidate {
    Layout layout;
    int score = 0;
    std::string evidence;
    // Set when a filesystem on this geometry was actually mounted and read.
    bool fsVerified = false;
};

struct DetectOptions {
    // Stripe sizes to try, smallest first. Apple's software RAID defaults to
    // 32 KiB, SoftRAID to 128 KiB; the rest are what people pick by hand.
    std::vector<uint64_t> stripeSizes{4096,    8192,    16384,   32768,  65536,
                                      131072,  262144,  524288,  1048576, 2097152};
    // How many cheap-pass candidates get the expensive filesystem check.
    size_t deepCandidates = 8;
    // Cap on member orderings tried, so a big set cannot explode.
    size_t maxPermutations = 24;
};

struct DetectResult {
    bool assembled = false;   // we found a geometry that verifies
    Layout layout;            // the winner
    std::string summary;      // one line for the user
    std::vector<std::string> notes;
    std::vector<Candidate> ranked; // best first, for offering alternatives
    std::vector<MemberMetadata> metadata; // per input device, in input order
    // Devices that are complete, mountable disks on their own - i.e. this is
    // probably not a RAID set at all.
    std::vector<size_t> standalone;
};

// Read a member's RAID metadata, if it has any we recognise.
MemberMetadata readMemberMetadata(ImageSource& dev);

// Work out how these devices go together. Order of `devices` is only a
// starting point; the detector tries the other orderings too.
DetectResult detect(const std::vector<std::shared_ptr<ImageSource>>& devices,
                    const DetectOptions& opt = {});

// Score an assembled disk by how much of it parses as real, checksum-clean
// filesystem structure. Exposed so the CLI can score a hand-specified geometry
// and tell the user whether it holds up. `deep` enables the expensive
// filesystem walk; `evidence` receives a human-readable breakdown.
//
// `fsVerified`, if given, is set when an actual filesystem on the disk was
// mounted and read successfully. That is the only evidence worth trusting: a
// partition table alone lives entirely in the first stripe and looks perfect
// on geometries that are wrong everywhere else.
int scoreAssembled(const std::shared_ptr<ImageSource>& disk, bool deep,
                   std::string* evidence, bool* fsVerified = nullptr);

} // namespace de::raid
