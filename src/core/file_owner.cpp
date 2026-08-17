#include "core/file_owner.h"

#include <cstdlib>
#include <cerrno>
#include <unistd.h>
#include <sys/types.h>

namespace de {

namespace {

// Parse a SUDO_* id. Rejects anything that is not a clean decimal number so a
// malformed environment cannot turn into a chown to an arbitrary id.
bool envId(const char* name, unsigned long& out) {
    const char* v = std::getenv(name);
    if (!v || !*v) return false;
    char* end = nullptr;
    errno = 0;
    unsigned long id = std::strtoul(v, &end, 10);
    if (errno || !end || *end) return false;
    out = id;
    return true;
}

} // namespace

bool applyInvokingOwner(const std::string& path) {
    unsigned long uid = 0, gid = 0;
    if (!envId("SUDO_UID", uid) || !envId("SUDO_GID", gid))
        return true;   // not under sudo; the file already belongs to the caller
    if (uid == geteuid() && gid == getegid()) return true;

    // Not AT_SYMLINK_NOFOLLOW's equivalent by accident: lchown so a name we
    // wrote is retargeted itself, never something it points at.
    return lchown(path.c_str(), static_cast<uid_t>(uid),
                  static_cast<gid_t>(gid)) == 0;
}

} // namespace de
