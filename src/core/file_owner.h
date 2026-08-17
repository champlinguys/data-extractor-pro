#pragma once
#include <string>

namespace de {

// Hand an exported file or directory back to the user who invoked sudo.
//
// Raw device reads need root, so every real recovery run is `sudo de-cli ...`,
// and anything we create lands owned by root:root. The customer then cannot
// read their own recovery without another sudo - so we undo the escalation on
// the way out, using SUDO_UID/SUDO_GID to find who we were before.
//
// A no-op when not running under sudo (nothing to hand back) and when already
// running as the target user. Returns false only if the chown itself failed.
bool applyInvokingOwner(const std::string& path);

} // namespace de
