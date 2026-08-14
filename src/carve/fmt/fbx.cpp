// GHOST RECOVER — fbx signature family (one file per format).
//
// Part of the per-format split: every format family gets its own
// translation unit; shared plumbing (mk, withConfirm, cross-family
// validators) lives in sig_common.h / sig_common.cpp and the registry
// aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "../sig_common.h"

#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace ghost {

i64 vFbx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.byte(off + 20) != 0x00 || s.byte(off + 21) != 0x1A || s.byte(off + 22) != 0x00)
        return -1;
    auto ver = s.read(off + 23, 5);
    if (ver.size() < 5 || ver[0] < '7' || ver[0] > '8' || ver[1] != '.' || ver[2] < '0' || ver[2] > '9')
        return -1;
    i64 total = s.le32(off + 28);
    if (total < 28 || total > max) return -1;
    return total;
}void registerFmt_fbx(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("FBX", "fbx", "misc", S("Kaydara FBX Binary"), 2*GB, SizeMode::Header, vFbx));
}

}  // namespace ghost
