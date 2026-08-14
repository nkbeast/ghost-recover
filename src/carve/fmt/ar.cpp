// GHOST RECOVER — ar signature family (one file per format).
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

i64 vAr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 8;
    int members = 0;
    while (p + 60 <= off + max && members < 100000) {
        auto h = s.read(p, 60);
        if (h.size() < 60 || h[58] != 0x60 || h[59] != 0x0A) break;
        u64 size = 0;
        for (int i = 48; i < 58; i++) {
            u8 c = h[i];
            if (c < '0' || c > '9') break;
            size = size * 10 + (u64)(c - '0');
        }
        p += 60 + (i64)size + ((size & 1) ? 1 : 0);
        members++;
    }
    if (members < 1) return -1;
    return p - off;
}void registerFmt_ar(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("DEB", "deb", "archive", S("!<arch>\n"), 2*GB, SizeMode::Container, vAr);
      withConfirm(c, S("debian-binary"), -1, 128); c.priority = 20; add(c); }
    { auto c = mk("AR", "a", "archive", S("!<arch>\n"), 2*GB, SizeMode::Container, vAr);
      c.min_size = 68; add(c); }
}

}  // namespace ghost
