// GHOST RECOVER — jp2 signature family (one file per format).
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

i64 vJp2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    while (p + 8 <= off + max) {
        u64 size = s.be32(p);
        if (size == 0) return -1;
        auto type = s.read(p + 4, 4);
        if (type.size() < 4) return -1;
        bool stream = std::memcmp(type.data(), "jp2c", 4) == 0 ||
                      std::memcmp(type.data(), "jxlp", 4) == 0 ||
                      std::memcmp(type.data(), "brob", 4) == 0;
        if (size == 1) {                                       // XLBox
            u64 xl = s.be64(p + 8);
            if (xl < 16 || p + (i64)xl > off + max) return -1;
            p += (i64)xl;
        } else {
            if (size < 8 || p + (i64)size > off + max) return -1;
            p += (i64)size;
        }
        if (stream) return p - off;
    }
    return -1;
}void registerFmt_jp2(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("JP2", "jp2", "image", B({0x00,0x00,0x00,0x0C,'j','P',0x20,0x20}), 256*MB, SizeMode::Header, vJp2));
    add(mk("JXL_ISO", "jxl", "image", B({0x00,0x00,0x00,0x0C,'J','X','L',0x20}), 256*MB, SizeMode::Header, vJp2));
}

}  // namespace ghost
