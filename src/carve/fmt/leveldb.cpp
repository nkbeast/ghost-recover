// GHOST RECOVER — leveldb signature family (one file per format).
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

i64 vLevelDb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    const i64 kBlock = 32768;
    i64 p = off + 8;
    for (int blocks = 0; blocks < (1 << 20); blocks++) {
        while (true) {
            if (p + 7 > off + max) return -1;
            u16 len = s.le16(p + 4);
            u8 type = s.byte(p + 6);
            if (type == 0 || len == 0) break;      // zero padding
            if (len > 4096 || p + 7 + len > off + max) return -1;
            p += 7 + len;
        }
        i64 next = off + 8 + ((p - off - 8 + kBlock - 1) / kBlock) * kBlock;
        if (next + 7 > off + max) return next - off;
        if (s.byte(next + 6) == 0) return next - off;
        p = next;
    }
    return -1;
}void registerFmt_leveldb(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("LevelDB", "ldb", "database", B({0x57,0xFB,0x80,0x8B,0x24,0x75,0x47,0xDB}), 2*GB, SizeMode::Header, vLevelDb));
}

}  // namespace ghost
