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
    // The LevelDB footer (48 bytes) ends the file: metaindex handle (two
    // varints), index handle (two varints), padding to 40 bytes, then the
    // 8-byte magic which is the signature. The index block ends where the
    // footer begins, so the file start is derived from the index handle.
    if (off - 40 < 0) return -1;
    auto pad = s.read(off - 40, 40);
    if (pad.size() < 40) return -1;
    i64 pos = 0;
    u64 vals[4];
    for (int i = 0; i < 4; i++) {
        u64 v = 0;
        int shift = 0;
        bool done = false;
        while (pos < 40 && shift < 64) {
            u8 b = pad[pos++];
            v |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) { done = true; break; }
            shift += 7;
        }
        if (!done || shift >= 64) return -1;
        vals[i] = v;
    }
    const u64 idxOff = vals[2], idxSize = vals[3];
    if (idxSize == 0 || idxOff > (1ull << 40)) return -1;
    const u64 footerRel = idxOff + idxSize;
    const i64 fileStart = (off - 40) - (i64)footerRel;
    if (fileStart < 0 || fileStart >= off) return -1;
    const i64 size = off + 8 - fileStart;          // file ends after the magic
    if (size > max) return -1;
    s.setBackscan(off - fileStart);
    return 8;   // bytes after the signature; the engine adds the backscan
}void registerFmt_leveldb(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("LevelDB", "ldb", "database", B({0x57,0xFB,0x80,0x8B,0x24,0x75,0x47,0xDB}), 2*GB, SizeMode::Header, vLevelDb));
}

}  // namespace ghost
