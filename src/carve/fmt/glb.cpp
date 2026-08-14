// GHOST RECOVER — glb signature family (one file per format).
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

i64 vGlb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 20);
    if (b.size() < 12) return -1;
    if (b[0] != 'g' || b[1] != 'l' || b[2] != 'T' || b[3] != 'F') return -1;
    u32 version = (u32)b[4] | (u32)b[5] << 8 | (u32)b[6] << 16 | (u32)b[7] << 24;
    if (version != 2) return -1;
    u64 len = (u64)((u32)b[8] | (u32)b[9] << 8 | (u32)b[10] << 16 | (u32)b[11] << 24);
    if (len < 20 || len > (u64)max) return -1;
    // First chunk must be a JSON chunk and must fit inside the declared file.
    u32 chunkLen = (u32)b[12] | (u32)b[13] << 8 | (u32)b[14] << 16 | (u32)b[15] << 24;
    if ((u64)chunkLen > len - 20) return -1;
    if (b[16] != 'J' || b[17] != 'S' || b[18] != 'O' || b[19] != 'N') return -1;
    // Optional second chunk, if claimed to exist, must be BIN and fit too.
    if (len >= 12 + 8 + 8 + (u64)chunkLen) {
        auto b2 = s.read(off + 20 + chunkLen, 8);
        if (b2.size() == 8) {
            u32 len2 = (u32)b2[0] | (u32)b2[1] << 8 | (u32)b2[2] << 16 | (u32)b2[3] << 24;
            bool bin = b2[4] == 'B' && b2[5] == 'I' && b2[6] == 'N' && b2[7] == 0;
            if (bin && 20 + (u64)chunkLen + 8 + (u64)len2 > len) return -1;
        }
    }
    return (i64)len;
}void registerFmt_glb(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("GLTF_BIN", "glb", "misc", S("glTF"), 2*GB, SizeMode::Header, vGlb));
}

}  // namespace ghost
