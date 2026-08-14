// GHOST RECOVER — mat signature family (one file per format).
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

i64 vMat(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 128);
    if (b.size() < 128) return -1;
    if (std::memcmp(b.data(), "MATLAB 5.0 MAT-file", 19) != 0) return -1;
    bool le;
    if (b[126] == 'I' && b[127] == 'M') le = true;       // 'IM' = little endian
    else if (b[126] == 'M' && b[127] == 'I') le = false; // 'MI' = big endian
    else return -1;
    u16 ver = le ? (u16)(b[124] | (u16)b[125] << 8) : (u16)(b[124] << 8 | b[125]);
    if (ver != 0x0100) return -1;
    // Subsystem offset (header bytes 116..123) should be zero for plain files.
    u64 subsys = 0;
    if (le)
        for (int k = 7; k >= 0; k--) subsys = subsys << 8 | b[116 + k];
    else
        for (int k = 0; k < 8; k++) subsys = subsys << 8 | b[116 + k];
    if (subsys != 0) return -1;
    auto rd32 = [&](i64 p) -> u32 {
        auto v = s.read(off + p, 4);
        if (v.size() < 4) return 0;
        return le ? ((u32)v[3] << 24 | (u32)v[2] << 16 | (u32)v[1] << 8 | v[0])
                  : ((u32)v[0] << 24 | (u32)v[1] << 16 | (u32)v[2] << 8 | v[3]);
    };
    // Walk the chain of top-level data elements. A miMATRIX/miCOMPRESSED
    // element uses a 16-byte tag whose size field sits at +4; other types an
    // 8-byte tag (size at +4) or a small 4-byte tag (size in bits 8..15
    // when the type bits alone look like a small element).
    i64 p = 128;
    int els = 0;
    while (p + 4 <= max && els < 100000) {
        u32 t = rd32(p);
        int type = (int)(t & 0xFF);
        if (type == 14 || type == 15) {
            u32 size = rd32(p + 4);
            if (size > (u32)max) return -1;
            // The tag's size field counts the element body from right after
            // the 8-byte tag: for a miCOMPRESSED/miMATRIX element the file
            // ends exactly at p + 8 + size (e.g. scipy's savemat). Stepping
            // 16 bytes skips the trailing 4-byte data-length pair INSIDE the
            // body and over-runs every such file by 8.
            i64 next = p + 8 + (i64)size;
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        u32 word2 = rd32(p + 4);
        int smallSize = (int)((t >> 8) & 0xFF);
        if (type >= 1 && type <= 13 && (t & 0xFF00) != 0 && (t & 0xFF0000) == 0 &&
            (t & 0xFF000000) == 0 && smallSize != 0) {
            i64 next = p + 4 + smallSize;    // small element, no padding
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        if (type >= 1 && type <= 13) {       // 8-byte tag (size at +4)
            i64 next = p + 8 + (i64)word2;
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        break;   // unknown element type: the top-level chain ends here
    }
    if (els < 1) return -1;
    return p - 0;   // p counts from off already
}void registerFmt_mat(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("MAT", "mat", "database", S("MATLAB 5.0 MAT-file"), 8*GB, SizeMode::Header, vMat));
}

}  // namespace ghost
