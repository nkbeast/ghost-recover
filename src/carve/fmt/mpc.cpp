// GHOST RECOVER — mpc signature family (one file per format).
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

i64 vMpc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 16) return -1;
    if (s.byte(off) == 'M' && s.byte(off + 1) == 'P' && s.byte(off + 2) == 'C' &&
        s.byte(off + 3) == 'K') {
        // SV8: chain of "MPCK" packets; each has a BE u16 key and a BE
        // varint size (covering the 6-byte packet header). The stream header
        // (SH, 0x5348) comes first; the stream end packet (ST, 0x5354)
        // terminates the file.
        i64 p = off;
        for (int guard = 0; guard < 100000; guard++) {
            auto h = s.read(p, 8);
            if (h.size() < 8) return -1;
            if (h[0] != 'M' || h[1] != 'P' || h[2] != 'C' || h[3] != 'K') return -1;
            u16 key = (u16)h[4] << 8 | h[5];
            if (p == off && key != 0x5348) return -1;
            i64 q = p + 6;
            u64 size = 0;
            int shift = 0;
            bool done = false;
            while (q < off + max && shift < 56) {
                u8 b = s.byte(q++);
                size |= (u64)(b & 0x7F) << shift;
                if (!(b & 0x80)) { done = true; break; }
                shift += 7;
            }
            if (!done || shift >= 56) return -1;
            if (size < 6) return -1;
            if (p + (i64)size > off + max) return -1;
            if (key == 0x5354) return p + (i64)size - off;
            p += (i64)size;
        }
        return -1;
    }
    if (s.byte(off + 3) != 0x07) return -1;
    // SV7: the header carries the frame count, not a file size.
    return 0;
}void registerFmt_mpc(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MPC", "mpc", "audio", S("MPCK"), 512*MB, SizeMode::Header, vMpc);
      c.min_size = 32; add(c); }
    { auto c = mk("MPC_SV7", "mpc", "audio", S("MP+"), 512*MB, SizeMode::Header, vMpc);
      c.min_size = 32; add(c); }
}

}  // namespace ghost
