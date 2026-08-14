// GHOST RECOVER — wasm signature family (one file per format).
//
// Part of the per-format split: every format family gets its own
// translation unit; shared plumbing (mk, withConfirm, cross-family
// validators) lives in sig_common.h / sig_common.cpp and the registry
// aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "../sig_common.h"

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif


#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace ghost {

i64 vWasm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 4) != 1) return -1;
    i64 p = 8;
    int sections = 0;
    while (p < max && sections < 4096) {
        u8 id = s.byte(off + p);
        if (id > 13) break;
        // LEB128 section length — peek without consuming so a zero-length
        // section (padding after the last real section) does not inflate the
        // carved size.
        i64 leb = p + 1;
        u64 len = 0;
        int shift = 0;
        bool done = false;
        while (leb < max && shift < 35) {
            u8 b = s.byte(off + leb++);
            len |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) { done = true; break; }
            shift += 7;
        }
        if (!done || shift >= 35) break;      // unterminated LEB -> not ours
        if (len == 0) break;                  // empty section: stop, not run
        p = leb;
        if (p - 8 + (i64)len > max) break;
        p += (i64)len;
        sections++;
    }
    if (sections < 1) return -1;
    return p;
}void registerFmt_wasm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("WASM", "wasm", "executable", B({0x00,'a','s','m'}), 512*MB,
                  SizeMode::Container, vWasm); c.min_size = 8; add(c); }
}

}  // namespace ghost
