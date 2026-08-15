// GHOST RECOVER — gzip signature family (one file per format).
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

i64 vGzip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
#ifdef GHOST_HAVE_ZLIB
    const i64 kInBudget = 1 * 1024LL * 1024 * 1024;    // compressed bytes per member
    const i64 kOutBudget = 32 * 1024LL * 1024 * 1024;  // decompressed cap
    i64 pos = off;
    i64 outTotal = 0;
    std::vector<u8> buf;
    for (int member = 0; member < 64; member++) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15 + 16) != Z_OK) return -1;
        int rc = Z_OK;
        u8 out[64 * 1024];
        while (rc != Z_STREAM_END) {
            if (zs.avail_in == 0) {
                if (pos - off >= max || (i64)zs.total_in >= kInBudget) {
                    rc = Z_BUF_ERROR;
                    break;
                }
                i64 want = std::min<i64>(
                    64 * 1024,
                    std::min(max - (pos - off), kInBudget - (i64)zs.total_in));
                buf = s.read(pos, want);
                if (buf.empty()) {
                    // Input exhausted: one last inflate call lets zlib report
                    // a stream that ended flush against the read boundary.
                    zs.next_in = nullptr;
                    zs.avail_in = 0;
                    zs.next_out = out;
                    zs.avail_out = sizeof(out);
                    rc = inflate(&zs, Z_NO_FLUSH);
                    break;
                }
                zs.next_in = buf.data();
                zs.avail_in = (uInt)buf.size();
            }
            zs.next_out = out;
            zs.avail_out = sizeof(out);
            rc = inflate(&zs, Z_NO_FLUSH);
            outTotal += (i64)(sizeof(out) - zs.avail_out);
            if (outTotal > kOutBudget) { rc = Z_BUF_ERROR; break; }
            if (rc == Z_STREAM_ERROR || rc == Z_MEM_ERROR || rc == Z_DATA_ERROR) break;
        }
        i64 consumed = (i64)zs.total_in;
        bool ok = (rc == Z_STREAM_END);
        inflateEnd(&zs);
        if (!ok) return -1;
        pos += consumed;                               // trailer included
        if (pos - off > max) return -1;
        auto nx = s.read(pos, 2);                      // concatenated member?
        if (nx.size() < 2 || nx[0] != 0x1F || nx[1] != 0x8B) return pos - off;
    }
    return pos - off;
#else
    (void)s; (void)off; (void)max;
    return -2;                       // zlib not compiled in
#endif
}void registerFmt_gzip(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("GZIP", "gz", "archive", B({0x1F,0x8B,0x08}), 8*GB, SizeMode::Heuristic, vGzip);
      c.min_size = 20; add(c); }
}

}  // namespace ghost
