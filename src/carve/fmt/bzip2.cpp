// GHOST RECOVER — bzip2 signature family (one file per format).
//
// Part of the per-format split: every format family gets its own
// translation unit; shared plumbing (mk, withConfirm, cross-family
// validators) lives in sig_common.h / sig_common.cpp and the registry
// aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "../sig_common.h"

#ifdef GHOST_HAVE_BZIP2
#include <bzlib.h>
#endif


#include <algorithm>
#include <cstring>
#include <string>
#include <vector>

namespace ghost {

i64 vBzip2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
#ifdef GHOST_HAVE_BZIP2
    const i64 kInBudget = 1 * 1024LL * 1024 * 1024;
    const i64 kOutBudget = 32 * 1024LL * 1024 * 1024;
    auto h = s.read(off, 4);
    if (h.size() < 4 || h[0] != 'B' || h[1] != 'Z' || h[2] != 'h'
        || h[3] < '1' || h[3] > '9') return -1;
    bz_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (BZ2_bzDecompressInit(&zs, 0, 0) != BZ_OK) return -1;
    auto bzIn = [](bz_stream* z) { return (i64)z->total_in_hi32 << 32 | (u32)z->total_in_lo32; };
    i64 fed = 0;                 // bytes handed to the decompressor so far
    i64 outTotal = 0;
    int rc = BZ_OK;
    u8 out[64 * 1024];
    std::vector<u8> buf;
    while (rc != BZ_STREAM_END) {
        if (zs.avail_in == 0) {
            if (fed >= max || bzIn(&zs) >= kInBudget) {
                rc = BZ_UNEXPECTED_EOF;
                break;
            }
            i64 want = std::min<i64>(
                64 * 1024,
                std::min(max - fed, kInBudget - bzIn(&zs)));
            buf = s.read(off + fed, want);
            if (buf.empty()) {
                zs.next_in = nullptr;
                zs.avail_in = 0;
                zs.next_out = reinterpret_cast<char*>(out);
                zs.avail_out = sizeof(out);
                rc = BZ2_bzDecompress(&zs);
                break;
            }
            zs.next_in = reinterpret_cast<char*>(buf.data());
            zs.avail_in = (unsigned)buf.size();
            fed += (i64)buf.size();
        }
        zs.next_out = reinterpret_cast<char*>(out);
        zs.avail_out = sizeof(out);
        rc = BZ2_bzDecompress(&zs);
        outTotal += (i64)(sizeof(out) - zs.avail_out);
        if (outTotal > kOutBudget) { rc = BZ_UNEXPECTED_EOF; break; }
        if (rc != BZ_OK && rc != BZ_STREAM_END) break;
    }
    i64 consumed = bzIn(&zs);
    bool ok = (rc == BZ_STREAM_END);
    BZ2_bzDecompressEnd(&zs);
    if (!ok || consumed <= 0) return -1;
    return consumed;                             // EOS + CRC included
#else
    (void)s; (void)off; (void)max;
    return -2;                       // bzip2 library not compiled in
#endif
}void registerFmt_bzip2(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("BZIP2", "bz2", "archive", S("BZh"), 8*GB, SizeMode::Heuristic, vBzip2);
      c.min_size = 20; add(c); }
}

}  // namespace ghost
