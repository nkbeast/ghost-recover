// GHOST RECOVER — swf signature family (one file per format).
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

i64 vSwf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 9);
    if (b.size() < 9) return -1;
    bool fws = b[0] == 'F' && b[1] == 'W' && b[2] == 'S';
    bool cws = b[0] == 'C' && b[1] == 'W' && b[2] == 'S';
    if (!fws && !cws) return -1;
    u32 len = (u32)b[4] | (u32)b[5] << 8 | (u32)b[6] << 16 | (u32)b[7] << 24;
    if (len < 8 || (u64)len > (u64)max + 1) return -1;
#ifdef GHOST_HAVE_ZLIB
    if (cws && len > 8) {
        // CWS: the length field is the *uncompressed* size; inflate the body
        // and require the output to match it exactly. A stream that inflates
        // to the declared size and ends cleanly is a real SWF.
        const i64 kOutBudget = 512LL * 1024 * 1024;
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        if (inflateInit(&zs) != Z_OK) return -1;
        const i64 kInBudget2 = 512LL * 1024 * 1024;
        std::vector<u8> in = s.read(off + 8, std::min<i64>(max - 8, kInBudget2));
        if (in.empty()) return -1;
        i64 outTotal = 0;
        int rc = Z_OK;
        u8 out[64 * 1024];
        bool ok = false;
        while (rc == Z_OK && (i64)zs.total_in < (i64)in.size()) {
            zs.next_in = in.data() + zs.total_in;
            zs.avail_in = (uInt)(in.size() - (size_t)zs.total_in);
            zs.next_out = out;
            zs.avail_out = sizeof(out);
            rc = inflate(&zs, Z_NO_FLUSH);
            i64 got = (i64)(sizeof(out) - zs.avail_out);
            outTotal += got;
            if (outTotal > kOutBudget) break;
            if (rc == Z_STREAM_END) {
                ok = outTotal == (i64)len - 8;
                break;
            }
            if (got == 0 && rc == Z_OK) break;   // no progress: corrupt input
        }
        inflateEnd(&zs);
        if (rc != Z_STREAM_END) return -1;
        if (!ok) return -1;
        // The u32 length field is the *uncompressed* size. The bytes stored on
        // disk are the compressed stream, so the file's real length is the
        // 8-byte header plus however many compressed bytes zlib consumed.
        return 8 + (i64)zs.total_in;
    }
#else
    if (cws) return -1;
#endif
    if (!fws) return -1;
    // FWS: the length field is only a hint — random data can forge it and
    // mask every file that follows. Walk the RECT field and the tag stream
    // to the End tag; the chain end must agree with the declared length.
    i64 nbits = b[8] >> 3;
    if (nbits > 31) return -1;
    i64 p = off + 8 + 1 + ((nbits * 4 + 7) / 8);
    if (p + 2 > off + max) return -1;
    i64 chainEnd = -1;
    int guard = 0;
    while (p + 2 <= off + max && guard++ < 100000) {
        u16 t = s.le16(p);
        int code = (t >> 6) & 0x3FF;
        i64 tl = t & 0x3F;
        i64 hdr = 2;
        if (tl == 0x3F) {
            if (p + 6 > off + max) return -1;
            tl = s.le32(p + 2);
            hdr = 6;
        }
        if (code == 0 && tl == 0) { chainEnd = p + hdr - off; break; }
        if (tl < 0 || p + hdr + tl > off + max) return -1;
        p += hdr + tl;
    }
    if (chainEnd < 0) return -1;
    i64 diff = chainEnd > (i64)len ? chainEnd - (i64)len : (i64)len - chainEnd;
    if (diff > 64) return -1;
    return chainEnd;
}i64 vZws(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 16) return -1;
    u32 compLen = s.le32(off + 4);
    u32 uncompLen = s.le32(off + 8);
    if (compLen < 5 || compLen > 512 * MB || uncompLen < 1) return -1;
    i64 size = 12 + (i64)compLen;
    if (size > max) return -1;
    return size;
}void registerFmt_swf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("SWF", "swf", "video", S("FWS"), 256*MB, SizeMode::Header, vSwf));
    add(mk("SWF_ZLIB", "swf", "video", S("CWS"), 256*MB, SizeMode::Header, vSwf));
    { auto c = mk("SWF_LZMA", "swf", "video", S("ZWS"), 256*MB, SizeMode::Header, vZws);
      c.min_size = 32; add(c); }
}

}  // namespace ghost
