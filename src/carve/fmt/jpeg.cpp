// GHOST RECOVER — jpeg signature family (one file per format).
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

i64 vJpeg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 2;
    int segments = 0;
    bool sawSOF = false;
    // "Data after EOI": files that were edited or repaired in place can carry
    // a raw continuation of the entropy stream past an unescaped EOI. The
    // later EOI is only trusted as the real end when the whole span between
    // the two is well-formed entropy data — every FF stuffed as FF 00 / FF FF
    // or a restart marker, with no silent run longer than 1 MiB (zeros and
    // file-system gaps are not entropy data). Any other unescaped FF (a gap,
    // a new SOI, a segment marker) ends the scan at the first EOI, so a real
    // file followed by unrelated bytes still carves exactly as before.
    const i64 kTailMax = 64 * 1024 * 1024;
    const i64 kNoFFRun = 1024 * 1024;
    auto eoiEnd = [&](i64 eoiPos) -> i64 {
        i64 end = eoiPos + 2, last = end, j = end, lastFF = end;
        while (j + 1 < off + max && j - end < kTailMax) {
            if (s.byte(j) != 0xFF) {
                j++;
                if (j - lastFF > kNoFFRun) break;
                continue;
            }
            lastFF = j;
            u8 m = s.byte(j + 1);
            if (m == 0x00 || m == 0xFF || (m >= 0xD0 && m <= 0xD7)) { j += 2; continue; }
            if (m == 0xD9) { last = j + 2; j += 2; continue; }
            break;
        }
        return last;
    };
    // A start-of-frame header is the only reliable anchor for the size of a
    // JPEG: the compressed data is bounded by the uncompressed image mass,
    // W x H pixels x ~2 bytes. Everything the walk does must stay inside a
    // generous envelope of that mass, or the walk is following an FF xx
    // pattern inside unrelated data (zip/gzip/xz payloads are full of them)
    // and would run to the first coincidental EOI — previously a few MB of
    // junk per false hit, masking whatever was stored after it.
    i64 sofLimit = 0;
    auto markerOk = [](u8 m) {
        if (m == 0x01 || m == 0xC4 || m == 0xD8 || m == 0xD9 || m == 0xDA ||
            m == 0xDB || m == 0xDD || m == 0xFE) return true;
        if (m >= 0xC0 && m <= 0xCF) return true;       // SOF0..SOF15
        if (m >= 0xD0 && m <= 0xD7) return true;       // restart
        if (m >= 0xE0 && m <= 0xEF) return true;       // APPn
        return false;
    };
    while (p + 4 <= off + max && segments < 65536) {
        if (sofLimit && p - off > sofLimit) return -1;
        if (s.byte(p) != 0xFF) {
            // Resync: entropy-coded data can contain stuffed bytes.
            i64 q = p;
            while (q < off + max && s.byte(q) != 0xFF) q++;
            if (q >= off + max) break;
            p = q;
        }
        u8 marker = s.byte(p + 1);
        if (marker == 0xFF) { p++; continue; }
        if (marker == 0xD9) return eoiEnd(p) - off;            // EOI
        if (marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) { p += 2; continue; }
        if (!markerOk(marker)) {
            // A byte that is not a real marker at all: random data that
            // merely contains FF xx. Do not trust segment lengths here —
            // step to the next candidate marker byte.
            p++;
            // 128 KiB of marker scanning without any SOF: random data that
            // merely contains FF D8 FF (or a payload full of FF xx). 512 KiB
            // cost ~125 GB of window reads on a flood of false candidates —
            // the exact case that hangs a 1 GiB box for minutes. Real JPEGs
            // reach SOF within the first few KiB.
            if (p - off > 128 * 1024 && !sawSOF) return -1;
            continue;
        }
        u16 len = s.be16(p + 2);
        if (len < 2) return -1;
        segments++;
        if (marker >= 0xC0 && marker <= 0xCF && marker != 0xC4 && marker != 0xC8 && marker != 0xCC) {
            // A start-of-frame marker is only credible with the full frame
            // header being sane: 8-bit precision, 1-4 components whose ids,
            // sampling factors and quantisation tables all fall in range.
            // Compressed payloads (zip/gzip/xz) contain countless FF C0
            // coincidences; without this gate a false SOF with a mid-sized
            // fake W x H sails past every mass-based bound.
            auto d = s.read(p + 4, len);
            if (d.size() >= (size_t)len && len >= 7) {
                u8 prec = d[0];
                u32 h = (u32)d[2] << 8 | d[3];
                u32 w = (u32)d[4] << 8 | d[5];
                u8 n = d[6];
                bool sane = prec == 8 && n >= 1 && n <= 4 && (size_t)len == 8 + 3u * n &&
                            w > 0 && w <= 20000 && h > 0 && h <= 20000;
                for (int i = 0; sane && i < n; i++) {
                    u8 id = d[7 + 3 * i];
                    u8 samp = d[8 + 3 * i];
                    u8 qt = d[9 + 3 * i];
                    if (id > 4 || (samp >> 4) > 4 || (samp & 0x0F) > 4 || qt > 3) sane = false;
                }
                if (sane) {
                    sawSOF = true;
                    sofLimit = (i64)w * h * 2 + 512 * 1024;
                }
            }
        }
        if (marker == 0xDA) {
            // Start of scan: entropy data follows until the next real marker.
            i64 q = p + 2 + len;
            while (q + 1 < off + max) {
                if (sofLimit && q - p > sofLimit) { p = off + max; break; }
                if (q - p > 64 * 1024 * 1024) { p = off + max; break; }
                if (s.byte(q) == 0xFF) {
                    u8 m = s.byte(q + 1);
                    if (m == 0xD9) return eoiEnd(q) - off;
                    if (m != 0x00 && !(m >= 0xD0 && m <= 0xD7)) { p = q; break; }
                }
                q++;
            }
            if (q + 1 >= off + max) break;
            continue;
        }
        p += 2 + len;
        if (sofLimit && p - off > sofLimit) return -1;
    }
    return segments >= 2 && sawSOF ? 0 : -1;   // structurally plausible, length unknown
}void registerFmt_jpeg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("JPEG", "jpg", "image", B({0xFF,0xD8,0xFF}), 512*MB, SizeMode::Container, vJpeg);
      c.min_size = 128; c.footer = B({0xFF,0xD9}); c.priority = 10; add(c); }
}

}  // namespace ghost
