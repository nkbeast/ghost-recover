// GHOST RECOVER — mod signature family (one file per format).
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

i64 vS3m(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 orders = s.le16(off + 32);
    u16 instruments = s.le16(off + 34);
    u16 patterns = s.le16(off + 36);
    u16 flags = s.le16(off + 38);
    u16 channels = (u16)((flags & 0x0F) + 1);
    if (orders > 256 || instruments > 255 || patterns > 255 || channels < 1 || channels > 64)
        return -1;
    i64 p = off + 96 + orders + 2 * (i64)instruments + 2 * (i64)patterns +
            (i64)instruments * 0x50;
    for (u16 i = 0; i < patterns; i++) {
        if (p + 64 * (i64)channels + 2 > off + max) return -1;
        u16 size = s.le16(p + 64 * (i64)channels);
        if (p + 64 * (i64)channels + 2 + size > off + max) return -1;
        p += 64 * (i64)channels + 2 + size;
    }
    i64 sampleHeaders = p;
    p += (i64)instruments * 0x50;
    for (u16 i = 0; i < instruments; i++) {
        u32 len = s.le32(sampleHeaders + (i64)i * 0x50 + 0x20);
        if (p + len > off + max) return -1;
        p += len;
    }
    return p - off;
}i64 vXm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.byte(off + 37) != 0x1A) return -1;
    u16 version = s.le16(off + 60);
    if (version < 0x0102 || version > 0x0104) return -1;
    u32 headerSize = s.le32(off + 64);
    u16 songLen = s.le16(off + 68);
    u16 channels = s.le16(off + 72);
    u16 patterns = s.le16(off + 74);
    u16 instruments = s.le16(off + 76);
    if (headerSize < (u32)(24 + songLen) || headerSize > 4096) return -1;
    if (songLen < 1 || songLen > 256 || channels < 1 || channels > 64) return -1;
    if (patterns > 256 || instruments > 128) return -1;
    i64 p = off + 60 + headerSize;
    for (u16 i = 0; i < patterns; i++) {
        if (p + 9 > off + max) return -1;
        u32 len = s.le32(p);
        u16 rows = s.le16(p + 5);
        u16 packed = s.le16(p + 7);
        if (len < 9 || len > 4096) return -1;
        if (rows < 1 || rows > 256) return -1;
        if (p + (i64)len + packed > off + max) return -1;
        p += (i64)len + packed;
    }
    // Instrument section: a 29-byte fixed header (size, 22-byte name, type,
    // u16 sample count) then numSamples 40-byte sample headers; the size
    // field spans exactly 29 + 40*numSamples. All sample data follows after
    // every instrument header, in order.
    struct Sample { i64 len; };
    std::vector<Sample> samples;
    for (u16 i = 0; i < instruments; i++) {
        if (p + 29 > off + max) return -1;
        u32 isize = s.le32(p);
        if (isize < 29) return -1;
        u32 rest = isize - 29;
        if (rest % 40 != 0) return -1;
        u32 numSamples = rest / 40;
        if (numSamples > 512) return -1;
        u16 ns = s.le16(p + 27);
        if (ns != numSamples) return -1;
        if (p + (i64)isize > off + max) return -1;
        for (u32 j = 0; j < numSamples; j++) {
            u32 len = s.le32(p + 29 + (i64)j * 40);
            if (len > 16 * 1024 * 1024) return -1;
            samples.push_back({len});
        }
        p += (i64)isize;
    }
    for (auto& smp : samples) {
        if (p + smp.len > off + max) return -1;
        p += smp.len;
    }
    return p - off;
}void registerFmt_mod(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("MOD_IT", "it", "audio", S("IMPM"), 128*MB));
    { auto c = mk("MOD_S3M", "s3m", "audio", S("SCRM"), 128*MB, SizeMode::Header, vS3m);
      c.magic_offset = 44; add(c); }
    add(mk("MOD_XM", "xm", "audio", S("Extended Module:"), 128*MB, SizeMode::Header, vXm));
}

}  // namespace ghost
