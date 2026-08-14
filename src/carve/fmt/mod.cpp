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
    u32 headerSize = s.le32(off + 60);
    u16 orders = s.le16(off + 64);
    u16 instruments = s.le16(off + 66);
    u16 patterns = s.le16(off + 68);
    if (headerSize < (u32)(34 + orders) || headerSize > 4096) return -1;
    if (instruments > 128 || patterns > 256) return -1;
    i64 p = off + 60 + headerSize;
    for (u16 i = 0; i < patterns; i++) {
        if (p + 10 > off + max) return -1;
        u32 rows = s.le32(p + 4);
        u32 packed = s.le32(p + 8);
        if (rows < 1 || rows > 256 || packed > (u32)(off + max - p - 10)) return -1;
        p += 10 + packed;
    }
    // Instrument section: fixed prefix then sample headers; the sample data
    // chunks follow in instrument order after every header.
    struct Sample { i64 len; };
    std::vector<Sample> samples;
    for (u16 i = 0; i < instruments; i++) {
        if (p + 33 > off + max) return -1;
        u32 isize = s.le32(p);
        u16 numSamples = s.le16(p + 26);
        u32 shSize = s.le32(p + 29);
        if (isize < 29 || numSamples > 512 || shSize > 1024) return -1;
        if (p + isize > off + max) return -1;
        for (u16 j = 0; j < numSamples; j++) {
            u32 len = s.le32(p + 33 + (i64)j * shSize);
            samples.push_back({len});
        }
        p += isize;
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
