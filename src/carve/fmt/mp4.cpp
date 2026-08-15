// GHOST RECOVER — mp4 signature family (one file per format).
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

i64 vMp4(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int atoms = 0;
    bool sawFtyp = false, sawMdatOrMoov = false;
    while (p + 8 <= off + max && atoms < 100000) {
        u32 sz32 = s.be32(p);
        auto type = s.read(p + 4, 4);
        if (type.size() < 4) break;
        for (u8 c : type)
            if (!(c == ' ' || c == '-' || (c >= '0' && c <= '9') ||
                  (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c >= 0xA9)) {
                return atoms ? lastEnd - off : -1;
            }
        i64 size = sz32;
        if (sz32 == 1) {
            auto ext = s.read(p + 8, 8);
            if (ext.size() < 8) break;
            // Accumulate in u64: an 8-byte extended size can reach 2^64-1 and
            // shifting it into a signed i64 is undefined behaviour.
            u64 esz = 0;
            for (int i = 0; i < 8; i++) esz = (esz << 8) | ext[i];
            if (esz > 0x7FFFFFFFFFFFFFFFull) break;
            size = (i64)esz;
        } else if (sz32 == 0) {
            // "extends to end of file" — in a carving context we cannot know
            // where that is, so stop at the last complete atom.
            break;
        }
        if (size < 8 || p + size > off + max) break;
        if (std::memcmp(type.data(), "ftyp", 4) == 0) sawFtyp = true;
        if (std::memcmp(type.data(), "mdat", 4) == 0 ||
            std::memcmp(type.data(), "moov", 4) == 0) sawMdatOrMoov = true;
        lastEnd = p + size;
        p = lastEnd;
        atoms++;
    }
    if (atoms < 2 || !(sawFtyp || sawMdatOrMoov)) return -1;
    return lastEnd - off;
}void registerFmt_mp4(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("M4A", "m4a", "audio", S("ftyp"), 4*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.priority = 20; add(c); }
    { auto c = mk("HEIC", "heic", "image", S("ftyp"), 256*MB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("heic"), 8); c.priority = 20; add(c); }
    { auto c = mk("HEIF", "heif", "image", S("ftyp"), 256*MB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("mif1"), 8); c.priority = 19; add(c); }
    { auto c = mk("AVIF", "avif", "image", S("ftyp"), 256*MB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("avif"), 8); c.priority = 20; add(c); }
    { auto c = mk("MP4", "mp4", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.min_size = 1024; add(c); }
    { auto c = mk("MOV", "mov", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("qt  "), 8); c.priority = 20; add(c); }
    { auto c = mk("M4V", "m4v", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.priority = 20; add(c); }
    { auto c = mk("3GP", "3gp", "video", S("ftyp"), 4*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("3gp"), 8); c.priority = 20; add(c); }
    { auto c = mk("MOV_MDAT", "mov", "video", S("moov"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.min_size = 1024; add(c); }
}

}  // namespace ghost
