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

// True when any moov child track carries a video ('vide') handler — such a
// container is a movie, not an audio-only M4A. Boxes are read strictly on
// their declared sizes so a damaged file cannot walk past the moov extent.
static bool moovHasVideoTrack(ByteSource& s, i64 moov, i64 end) {
    i64 p = moov + 8;
    while (p + 8 <= end) {
        u32 sz = s.be32(p);
        auto type = s.read(p + 4, 4);
        if (sz < 8 || p + (i64)sz > end) break;
        if (type.size() == 4 && std::memcmp(type.data(), "trak", 4) == 0) {
            i64 q = p + 8;
            while (q + 8 <= p + sz) {
                u32 tsz = s.be32(q);
                auto ttype = s.read(q + 4, 4);
                if (tsz < 8 || q + (i64)tsz > p + sz) break;
                if (ttype.size() == 4 && std::memcmp(ttype.data(), "mdia", 4) == 0) {
                    i64 r = q + 8;
                    while (r + 8 <= q + tsz) {
                        u32 msz = s.be32(r);
                        auto mtype = s.read(r + 4, 4);
                        if (msz < 8 || r + (i64)msz > q + tsz) break;
                        if (mtype.size() == 4 && std::memcmp(mtype.data(), "hdlr", 4) == 0) {
                            auto h = s.read(r + 16, 4);   // version/flags+pre_defined
                            if (h.size() == 4 && std::memcmp(h.data(), "vide", 4) == 0)
                                return true;
                        }
                        r += msz;
                    }
                }
                q += tsz;
            }
        }
        p += sz;
    }
    return false;
}

i64 vMp4(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
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
        if (spec.name == "M4A" && std::memcmp(type.data(), "moov", 4) == 0 &&
            moovHasVideoTrack(s, p, p + size))
            return -1;                           // a movie, not audio-only
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
      c.magic_offset = 4; withConfirm(c, S("M4VH"), 8); c.priority = 20; add(c); }
    { auto c = mk("M4V", "m4v", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("M4VP"), 8); c.priority = 20; add(c); }
    { auto c = mk("3GP", "3gp", "video", S("ftyp"), 4*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("3gp"), 8); c.priority = 20; add(c); }
    { auto c = mk("MOV_MDAT", "mov", "video", S("moov"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.min_size = 1024; add(c); }
}

}  // namespace ghost
