// GHOST RECOVER — tiff signature family (one file per format).
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

i64 vTiff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto hdr = s.read(off, 8);
    if (hdr.size() < 8) return -1;
    bool be = hdr[0] == 'M';
    auto rd16 = [&](i64 o) { return be ? s.be16(o) : s.le16(o); };
    auto rd32 = [&](i64 o) { return be ? s.be32(o) : s.le32(o); };
    i64 furthest = 8;
    std::vector<i64> ifdQueue;
    auto pushIfd = [&](i64 v) { if (v > 0 && v < max) ifdQueue.push_back(v); };
    pushIfd(rd32(off + 4));
    int guard = 0;
    while (!ifdQueue.empty() && guard++ < 256) {
        i64 ifd = ifdQueue.back();
        ifdQueue.pop_back();
        u16 count = rd16(off + ifd);
        if (count == 0 || count > 4096) break;
        i64 end = ifd + 2 + (i64)count * 12 + 4;
        furthest = std::max(furthest, end);
        // StripOffsets/StripByteCounts and the JPEG-preview pointers tell us
        // where the pixel data actually ends. The count must be added to the
        // offset entry, not to furthest: by the time tag 279 is reached the
        // walker has already processed tags 269/273/... and furthest is no
        // longer the strip start — adding there over-runs every single-strip
        // TIFF by the strip length.
        i64 stripOff = 0;
        std::vector<i64> tileOffs, tileCnts;
        for (u16 i = 0; i < count; i++) {
            i64 e = off + ifd + 2 + (i64)i * 12;
            u16 type = rd16(e + 2);
            u32 n = rd32(e + 4);
            static const int kTypeSize[] = {0,1,1,2,4,8,1,1,2,4,8,4,8};
            int ts = (type < 13) ? kTypeSize[type] : 0;
            if (!ts) continue;
            i64 bytes = (i64)n * ts;
            u16 tag = rd16(e);
            if (bytes > 4) {
                i64 vo = rd32(e + 8);
                if (vo > 0 && vo + bytes <= max) furthest = std::max(furthest, vo + bytes);
                if (tag == 324 && type == 4) {   // TileOffsets: array, one u32 each
                    tileOffs.clear();
                    for (u32 k = 0; k < n; k++) tileOffs.push_back(rd32(off + vo + (i64)k * 4));
                } else if (tag == 325 && type == 4) {   // TileByteCounts
                    tileCnts.clear();
                    for (u32 k = 0; k < n; k++) tileCnts.push_back(rd32(off + vo + (i64)k * 4));
                }
                if (tag == 330 && type == 4) {   // SubIFDs: each value is an IFD
                    for (u32 k = 0; k < n; k++) pushIfd(rd32(off + vo + (i64)k * 4));
                }
            } else if (tag == 330) {
                pushIfd(rd32(e + 8));
            }
            if ((tag == 273 || tag == 324 || tag == 513) && n == 1 && bytes <= 4) {
                stripOff = rd32(e + 8);
                if (stripOff < max) furthest = std::max(furthest, stripOff);
            }
            if ((tag == 279 || tag == 325 || tag == 514) && n == 1 && bytes <= 4) {
                i64 cnt = rd32(e + 8);
                if (stripOff > 0 && cnt > 0 && stripOff + cnt <= max)
                    furthest = std::max(furthest, stripOff + cnt);
            }
        }
        for (size_t k = 0; k < tileOffs.size() && k < tileCnts.size(); k++)
            if (tileOffs[k] > 0 && tileCnts[k] > 0 && tileOffs[k] + tileCnts[k] <= max)
                furthest = std::max(furthest, tileOffs[k] + tileCnts[k]);
        pushIfd(rd32(off + ifd + 2 + (i64)count * 12));
    }
    if (furthest <= 8) return -1;
    return std::min(furthest, max);
}void registerFmt_tiff(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("CR2", "cr2", "image", B({'I','I',0x2A,0x00}), 256*MB, SizeMode::Header, vTiff);
      withConfirm(c, S("CR"), 8); c.priority = 20; add(c); }
    { auto c = mk("DNG", "dng", "image", B({'I','I',0x2A,0x00}), 512*MB, SizeMode::Header, vTiff);
      withConfirm(c, S("DNG"), -1, 65536); c.priority = 18; add(c); }
    { auto c = mk("ARW", "arw", "image", B({'I','I',0x2A,0x00}), 256*MB, SizeMode::Header, vTiff);
      withConfirm(c, S("SONY"), -1, 65536); c.priority = 18; add(c); }
    { auto c = mk("NEF", "nef", "image", B({'M','M',0x00,0x2A}), 256*MB, SizeMode::Header, vTiff);
      withConfirm(c, S("NIKON"), -1, 65536); c.priority = 18; add(c); }
    { auto c = mk("ORF", "orf", "image", B({'I','I','R','O'}), 256*MB, SizeMode::Header, vTiff); add(c); }
    { auto c = mk("RW2", "rw2", "image", B({'I','I','U',0x00}), 256*MB, SizeMode::Header, vTiff); add(c); }
    { auto c = mk("PEF", "pef", "image", B({'M','M',0x00,0x2A}), 256*MB, SizeMode::Header, vTiff);
      withConfirm(c, S("PENTAX"), -1, 65536); c.priority = 18; add(c); }
    { auto c = mk("TIFF_LE", "tif", "image", B({'I','I',0x2A,0x00}), 512*MB, SizeMode::Header, vTiff);
      c.min_size = 16; add(c); }
    { auto c = mk("TIFF_BE", "tif", "image", B({'M','M',0x00,0x2A}), 512*MB, SizeMode::Header, vTiff);
      c.min_size = 16; add(c); }
}

}  // namespace ghost
