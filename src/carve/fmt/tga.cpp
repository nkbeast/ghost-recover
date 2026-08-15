// GHOST RECOVER — tga signature family (one file per format).
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

// TGA layout: 18-byte header (idlen, colormap type, image type, cmap
// origin/len/bpp, x/y origin, width, height, depth, descriptor), optional
// id field, optional colormap (len*ceil(bpp/8) bytes), pixel data, optional
// 26-byte TRUEVISION footer. Types 1/2/3 store pixels directly; 9/10/11
// are RLE packets of runlen(7 bits)+type(1 bit).
i64 vTga(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 18);
    if (h.size() < 18) return -1;
    const u8 idLen = h[0];
    const u8 cmapType = h[1];
    const u8 imgType = h[2];
    const u32 cmapLen = (u32)h[5] | ((u32)h[6] << 8);
    const u8 cmapBpp = h[7];
    const u32 w = (u32)h[12] | ((u32)h[13] << 8);
    const u32 hgt = (u32)h[14] | ((u32)h[15] << 8);
    const u8 depth = h[16];
    if (cmapType > 1) return -1;
    if (imgType < 1 || imgType > 3) {
        if (imgType < 9 || imgType > 11) return -1;
    }
    if (w == 0 || hgt == 0 || w > 65535 || hgt > 65535) return -1;
    if (depth != 8 && depth != 15 && depth != 16 && depth != 24 && depth != 32)
        return -1;
    if (cmapType == 1) {
        if (cmapLen == 0 || cmapLen > 65535) return -1;
        if (cmapBpp != 15 && cmapBpp != 16 && cmapBpp != 24 && cmapBpp != 32)
            return -1;
    }
    i64 p = off + 18 + idLen;
    if (cmapType == 1) p += (i64)cmapLen * ((cmapBpp + 7) / 8);
    const i64 pixels = (i64)w * hgt;
    const i64 indexBytes = (depth + 7) / 8;   // index width from image depth
    if (imgType == 1 || imgType == 2 || imgType == 3) {
        if (imgType == 1) p += pixels * indexBytes;
        else if (imgType == 3) {
            if (depth != 8) return -1;               // grayscale only
            p += pixels;
        } else {
            p += pixels * ((depth + 7) / 8);
        }
    } else {
        const i64 pxBytes = (imgType == 9) ? indexBytes
                         : (imgType == 10) ? ((depth + 7) / 8) : 1;
        if (imgType == 11 && depth != 8) return -1;  // RLE grayscale only
        i64 got = 0;
        for (i64 guard = 0; guard < pixels + 1; guard++) {
            if (p >= off + max) return -1;
            u8 hdrByte = s.byte(p);
            p++;
            const i64 runLen = (i64)(hdrByte & 0x7F) + 1;
            if (hdrByte & 0x80) {                            // run packet
                if (p + pxBytes > off + max) return -1;
                p += pxBytes;
            } else {                                         // raw packet
                if (p + runLen * pxBytes > off + max) return -1;
                p += runLen * pxBytes;
            }
            got += runLen;
            if (got >= pixels) break;
            if (got > pixels) return -1;
        }
        if (got < pixels) return -1;
    }
    i64 end = p;
    if (end + 26 <= off + max) {                             // TRUEVISION footer
        auto f = s.read(end, 26);
        if (f.size() == 26 &&
            std::memcmp(f.data() + 8, "TRUEVISION-XFILE.\0", 18) == 0)
            end += 26;
    }
    return end - off;
}

void registerFmt_tga(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("TGA_CMAP", "tga", "image", B({0x00,0x01,0x01}), 4*GB, SizeMode::Container, vTga);
      c.min_size = 18; add(c); }
    { auto c = mk("TGA", "tga", "image", B({0x00,0x00,0x02}), 4*GB, SizeMode::Container, vTga);
      c.min_size = 18; add(c); }
    { auto c = mk("TGA_GRAY", "tga", "image", B({0x00,0x00,0x03}), 4*GB, SizeMode::Container, vTga);
      c.min_size = 18; add(c); }
    { auto c = mk("TGA_RLE_CMAP", "tga", "image", B({0x00,0x01,0x09}), 4*GB, SizeMode::Container, vTga);
      c.min_size = 18; add(c); }
    { auto c = mk("TGA_RLE", "tga", "image", B({0x00,0x00,0x0A}), 4*GB, SizeMode::Container, vTga);
      c.min_size = 18; add(c); }
    { auto c = mk("TGA_RLE_GRAY", "tga", "image", B({0x00,0x00,0x0B}), 4*GB, SizeMode::Container, vTga);
      c.min_size = 18; add(c); }
}

}  // namespace ghost
