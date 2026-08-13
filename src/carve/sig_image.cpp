// GHOST RECOVER — carver signature specs and validators for Images.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

namespace ghost {




// ASCII spelled out as UTF-16LE — OLE2 stream names are stored that way, and
// writing them as a C string would terminate at the first embedded NUL.






// ===========================================================================
// Validators
// ===========================================================================

// --- JPEG: walk the marker chain to the EOI. -------------------------------
i64 vJpeg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 2;
    int segments = 0;
    bool sawSOF = false;
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
        if (marker == 0xD9) return (p + 2) - off;            // EOI
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
                    if (m == 0xD9) return (q + 2) - off;
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
}

// --- PNG: walk chunks to IEND. ---------------------------------------------
i64 vPng(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 8;
    int chunks = 0;
    while (p + 12 <= off + max && chunks < 100000) {
        u32 len = s.be32(p);
        if (len > 0x7FFFFFFF) return -1;
        auto type = s.read(p + 4, 4);
        if (type.size() < 4) return -1;
        for (u8 c : type)
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))) return -1;
        chunks++;
        i64 next = p + 12 + (i64)len;
        if (std::memcmp(type.data(), "IEND", 4) == 0) return next - off;
        if (next <= p || next > off + max) return -1;
        p = next;
    }
    return -1;
}

// --- GIF: walk blocks to the 0x3B trailer. ---------------------------------
i64 vGif(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    const u8 packed = s.byte(off + 10);
    i64 p = off + 13;
    if (packed & 0x80) p += 3LL * (1 << ((packed & 0x07) + 1));   // global colour table
    int guard = 0;
    while (p < off + max && guard++ < 100000) {
        u8 b = s.byte(p);
        if (b == 0x3B) return (p + 1) - off;                      // trailer
        if (b == 0x21) {                                          // extension
            p += 2;
            while (p < off + max) {
                u8 sz = s.byte(p);
                p += 1 + sz;
                if (sz == 0) break;
            }
            continue;
        }
        if (b == 0x2C) {                                          // image descriptor
            u8 lp = s.byte(p + 9);
            p += 10;
            if (lp & 0x80) p += 3LL * (1 << ((lp & 0x07) + 1));
            p += 1;                                               // LZW min code size
            while (p < off + max) {
                u8 sz = s.byte(p);
                p += 1 + sz;
                if (sz == 0) break;
            }
            continue;
        }
        return -1;
    }
    return -1;
}

// --- QOI (Quite OK Image): op stream ended by the 8-byte end marker. -------
i64 vQoi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 4) == 0 || s.be32(off + 8) == 0) return -1;   // width/height
    u8 ch = s.byte(off + 12);
    if (ch < 3 || ch > 4) return -1;
    i64 p = off + 14;
    while (p + 8 <= off + max) {
        // The end marker (7 zero bytes + 0x01) must be checked before
        // decoding — its own zero bytes read back-to-back as index ops.
        if (s.be32(p) == 0 && s.be32(p + 4) == 1) return (p + 8) - off;
        u8 b = s.byte(p);
        if (b == 0xFE) { p += 4; continue; }   // QOI_OP_RGB
        if (b == 0xFF) { p += 5; continue; }   // QOI_OP_RGBA
        p += ((b >> 6) == 2) ? 2 : 1;          // luma takes 2 bytes, others 1
    }
    return -1;
}

// --- BMP: the header carries the file size. --------------------------------
i64 vBmp(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 2);
    u32 dataOff = s.le32(off + 10);
    u32 dibSize = s.le32(off + 14);
    if (dibSize != 12 && dibSize != 40 && dibSize != 52 && dibSize != 56 &&
        dibSize != 64 && dibSize != 108 && dibSize != 124) return -1;
    if (dataOff < 14 + dibSize) return -1;
    if (size < dataOff || (i64)size > max) return -1;
    return size;
}

// --- TIFF (and every raw format built on it): walk the IFD chain. ----------
i64 vTiff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto hdr = s.read(off, 8);
    if (hdr.size() < 8) return -1;
    bool be = hdr[0] == 'M';
    auto rd16 = [&](i64 o) { return be ? s.be16(o) : s.le16(o); };
    auto rd32 = [&](i64 o) { return be ? s.be32(o) : s.le32(o); };
    i64 furthest = 8;
    i64 ifd = rd32(off + 4);
    int guard = 0;
    while (ifd > 0 && ifd < max && guard++ < 64) {
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
        for (u16 i = 0; i < count; i++) {
            i64 e = off + ifd + 2 + (i64)i * 12;
            u16 type = rd16(e + 2);
            u32 n = rd32(e + 4);
            static const int kTypeSize[] = {0,1,1,2,4,8,1,1,2,4,8,4,8};
            int ts = (type < 13) ? kTypeSize[type] : 0;
            if (!ts) continue;
            i64 bytes = (i64)n * ts;
            if (bytes > 4) {
                i64 vo = rd32(e + 8);
                if (vo > 0 && vo + bytes <= max) furthest = std::max(furthest, vo + bytes);
            }
            u16 tag = rd16(e);
            if ((tag == 273 || tag == 324 || tag == 513) && n == 1 && bytes <= 4) {
                stripOff = rd32(e + 8);
                furthest = std::max(furthest, stripOff);
            }
            if ((tag == 279 || tag == 325 || tag == 514) && n == 1 && bytes <= 4) {
                if (stripOff > 0) furthest = std::max(furthest, stripOff + rd32(e + 8));
            }
        }
        ifd = rd32(off + ifd + 2 + (i64)count * 12);
    }
    if (furthest <= 8) return -1;
    return std::min(furthest, max);
}

// --- ICO / CUR -------------------------------------------------------------
i64 vIco(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 type = s.le16(off + 2);
    u16 count = s.le16(off + 4);
    if ((type != 1 && type != 2) || count == 0 || count > 64) return -1;
    const i64 dirEnd = 6 + (i64)count * 16;
    i64 furthest = dirEnd;
    for (u16 i = 0; i < count; i++) {
        i64 e = off + 6 + (i64)i * 16;
        u8 w = s.byte(e), h = s.byte(e + 1);
        u8 planes = s.byte(e + 4);
        u32 bytes = s.le32(e + 8);
        u32 imgOff = s.le32(e + 12);
        // Icon dimensions are 0 (meaning 256) or a real pixel count, colour
        // planes are 0 or 1, and image data must follow the directory.
        if (w == 0 && h == 0 && count == 1) return -1;
        if (planes > 1 && type == 1) return -1;
        if (bytes < 16 || bytes > 16 * 1024 * 1024) return -1;
        if ((i64)imgOff < dirEnd) return -1;
        if ((i64)imgOff + bytes > max) return -1;
        // Each entry points at either a BMP info header (40) or a PNG stream.
        u32 hdr = s.le32(off + (i64)imgOff);
        auto sig = s.read(off + (i64)imgOff, 4);
        bool isPng = sig.size() == 4 && sig[0] == 0x89 && sig[1] == 'P';
        if (hdr != 40 && hdr != 108 && hdr != 124 && !isPng) return -1;
        furthest = std::max<i64>(furthest, (i64)imgOff + bytes);
    }
    return furthest <= max ? furthest : -1;
}

// --- JPEG XL: the raw codestream carries its size in the header. ------------
i64 vJxl(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 7);
    if (h.size() < 7) return -1;
    if (h[0] != 0xFF || h[1] != 0x0A) return -1;
    u32 len = ((u32)h[2] << 24) | ((u32)h[3] << 16) | ((u32)h[4] << 8) | (u32)h[5];
    if (len < 8 || len > max - 6) return -1;
    // A conforming codestream opens with a zero byte (entropy-coded layer
    // header); random data fails this almost always.
    if (h[6] != 0x00) return -1;
    return 6 + (i64)len;
}

// --- PCX (RLE walk) ---------------------------------------------------------
i64 vPcx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 end = off + 128;
    if (end > off + max) return -1;
    u8 bpp = s.byte(off + 3);
    u8 planes = s.byte(off + 65);
    u16 bytesPerLine = s.le16(off + 66);
    u16 xmax = s.le16(off + 8), ymax = s.le16(off + 10);
    u16 xmin = s.le16(off + 4), ymin = s.le16(off + 6);
    if (xmax < xmin || ymax < ymin) return -1;
    if (bpp != 1 && bpp != 2 && bpp != 4 && bpp != 8 && bpp != 24) return -1;
    if (planes == 0 || planes > 4) return -1;
    if (bytesPerLine == 0 || bytesPerLine > 0x7FFF) return -1;
    u64 lines = (u64)(ymax - ymin) + 1;
    // Decoded units = rows x bytes-per-row x planes. RLE data expands to that
    // count; walk the RLE stream over the exact byte count. A 256-color
    // palette (0x0C + 768) may follow.
    u64 units = lines * (u64)bytesPerLine * planes;
    i64 p = end;
    bool any = false;
    for (u64 u = 0; u < units; u++) {
        if (p >= off + max) return -1;
        u8 c = s.byte(p++);
        if (c & 0xC0) {
            if (p >= off + max) return -1;
            p++;                                    // one run value byte
            u += (u64)(c & 0x3F) - 1;
            if (u >= units) break;
        }
        any = true;
    }
    if (!any) return -1;
    // 8-bit single-plane images end with a 768-byte VGA palette preceded by
    // the 0x0C marker.
    if (bpp == 8 && planes == 1 && s.byte(p) == 0x0C) {
        if (p + 769 > off + max) return -1;
        p += 769;
    }
    return (p <= off + max) ? p - off : -1;
}

// --- Photoshop -------------------------------------------------------------
i64 vPsd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 version = s.be16(off + 4);
    if (version != 1 && version != 2) return -1;
    u16 channels = s.be16(off + 12);
    u32 height = s.be32(off + 14);
    u32 width = s.be32(off + 18);
    u16 depth = s.be16(off + 22);
    if (channels == 0 || channels > 56 || width == 0 || height == 0) return -1;
    // The header is all we have before trusting these: bound the dimensions so
    // width * height * channels * depth cannot overflow signed arithmetic.
    if (width > 65536 || height > 65536) return -1;
    if (depth != 1 && depth != 8 && depth != 16 && depth != 32) return -1;
    i64 p = 26;
    u32 colorLen = s.be32(off + p); p += 4 + colorLen;
    u32 resLen   = s.be32(off + p); p += 4 + resLen;
    u32 layerLen = s.be32(off + p); p += 4 + layerLen;
    if (p > max) return -1;
    // Image data section: uncompressed size is an upper bound.
    i64 raw = (i64)width * height * channels * (depth / 8 ? depth / 8 : 1);
    i64 total = std::min(p + raw + 2, max);
    return total;
}

// --- SVG behind an XML declaration: real-world SVGs routinely open with
// <?xml version=...?>, so the <svg magic never fires. Confirm the root tag
// within the first 8 KB, then treat it as the plain-text run it is. ---------
i64 vSvgXml(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
    auto head = s.read(off, std::min<i64>(max, 8192));
    if (head.size() < 16) return -1;
    bool found = false;
    for (size_t i = 0; i + 4 <= head.size(); i++) {
        if (std::memcmp(head.data() + i, "<svg", 4) == 0) { found = true; break; }
    }
    if (!found) return -1;
    i64 size = vText(s, off, max, spec);
    if (size <= 0) return -1;
    // Text carving runs into whatever printable bytes follow the file (a
    // random ASCII byte in the slack region pads the recovered copy). An SVG
    // is a document: it ends with a closing root tag, so trim the run back to
    // the end of the last </svg> plus its trailing newline.
    i64 end = off + size;
    const i64 kProbe = std::min<i64>(size, 64 * KB);
    auto run = s.read(off, kProbe);
    i64 lastClose = -1;
    for (i64 i = 0; i + 6 <= (i64)run.size(); i++) {
        if (std::memcmp(run.data() + (size_t)i, "</svg", 5) == 0) lastClose = i + 5;
    }
    if (lastClose >= 0) {
        i64 trimmed = lastClose;
        if (trimmed < (i64)run.size() && run[(size_t)trimmed] == '>') trimmed++;
        if (trimmed < (i64)run.size() && run[(size_t)trimmed] == '\r') trimmed++;
        if (trimmed < (i64)run.size() && run[(size_t)trimmed] == '\n') trimmed++;
        if (trimmed > 0 && trimmed < size) size = trimmed;
    }
    return size;
}

void registerImages(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("JPEG", "jpg", "image", B({0xFF,0xD8,0xFF}), 512*MB, SizeMode::Container, vJpeg);
      c.min_size = 128; c.footer = B({0xFF,0xD9}); c.priority = 10; add(c); }
    { auto c = mk("PNG", "png", "image", B({0x89,'P','N','G',0x0D,0x0A,0x1A,0x0A}), 512*MB,
                  SizeMode::Container, vPng); c.min_size = 67; c.priority = 10; add(c); }
    { auto c = mk("GIF89a", "gif", "image", S("GIF89a"), 256*MB, SizeMode::Container, vGif);
      c.min_size = 30; add(c); }
    { auto c = mk("GIF87a", "gif", "image", S("GIF87a"), 256*MB, SizeMode::Container, vGif);
      c.min_size = 30; add(c); }
    { auto c = mk("BMP", "bmp", "image", B({'B','M'}), 512*MB, SizeMode::Header, vBmp);
      c.min_size = 54; add(c); }
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
    add(mk("RAF", "raf", "image", S("FUJIFILMCCD-RAW "), 256*MB));
    add(mk("X3F", "x3f", "image", S("FOVb"), 256*MB));
    { auto c = mk("TIFF_LE", "tif", "image", B({'I','I',0x2A,0x00}), 512*MB, SizeMode::Header, vTiff);
      c.min_size = 16; add(c); }
    { auto c = mk("TIFF_BE", "tif", "image", B({'M','M',0x00,0x2A}), 512*MB, SizeMode::Header, vTiff);
      c.min_size = 16; add(c); }
    { auto c = mk("BigTIFF", "tif", "image", B({'I','I',0x2B,0x00}), 2*GB); add(c); }
    { auto c = mk("WEBP", "webp", "image", S("RIFF"), 256*MB, SizeMode::Header, vRiff);
      withConfirm(c, S("WEBP"), 8); c.priority = 20; add(c); }
    { auto c = mk("HEIC", "heic", "image", S("ftyp"), 256*MB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("heic"), 8); c.priority = 20; add(c); }
    { auto c = mk("HEIF", "heif", "image", S("ftyp"), 256*MB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("mif1"), 8); c.priority = 19; add(c); }
    { auto c = mk("AVIF", "avif", "image", S("ftyp"), 256*MB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("avif"), 8); c.priority = 20; add(c); }
    { auto c = mk("ICO", "ico", "image", B({0x00,0x00,0x01,0x00}), 16*MB, SizeMode::Header, vIco);
      c.min_size = 64; add(c); }
    { auto c = mk("CUR", "cur", "image", B({0x00,0x00,0x02,0x00}), 16*MB, SizeMode::Header, vIco);
      c.min_size = 64; add(c); }
    { auto c = mk("PSD", "psd", "image", S("8BPS"), 2*GB, SizeMode::Header, vPsd);
      c.min_size = 128; add(c); }
    add(mk("XCF", "xcf", "image", S("gimp xcf "), 512*MB));
    add(mk("JP2", "jp2", "image", B({0x00,0x00,0x00,0x0C,'j','P',0x20,0x20}), 256*MB));
    add(mk("J2K", "j2k", "image", B({0xFF,0x4F,0xFF,0x51}), 256*MB));
    add(mk("JXL", "jxl", "image", B({0xFF,0x0A}), 256*MB, SizeMode::Header, vJxl));
    add(mk("JXL_ISO", "jxl", "image", B({0x00,0x00,0x00,0x0C,'J','X','L',0x20}), 256*MB));
    add(mk("QOI", "qoi", "image", S("qoif"), 256*MB, SizeMode::Heuristic, vQoi));
    add(mk("DDS", "dds", "image", S("DDS "), 512*MB));
    add(mk("EXR", "exr", "image", B({0x76,0x2F,0x31,0x01}), 512*MB));
    add(mk("HDR", "hdr", "image", S("#?RADIANCE"), 256*MB));
    add(mk("PCX", "pcx", "image", B({0x0A,0x05,0x01,0x08}), 64*MB, SizeMode::Container, vPcx));
    add(mk("ICNS", "icns", "image", S("icns"), 64*MB));
    add(mk("EMF", "emf", "image", B({0x01,0x00,0x00,0x00,0x58,0x00,0x00,0x00}), 64*MB));
    add(mk("WMF", "wmf", "image", B({0xD7,0xCD,0xC6,0x9A}), 64*MB));
    { auto c = mk("SVG", "svg", "image", S("<svg"), 32*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("SVG_XML", "svg", "image", S("<?xml"), 32*MB, SizeMode::Text, vSvgXml);
      c.min_size = 64; c.priority = 15; add(c); }
    add(mk("CDR", "cdr", "image", S("RIFF"), 256*MB, SizeMode::Header, vRiff));
}

}  // namespace ghost
