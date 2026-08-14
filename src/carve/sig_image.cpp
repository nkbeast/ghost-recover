// GHOST RECOVER — carver signature specs and validators for Images.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstdlib>
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

// --- BigTIFF (II 43 08 00): IFD walk to the end of the strip data. ----------
i64 vBigTiff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le16(off + 4) != 8) return -1;                       // offset size
    i64 p = (i64)s.le64(off + 8);                              // first IFD
    if (p < 16 || p > max - 8) return -1;
    u64 n = s.le64(off + p);
    if (n == 0 || n > 100000) return -1;
    i64 stripOff = -1, stripBytes = 0;
    i64 q = p + 8;
    for (u64 i = 0; i < n; i++) {
        if (q + 20 > max) return -1;
        u16 tag = s.le16(off + q);
        u16 type = s.le16(off + q + 2);
        if (type == 4) {                                       // LONG
            u32 v = s.le32(off + q + 12);
            if (tag == 273) stripOff = v;
            if (tag == 279) stripBytes = v;
        } else if (type == 16) {                               // LONG8
            i64 v = (i64)s.le64(off + q + 12);
            if (tag == 273) stripOff = v;
            if (tag == 279) stripBytes = v;
        }
        q += 20;
    }
    if (stripOff < 0) return -1;
    i64 total = std::max(q + 8, stripOff + stripBytes);
    return (total <= max) ? total : -1;
}

// --- ICNS: BE32 total length; walk the chunk table exactly to it. -----------
i64 vIcns(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.be32(off + 4);
    if (total < 16 || total > max) return -1;
    i64 p = off + 8;
    while (p + 8 <= off + total) {
        u32 sz = s.be32(p + 4);
        if (sz < 8 || p + sz > off + total) return -1;
        p += sz;
    }
    return (p == off + total) ? total : -1;
}

// --- EMF: 88-byte header then records [type (4) + size (4 LE) + data];
// the EMR_EOF record (type 14) closes the file; nBytes at 48 must agree. -----
i64 vEmf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.le32(off + 48);
    if (total < 88 || total > max) return -1;
    i64 p = off + 88;
    for (int guard = 0; guard < (1 << 20); guard++) {
        if (p + 8 > off + total) return -1;
        u32 type = s.le32(p);
        u32 size = s.le32(p + 4);
        if (size < 8 || p + size > off + total) return -1;
        p += size;
        if (type == 14) break;                                 // EMR_EOF
    }
    return (p == off + total) ? total : -1;
}

// --- XCF: 14-byte magic + "v00x"; BE32 file size at offset 22. --------------
i64 vXcf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto v = s.read(off + 9, 5);
    if (v.size() < 5 || v[0] != 'v' || v[1] < '0' || v[1] > '1' ||
        v[2] < '0' || v[2] > '9' || v[3] < '0' || v[3] > '9' || v[4] < '0' || v[4] > '9')
        return -1;
    i64 total = s.be32(off + 22);
    if (total < 26 || total > max) return -1;
    return total;
}

// --- JPEG2000 codestream: marker walk; the SOT Psot skips the tile data and
// the EOC marker closes the codestream. --------------------------------------
i64 vJ2k(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 2;                                           // after SOC
    for (int guard = 0; guard < (1 << 16); guard++) {
        if (p + 2 > off + max) return -1;
        u16 m = s.be16(p);
        if (m == 0xFFD9) return (p + 2) - off;                 // EOC
        if (m == 0xFF90) {                                     // SOT
            i64 psot = s.be32(p + 6);
            if (psot < 14) return -1;
            p += psot;                                         // skip to tile end
            continue;
        }
        if ((m >> 8) != 0xFF) return -1;
        switch (m) {
            case 0xFF51: case 0xFF52: case 0xFF53: case 0xFF5C:
            case 0xFF5D: case 0xFF5E: case 0xFF5F: case 0xFF60:
            case 0xFF61: case 0xFF62: case 0xFF63: {           // length-carrying
                u16 len = s.be16(p + 2);
                if (len < 2) return -1;
                p += 2 + len;
                break;
            }
            case 0xFF4F: case 0xFF91: case 0xFF92:             // SOC/SOP/EPH
                p += 2;
                break;
            default:
                return -1;
        }
    }
    return -1;
}

// --- ISO-BMFF box family for codestream carriers (JP2, JXL_ISO): walk the
// top-level boxes; the codestream box (jp2c / jxlp / brob) ends the file. ----
i64 vJp2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    while (p + 8 <= off + max) {
        u64 size = s.be32(p);
        if (size == 0) return -1;
        auto type = s.read(p + 4, 4);
        if (type.size() < 4) return -1;
        bool stream = std::memcmp(type.data(), "jp2c", 4) == 0 ||
                      std::memcmp(type.data(), "jxlp", 4) == 0 ||
                      std::memcmp(type.data(), "brob", 4) == 0;
        if (size == 1) {                                       // XLBox
            u64 xl = s.be64(p + 8);
            if (xl < 16 || p + (i64)xl > off + max) return -1;
            p += (i64)xl;
        } else {
            if (size < 8 || p + (i64)size > off + max) return -1;
            p += (i64)size;
        }
        if (stream) return p - off;
    }
    return -1;
}

// --- OpenEXR: attribute list, then scanline blocks up to the last row. ------
i64 vExr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.le32(off + 4);
    if ((ver & 0xFF) != 2) return -1;                          // file version 2
    i64 p = off + 8;
    i64 yMax = -1;
    for (int guard = 0; guard < (1 << 16); guard++) {
        if (p + 2 > off + max) return -1;
        i64 nLen = 0;
        while (s.byte(p + nLen) != 0) { if (++nLen > 256) return -1; }
        if (nLen == 0) break;                                  // end of attrs
        i64 tLen = 0;
        while (s.byte(p + nLen + 1 + tLen) != 0) { if (++tLen > 64) return -1; }
        u32 sz = s.le32(p + nLen + 1 + tLen + 1);
        if (sz > 16 * 1024 * 1024) return -1;
        auto name = s.read(p, nLen);
        if (name.size() == (size_t)nLen && nLen == 10 &&
            std::memcmp(name.data(), "dataWindow", 10) == 0) {
            auto v = s.read(p + nLen + 1 + tLen + 1 + 4, 16);
            if (v.size() >= 16)                                // box2i: x y x y
                yMax = (i64)((u32)v[12] | (u32)v[13] << 8 | (u32)v[14] << 16 | (u32)v[15] << 24);
        }
        p += nLen + 1 + tLen + 1 + 4 + sz;
    }
    if (yMax < 0 || yMax > (1 << 20)) return -1;
    for (int rows = 0; rows < (1 << 24); rows++) {
        i64 y = (i64)s.le32(p);
        u32 size = s.le32(p + 4);
        if (y < 0 || y > yMax || size == 0 || p + 8 + (i64)size > off + max) return -1;
        p += 8 + size;
        if (y == yMax) return p - off;
    }
    return -1;
}

// --- HDR (Radiance): header + resolution line, then new-RLE scanlines. ------
i64 vHdr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto head = s.read(off, std::min<i64>(max, 4096));
    if (head.size() < 32) return -1;
    std::string text((const char*)head.data(), head.size());
    size_t pos = text.find("-Y ");
    size_t xp = (pos == std::string::npos) ? std::string::npos : text.find("+X ", pos);
    if (xp == std::string::npos) return -1;
    int h = (int)std::strtol(text.c_str() + pos + 3, nullptr, 10);
    int w = (int)std::strtol(text.c_str() + xp + 3, nullptr, 10);
    if (h < 1 || h > 16384 || w < 1 || w > 16384) return -1;
    size_t nl = text.find('\n', xp);
    if (nl == std::string::npos) return -1;
    i64 p = off + (i64)nl + 1;
    for (int r = 0; r < h; r++) {
        if (p + 5 > off + max) return -1;
        if (s.byte(p) != 0x02 || s.byte(p + 1) != 0x02 || s.be16(p + 2) != 1) return -1;
        if ((int)s.byte(p + 4) != w) return -1;
        p += 5 + 4 * (i64)w;
    }
    return p - off;
}

// --- Fuji RAF: the TIFF (offset, length) pair at 0x62/0x66 bounds the file. -
i64 vRaf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.be32(off + 0x62) + s.be32(off + 0x66);
    if (total < 0x70 || total > max) return -1;
    return total;
}

// --- Sigma X3F: image (offset, length) pair at 0x14/0x18 bounds the file. ---
i64 vX3f(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.be32(off + 0x14) + s.be32(off + 0x18);
    if (total < 28 || total > max) return -1;
    return total;
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
    add(mk("RAF", "raf", "image", S("FUJIFILMCCD-RAW "), 256*MB, SizeMode::Header, vRaf));
    add(mk("X3F", "x3f", "image", S("FOVb"), 256*MB, SizeMode::Header, vX3f));
    { auto c = mk("TIFF_LE", "tif", "image", B({'I','I',0x2A,0x00}), 512*MB, SizeMode::Header, vTiff);
      c.min_size = 16; add(c); }
    { auto c = mk("TIFF_BE", "tif", "image", B({'M','M',0x00,0x2A}), 512*MB, SizeMode::Header, vTiff);
      c.min_size = 16; add(c); }
    add(mk("BigTIFF", "tif", "image", B({'I','I',0x2B,0x00}), 2*GB, SizeMode::Header, vBigTiff));
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
    add(mk("XCF", "xcf", "image", S("gimp xcf "), 512*MB, SizeMode::Header, vXcf));
    add(mk("JP2", "jp2", "image", B({0x00,0x00,0x00,0x0C,'j','P',0x20,0x20}), 256*MB, SizeMode::Header, vJp2));
    add(mk("J2K", "j2k", "image", B({0xFF,0x4F,0xFF,0x51}), 256*MB, SizeMode::Header, vJ2k));
    add(mk("JXL", "jxl", "image", B({0xFF,0x0A}), 256*MB, SizeMode::Header, vJxl));
    add(mk("JXL_ISO", "jxl", "image", B({0x00,0x00,0x00,0x0C,'J','X','L',0x20}), 256*MB, SizeMode::Header, vJp2));
    add(mk("QOI", "qoi", "image", S("qoif"), 256*MB, SizeMode::Heuristic, vQoi));
    add(mk("DDS", "dds", "image", S("DDS "), 512*MB));
    add(mk("EXR", "exr", "image", B({0x76,0x2F,0x31,0x01}), 512*MB, SizeMode::Header, vExr));
    add(mk("HDR", "hdr", "image", S("#?RADIANCE"), 256*MB, SizeMode::Header, vHdr));
    { auto c = mk("PCX", "pcx", "image", B({0x0A,0x05,0x01,0x08}), 64*MB, SizeMode::Container, vPcx);
      add(c); }
    add(mk("ICNS", "icns", "image", S("icns"), 64*MB, SizeMode::Header, vIcns));
    add(mk("EMF", "emf", "image", B({0x01,0x00,0x00,0x00,0x58,0x00,0x00,0x00}), 64*MB, SizeMode::Header, vEmf));
    add(mk("WMF", "wmf", "image", B({0xD7,0xCD,0xC6,0x9A}), 64*MB));
    { auto c = mk("SVG", "svg", "image", S("<svg"), 32*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("SVG_XML", "svg", "image", S("<?xml"), 32*MB, SizeMode::Text, vSvgXml);
      c.min_size = 64; c.priority = 15; add(c); }
    add(mk("CDR", "cdr", "image", S("RIFF"), 256*MB, SizeMode::Header, vRiff));
}

}  // namespace ghost
