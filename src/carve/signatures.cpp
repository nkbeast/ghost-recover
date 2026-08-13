// GHOST RECOVER — carver signature registry and format validators.
//
// Two problems with the old table are fixed here.
//
// Sizing: most formats fell back to "read 64 KB and hope", and everything was
// hard-capped at 16 MB, so every video and most archives came out truncated and
// unplayable. Formats that describe their own length are now walked properly,
// and the cap is per-format.
//
// False positives: two-byte signatures such as BM, MZ and 0x0B77 match
// constantly in random data. Every spec can now demand a confirming byte string
// and an entropy range, and the validators reject candidates whose internal
// structure does not hold up.
#include "ghost/carve.h"

#include "ghost/util.h"

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif
#ifdef GHOST_HAVE_BZIP2
#include <bzlib.h>
#endif

#include <algorithm>
#include <cstring>

namespace ghost {

namespace {

inline std::vector<u8> B(std::initializer_list<int> v) {
    std::vector<u8> o;
    o.reserve(v.size());
    for (int x : v) o.push_back((u8)x);
    return o;
}
inline std::vector<u8> S(const char* s) {
    return std::vector<u8>(reinterpret_cast<const u8*>(s),
                           reinterpret_cast<const u8*>(s) + std::strlen(s));
}
// ASCII spelled out as UTF-16LE — OLE2 stream names are stored that way, and
// writing them as a C string would terminate at the first embedded NUL.
inline std::vector<u8> U16(const char* s) {
    std::vector<u8> o;
    for (const char* p = s; *p; ++p) { o.push_back((u8)*p); o.push_back(0); }
    return o;
}

constexpr i64 KB = 1024;
constexpr i64 MB = 1024 * 1024;
constexpr i64 GB = 1024 * MB;

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

// --- RIFF family (WAV, AVI, WEBP): size is in the header. ------------------
i64 vRiff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    u32 sz = s.le32(off + 4);
    i64 total = (i64)sz + 8;
    if (total < 12 || total > max) return -1;
    return total;
}

// --- AIFF / other IFF: big-endian length. ----------------------------------
i64 vIff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 sz = s.be32(off + 4);
    i64 total = (i64)sz + 8;
    if (total < 12 || total > max) return -1;
    return total;
}

// --- ISO base media (MP4/MOV/HEIF/3GP): walk the atom chain. ---------------
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
}

// --- EBML (Matroska/WebM) --------------------------------------------------
u64 ebmlNum(ByteSource& s, i64 p, int& width, bool stripMarker) {
    width = 0;
    u8 b = s.byte(p);
    int len = 0;
    u8 mask = 0x80;
    for (int i = 0; i < 8; i++) { if (b & mask) { len = i + 1; break; } mask >>= 1; }
    if (len == 0) return 0;
    width = len;
    auto raw = s.read(p, len);
    if ((int)raw.size() < len) { width = 0; return 0; }
    u64 v = stripMarker ? (u64)(raw[0] & (mask - 1)) : raw[0];
    for (int i = 1; i < len; i++) v = (v << 8) | raw[i];
    return v;
}

bool knownEbmlId(u64 id) {
    switch (id) {
        case 0x1A45DFA3: case 0x18538067: case 0x1549A966: case 0x1654AE6B:
        case 0x1F43B675: case 0x1C53BB6B: case 0x1941A469: case 0x1043A770:
        case 0x1254C367: case 0x114D9B74: case 0x4489: case 0x4461:
        case 0x2AD7B1: case 0x7BA9: case 0x4D80: case 0x5741: case 0xAE:
        case 0xD7: case 0x73C5: case 0x83: case 0xE0: case 0xE1: case 0x86:
        case 0x9C: case 0xB0: case 0xBA: case 0x23E383: case 0xB5:
        case 0x9F: case 0x6264: case 0x63A2: case 0xE7: case 0xA7: case 0xA3:
        case 0xA0: case 0xA1: case 0x75A1: case 0x9B: case 0x88:
        case 0x4286: case 0x42F7: case 0x42F2: case 0x42F3: case 0x4282:
        case 0x4287: case 0x4285: case 0x4DBB: case 0x53AB: case 0x53AC:
        case 0xBB: case 0xB7: case 0xB3: case 0xF1: case 0x67C8:
        case 0x45A3: case 0x4484: case 0x45B9: case 0xB6: case 0x73C4:
        case 0x91: case 0x92: case 0x61A7: case 0x467E: case 0x660E:
        case 0x42E2: case 0x42E3: case 0x428E: case 0x42E1: case 0x42E0:
            return true;
        default: return false;
    }
}

// Elements whose content is a nest of further elements rather than raw data.
// Descending into these is what makes a MKV carvable: real-world muxers
// (ffmpeg in particular) write the Segment with an explicit size, and the
// old walker skipped explicit-size elements entirely, so it saw the EBML
// header and the Segment, found "no more elements", and rejected every
// normally-sized MKV (nothing was ever carved for the format).
static bool ebmlContainerId(u64 id) {
    switch (id) {
        case 0x18538067:   // Segment
        case 0x114D9B74:   // SeekHead
        case 0x4DBB:       // Seek
        case 0x1549A966:   // Info
        case 0x1654AE6B:   // Tracks
        case 0xAE:         // TrackEntry
        case 0x1F43B675:   // Cluster
        case 0xA0:         // BlockGroup
        case 0x1C53BB6B:   // Cues
        case 0xBB:         // CuePoint
        case 0xB7:         // CueTrackPositions
        case 0x1043A770:   // Chapters
        case 0x1254C367:   // Tags
        case 0x7373:       // Tag
        case 0x1941A469:   // Attachments
        case 0x61A7:       // AttachedFile
        case 0x1A45DFA3:   // EBML header
            return true;
        default: return false;
    }
}

i64 vEbml(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastValid = off;
    int elems = 0, valid = 0;
    constexpr int kMaxDepth = 8;
    i64 limits[kMaxDepth];
    int depth = 0;
    limits[0] = off + max;
    int unknownStreak = 0;

    while (p < off + max && elems < 2000000) {
        while (depth > 0 && p >= limits[depth]) depth--;
        int idW = 0;
        u64 id = ebmlNum(s, p, idW, false);
        if (idW == 0 || id == 0) break;
        i64 szW = 0;
        u64 sz = 0;
        bool leaf = !knownEbmlId(id);
        if (leaf) {
            // Unknown id: most likely raw payload data inside a container.
            // Skip its body by its size field when that reads cleanly; bail
            // after a long run of these so junk cannot walk the disk.
            int lszW = 0;
            sz = ebmlNum(s, p + idW, lszW, true);
            if (lszW > 0 && sz != 0) {
                i64 end = p + idW + lszW + (i64)sz;
                if (end > p && end <= limits[depth]) {
                    // A sized leaf (raw payload element such as an ffmpeg
                    // SimpleBlock) lands exactly on the element end; record it
                    // so the tail element of a real file is included. Without
                    // this the last 1-2 elements of a WebM/MKV fall through to
                    // the next parse, overshoot the container limit, and the
                    // walker stops 2-3 bytes short of the true end.
                    lastValid = end;
                    p = end;
                    if (++unknownStreak > 512) break;
                    elems++;
                    continue;
                }
            }
            if (++unknownStreak > 512) break;
            // One-byte resync: covers size fields that won't parse, the old
            // fallback, and cleans up multi-byte misreads.
            for (int k = 0; k < 7; k++) {
                u8 b = s.byte(p);
                if (b == 0) { p++; break; }
                if (!(b & 0x80)) { p++; } else break;
            }
            p++;
            elems++;
            continue;
        }
        unknownStreak = 0;
        valid++;
        int kszW = 0;
        sz = ebmlNum(s, p + idW, kszW, true);
        szW = kszW;
        if (kszW == 0) break;
        i64 hdr = idW + kszW;
        bool unknownSize = true;
        {
            // All-ones size field means "unknown length".
            u64 allOnes = (szW >= 8) ? ~0ull : ((1ull << (szW * 7)) - 1);
            unknownSize = (sz >= allOnes);
        }
        if (unknownSize) {
            if (!ebmlContainerId(id)) { p += hdr; elems++; continue; }
            if (depth < kMaxDepth - 1) {
                depth++;
                limits[depth] = limits[depth - 1];
                p += hdr;
                lastValid = p;
                elems++;
                continue;
            }
            break;
        }
        i64 end = p + hdr + (i64)sz;
        if (end <= p || end > limits[depth]) break;
        lastValid = end;
        p = end;
        if (ebmlContainerId(id)) {
            if (depth < kMaxDepth - 1) {
                // Walk the container's children; the depth/limit bookkeeping
                // pops back out the moment the content runs out.
                depth++;
                limits[depth] = end;
                p = p - (i64)sz;        // back to the content start
                elems++;
                continue;
            }
        }
        elems++;
    }
    if (valid < 3) return -1;
    return lastValid - off;
}

// --- Ogg: walk pages. ------------------------------------------------------
i64 vOgg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int pages = 0;
    while (p + 27 <= off + max && pages < 4000000) {
        auto h = s.read(p, 27);
        if (h.size() < 27) break;
        if (h[0] != 'O' || h[1] != 'g' || h[2] != 'g' || h[3] != 'S' || h[4] != 0) break;
        u8 segs = h[26];
        auto seg = s.read(p + 27, segs);
        if ((int)seg.size() < segs) break;
        i64 dataSize = 0;
        for (u8 x : seg) dataSize += x;
        i64 pageSize = 27 + segs + dataSize;
        if (p + pageSize > off + max) break;
        lastEnd = p + pageSize;
        p = lastEnd;
        pages++;
    }
    if (pages < 1) return -1;
    return lastEnd - off;
}

// --- FLAC ------------------------------------------------------------------
// FLAC frames carry CRC-8 (poly 0x07, init 0) over the frame header and
// CRC-16 (poly 0x8005, init 0, unreflected) over the payload; walking frames
// with those checks makes every boundary exact without a subframe decode.
static u8 flacCrc8Step(u8 crc, u8 b) {
    crc ^= b;
    for (int i = 0; i < 8; i++)
        crc = (crc & 0x80) ? (u8)((crc << 1) ^ 0x07) : (u8)(crc << 1);
    return crc;
}
static u16 flacCrc16Step(u16 crc, u8 b) {
    crc ^= (u16)b << 8;
    for (int i = 0; i < 8; i++)
        crc = (crc & 0x8000) ? (u16)((crc << 1) ^ 0x8005) : (u16)(crc << 1);
    return crc;
}

i64 vFlac(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 4;
    bool last = false;
    int blocks = 0;
    u32 maxFramesize = 0;
    while (!last && p + 4 <= off + max && blocks < 128) {
        auto h = s.read(p, 4);
        if (h.size() < 4) break;
        last = (h[0] & 0x80) != 0;
        u8 type = h[0] & 0x7F;
        if (type > 6 && type != 127) return -1;
        u32 len = (u32)h[1] << 16 | (u32)h[2] << 8 | h[3];
        if (p + 4 + (i64)len > off + max) break;
        if (type == 0 && len >= 18) {
            auto si = s.read(p + 4, 18);
            if (si.size() >= 18)
                maxFramesize = (u32)si[7] << 16 | (u32)si[8] << 8 | si[9];
        }
        p += 4 + len;
        blocks++;
    }
    if (blocks == 0) return -1;
    // Walk frames: sync 0xFF 0xF8/0xF9/0xFA/0xFB, decode the header so the
    // CRC-8 covers exactly the header bytes, then find the frame end by
    // scanning for the byte position where CRC-16 over the payload matches —
    // so the final frame lands exactly on its own CRC, not on a guessed tail.
    i64 q = p;
    int frames = 0;
    while (q + 4 <= off + max && frames < 1000000) {
        auto sb = s.read(q, 4);
        if (sb.size() < 4 || sb[0] != 0xFF || (sb[1] & 0xFC) != 0xF8) break;
        u8 bc = (sb[2] >> 4) & 0xF;
        u8 sc = sb[2] & 0xF;
        i64 at = q + 4;
        u8 u = s.byte(at);
        int nlen;
        if ((u & 0x80) == 0) nlen = 1;
        else if ((u & 0xE0) == 0xC0) nlen = 2;
        else if ((u & 0xF0) == 0xE0) nlen = 3;
        else if ((u & 0xF8) == 0xF0) nlen = 4;
        else if ((u & 0xFC) == 0xF8) nlen = 5;
        else if ((u & 0xFE) == 0xFC) nlen = 6;
        else nlen = 7;
        at += nlen;
        if (bc == 6) at += 1;
        else if (bc == 7) at += 2;
        if (sc == 0xC) at += 1;
        else if (sc == 0xD || sc == 0xE) at += 2;
        // A frame may run past any encoder-stated max (wasted bits, odd block
        // sizes); give the scan generous headroom but never past the probe
        // region, so a deleted file cannot swallow what follows it.
        i64 scanEnd = q + 96 * KB;
        i64 headroom = 2 * (i64)std::max<u32>(maxFramesize, 4096) + 8 * KB;
        scanEnd = std::min<i64>(q + headroom, std::min<i64>(off + max, scanEnd));
        if (scanEnd - q < at - q + 8) return -1;
        auto fr = s.read(q, (size_t)(scanEnd - q));
        if (fr.size() < (size_t)(at - q) + 1) break;
        u8 crc8 = 0;
        for (size_t i = 0; i < (size_t)(at - q); i++) crc8 = flacCrc8Step(crc8, fr[i]);
        (void)crc8;                              // header CRC is advisory only
        // Incremental CRC-16: after byte i, checking the next two bytes tells
        // whether the frame ends at i+3.
        i64 L = -1;
        u16 crc16 = 0;
        const u8* d = fr.data();
        size_t n = fr.size();
        for (size_t i = 0; i + 3 <= n; i++) {
            crc16 = flacCrc16Step(crc16, d[i]);
            if (i + 1 >= (size_t)(at - q) && crc16 == ((u16)d[i + 1] << 8 | d[i + 2])) {
                L = (i64)i + 3;
                break;
            }
        }
        if (L < 0) break;                        // no valid boundary: foreign data
        q += L;
        frames++;
    }
    if (frames == 0) return p - off;             // metadata-only file
    return q - off;
}

// --- DTS / DCA (Coherent Acoustics) core frames ------------------------------
// Bitstream is LSB-first per 16-bit word; the 14-bit frame-size field sits at
// bit offset 24 in the on-disk byte order (byte 3 low bit + byte 4 top six) —
// the layout ffmpeg's encoder writes — rather than the textbook bits 32..45.
// Try both and keep whichever walks a self-consistent frame chain.
i64 vDts(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 8);
    if (h.size() < 8) return -1;
    if (h[0] != 0x7F || h[1] != 0xFE || h[2] != 0x80 || h[3] != 0x01) return -1;
    i64 c1 = ((i64)(h[3] & 0x01) << 6) | (h[4] >> 2);        // bytes: ffmpeg dst
    i64 c2 = ((i64)(h[4] & 0x3F) << 8) | h[5];               // spec 32..45
    struct Chain { i64 len; int frames; };
    auto walk = [&](i64 field) -> Chain {
        Chain bad = {-1, 0};
        i64 size = (field + 1) * 2;                          // 16-bit words
        if (field == 0 || size < 16 || size > 4 * MB) return bad;
        i64 p = off;
        int frames = 0;
        while (p + 8 <= off + max && frames < 1000000) {
            auto b = s.read(p, 8);
            if (b.size() < 8 || b[0] != 0x7F || b[1] != 0xFE ||
                b[2] != 0x80 || b[3] != 0x01) break;
            i64 f = ((i64)(b[3] & 0x01) << 6) | (b[4] >> 2);
            size = (f + 1) * 2;
            if (size < 16 || size > 4 * MB) return bad;
            p += size;
            frames++;
            if (p > off + max) return bad;
        }
        if (frames == 0) return bad;
        return {p - off, frames};
    };
    Chain a = walk(c1), b = walk(c2);
    bool aOk = a.len >= 0, bOk = b.len >= 0;
    if (!aOk && !bOk) return -1;
    if (!aOk) return b.len;
    if (!bOk) return a.len;
    // A longer frame chain is the real file; a stray candidate usually stops
    // after one frame. Ties go to the chain that fills the region exactly.
    if (a.frames != b.frames) return (a.frames > b.frames) ? a.len : b.len;
    if (a.len == max || b.len == max) return (a.len == max) ? a.len : b.len;
    return std::max(a.len, b.len);
}

// --- MP3 / MPEG audio ------------------------------------------------------
int mpegFrameSize(u8 b1, u8 b2, u8 b3, int* layerOut, int* verOut, int* srOut) {
    if ((b1 & 0xE0) != 0xE0) return 0;
    int ver = (b1 >> 3) & 3;      // 3=MPEG1, 2=MPEG2, 0=MPEG2.5
    int layer = (b1 >> 1) & 3;    // 3=I, 2=II, 1=III
    if (ver == 1 || layer == 0) return 0;
    int brIdx = (b2 >> 4) & 0xF;
    int srIdx = (b2 >> 2) & 3;
    int pad = (b2 >> 1) & 1;
    if (brIdx == 0 || brIdx == 0xF || srIdx == 3) return 0;
    static const int kBrV1[4][16] = {
        {0},
        {0,32,40,48,56,64,80,96,112,128,160,192,224,256,320,0},    // layer III
        {0,32,48,56,64,80,96,112,128,160,192,224,256,320,384,0},   // layer II
        {0,32,64,96,128,160,192,224,256,288,320,352,384,416,448,0} // layer I
    };
    static const int kBrV2[4][16] = {
        {0},
        {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0},
        {0,8,16,24,32,40,48,56,64,80,96,112,128,144,160,0},
        {0,32,48,56,64,80,96,112,128,144,160,176,192,224,256,0}
    };
    static const int kSr[4][4] = {
        {11025,12000,8000,0}, {0,0,0,0}, {22050,24000,16000,0}, {44100,48000,32000,0}
    };
    int bitrate = (ver == 3) ? kBrV1[layer][brIdx] : kBrV2[layer][brIdx];
    int sr = kSr[ver][srIdx];
    if (!bitrate || !sr) return 0;
    int size;
    if (layer == 3) size = (12 * bitrate * 1000 / sr + pad) * 4;             // layer I
    else if (ver == 3) size = 144 * bitrate * 1000 / sr + pad;               // layer II/III MPEG1
    else size = (layer == 1 ? 72 : 144) * bitrate * 1000 / sr + pad;
    if (size < 24 || size > 8192) return 0;
    if (layerOut) *layerOut = layer;
    if (verOut) *verOut = ver;
    if (srOut) *srOut = srIdx;
    (void)b3;
    return size;
}

i64 vMp3(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    auto h = s.read(off, 10);
    if (h.size() >= 10 && h[0] == 'I' && h[1] == 'D' && h[2] == '3') {
        u32 tagSize = ((u32)(h[6] & 0x7F) << 21) | ((u32)(h[7] & 0x7F) << 14) |
                      ((u32)(h[8] & 0x7F) << 7) | (u32)(h[9] & 0x7F);
        p = off + 10 + tagSize;
    }
    i64 lastEnd = p;
    int frames = 0, layer0 = -1, ver0 = -1, sr0 = -1;
    int consecResync = 0;   // random data must not chain through resyncs
    const i64 kResync = 32 * 1024;   // bridge small overwritten regions
    while (p + 4 <= off + max && frames < 4000000) {
        auto f = s.read(p, 4);
        if (f.size() < 4) break;
        int layer = 0, ver = 0, sr = 0;
        int size = (f[0] == 0xFF) ? mpegFrameSize(f[1], f[2], f[3], &layer, &ver, &sr) : 0;
        if (size && frames > 0 && (layer != layer0 || ver != ver0 || sr != sr0))
            break;   // a different stream layout — hard stop, not a gap
        if (!size) {
            // Deleted files are often partially overwritten in cluster-sized
            // chunks. A bad frame used to end the file, carving every run of
            // frames as a separate "MP3_FRAME_0000N". Resync within a bounded
            // window instead, requiring a frame of the exact same layout whose
            // successor parses too — one lucky byte pattern proves nothing.
            if (frames == 0) break;
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i + 8 <= (i64)win.size(); i++) {
                if (win[(size_t)i] != 0xFF) continue;
                int l2 = 0, v2 = 0, s2 = 0;
                int sz2 = mpegFrameSize(win[(size_t)(i + 1)], win[(size_t)(i + 2)],
                                        win[(size_t)(i + 3)], &l2, &v2, &s2);
                if (!sz2 || l2 != layer0 || v2 != ver0 || s2 != sr0) continue;
                i64 nxt = i + sz2;
                if (nxt + 4 > (i64)win.size()) break;
                if (win[(size_t)nxt] != 0xFF) continue;
                int l3 = 0, v3 = 0, s3 = 0;
                int sz3 = mpegFrameSize(win[(size_t)(nxt + 1)], win[(size_t)(nxt + 2)],
                                        win[(size_t)(nxt + 3)], &l3, &v3, &s3);
                if (!sz3 || l3 != layer0 || v3 != ver0 || s3 != sr0) continue;
                p += i;
                found = true;
                break;
            }
            if (!found) break;
            if (++consecResync >= 4) break;
            continue;
        }
        if (frames == 0) { layer0 = layer; ver0 = ver; sr0 = sr; }
        if (p + size > off + max) break;
        lastEnd = p + size;
        p = lastEnd;
        frames++;
        consecResync = 0;
    }
    if (frames < 3) return -1;
    // ID3v1 trailer, if present.
    auto tail = s.read(lastEnd, 3);
    if (tail.size() == 3 && tail[0] == 'T' && tail[1] == 'A' && tail[2] == 'G')
        lastEnd += 128;
    return lastEnd - off;
}

// --- AAC (ADTS) ------------------------------------------------------------
i64 vAac(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int frames = 0, sr0 = -1, prof0 = -1;
    int consecResync = 0;
    const i64 kResync = 32 * 1024;
    while (p + 7 <= off + max && frames < 4000000) {
        auto h = s.read(p, 7);
        if (h.size() < 7 || h[0] != 0xFF || (h[1] & 0xF0) != 0xF0) break;
        u32 len = ((u32)(h[3] & 0x03) << 11) | ((u32)h[4] << 3) | ((u32)(h[5] >> 5) & 7);
        if (len < 7 || len > 8192) break;
        int sr = (h[2] >> 2) & 0xF;
        int prof = (h[2] >> 6) & 3;
        if (sr > 12) break;
        if (frames == 0) { sr0 = sr; prof0 = prof; }
        else if (sr != sr0 || prof != prof0) break;
        if (p + (i64)len > off + max) break;
        lastEnd = p + len;
        p = lastEnd;
        frames++;
        consecResync = 0;
        if (frames < 4) continue;
        // Peek the next frame header; if it is not a valid frame of the same
        // layout, the bytes in between were overwritten. Resync over a bounded
        // window instead of fragmenting the file at the first bad byte
        // (deleted files are usually overwritten in cluster-sized chunks).
        auto nxt = s.read(p, 7);
        bool gap = nxt.size() < 7;
        if (!gap) {
            u32 len2 = ((u32)(nxt[3] & 0x03) << 11) | ((u32)nxt[4] << 3) |
                       ((u32)(nxt[5] >> 5) & 7);
            int sr2 = (nxt[2] >> 2) & 0xF;
            int prof2 = (nxt[2] >> 6) & 3;
            gap = nxt[0] != 0xFF || (nxt[1] & 0xF0) != 0xF0 || len2 < 7 ||
                  len2 > 8192 || sr2 != sr0 || prof2 != prof0;
        }
        if (gap) {
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i + 7 <= (i64)win.size(); i++) {
                if (win[(size_t)i] != 0xFF || (win[(size_t)(i + 1)] & 0xF0) != 0xF0) continue;
                u32 l2 = ((u32)(win[(size_t)(i + 3)] & 0x03) << 11) |
                         ((u32)win[(size_t)(i + 4)] << 3) | ((u32)(win[(size_t)(i + 5)] >> 5) & 7);
                if (l2 < 7 || l2 > 8192) continue;
                int s2 = (win[(size_t)(i + 2)] >> 2) & 0xF;
                int pf2 = (win[(size_t)(i + 2)] >> 6) & 3;
                if (s2 > 12 || s2 != sr0 || pf2 != prof0) continue;
                i64 nxt = i + (i64)l2;
                if (nxt + 7 > (i64)win.size()) break;
                if (win[(size_t)nxt] != 0xFF || (win[(size_t)(nxt + 1)] & 0xF0) != 0xF0) continue;
                u32 l3 = ((u32)(win[(size_t)(nxt + 3)] & 0x03) << 11) |
                         ((u32)win[(size_t)(nxt + 4)] << 3) | ((u32)(win[(size_t)(nxt + 5)] >> 5) & 7);
                if (l3 < 7 || l3 > 8192) continue;
                int s3 = (win[(size_t)(nxt + 2)] >> 2) & 0xF;
                int pf3 = (win[(size_t)(nxt + 2)] >> 6) & 3;
                if (s3 != sr0 || pf3 != prof0) continue;
                if (p + i + (i64)l2 <= off + max) { p += i; found = true; break; }
            }
            if (!found) break;
            if (++consecResync >= 4) break;
        }
    }
    if (frames < 4) return -1;
    return lastEnd - off;
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

// --- PGP keyring: walk the old-format public-key packet chain. --------------
i64 vGpg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int keys = 0;
    while (p + 3 <= off + max && keys < 1000000) {
        auto h = s.read(p, 3);
        if (h.size() < 3) break;
        if (h[0] != 0x99 && h[0] != 0x98) break;   // pubkey / seckey packet
        int len = ((int)h[1] << 8) | h[2];
        if (len < 269 || len > 8192) break;        // key body length is bounded
        auto b = s.read(p + 3, 1);
        if (b.empty() || (b[0] != 0x01 && b[0] != 0x02)) break;
        lastEnd = p + 3 + len;
        p = lastEnd;
        keys++;
    }
    if (keys == 0) return -1;
    return lastEnd - off;
}

// --- AC-3 ------------------------------------------------------------------
i64 vAc3(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // frmsizecod -> frame size in 16-bit words, per sample rate.
    static const u16 kFrameSizes[38][3] = {
        {64,69,96},{64,70,96},{80,87,120},{80,88,120},{96,104,144},{96,105,144},
        {112,121,168},{112,122,168},{128,139,192},{128,140,192},{160,174,240},{160,175,240},
        {192,208,288},{192,209,288},{224,243,336},{224,244,336},{256,278,384},{256,279,384},
        {320,348,480},{320,349,480},{384,417,576},{384,418,576},{448,487,672},{448,488,672},
        {512,557,768},{512,558,768},{640,696,960},{640,697,960},{768,835,1152},{768,836,1152},
        {896,975,1344},{896,976,1344},{1024,1114,1536},{1024,1115,1536},
        {1152,1253,1728},{1152,1254,1728},{1280,1393,1920},{1280,1394,1920}
    };
    i64 p = off, lastEnd = off;
    int frames = 0, fscod0 = -1;
    int consecResync = 0;
    const i64 kResync = 32 * 1024;
    while (p + 6 <= off + max && frames < 2000000) {
        auto h = s.read(p, 6);
        if (h.size() < 6 || h[0] != 0x0B || h[1] != 0x77) {
            // Overwritten region: resync like vMp3/vAac instead of
            // fragmenting the file at the first bad frame.
            if (frames == 0) break;
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i + 6 <= (i64)win.size(); i++) {
                if (win[(size_t)i] != 0x0B || win[(size_t)(i + 1)] != 0x77) continue;
                int f2 = (win[(size_t)(i + 4)] >> 6) & 3;
                int fs2 = win[(size_t)(i + 4)] & 0x3F;
                if (f2 != fscod0 || f2 == 3 || fs2 > 37) continue;
                i64 sz2 = (i64)kFrameSizes[fs2][f2] * 2;
                if (p + i + sz2 <= off + max) { p += i; found = true; break; }
            }
            if (!found) break;
            if (++consecResync >= 4) break;
            continue;
        }
        int fscod = (h[4] >> 6) & 3;
        int frmsizecod = h[4] & 0x3F;
        if (fscod == 3 || frmsizecod > 37) break;
        if (frames == 0) fscod0 = fscod;
        else if (fscod != fscod0) break;
        i64 size = (i64)kFrameSizes[frmsizecod][fscod] * 2;
        if (p + size > off + max) break;
        lastEnd = p + size;
        p = lastEnd;
        frames++;
        consecResync = 0;
    }
    if (frames < 4) return -1;
    return lastEnd - off;
}

// --- MPEG transport stream -------------------------------------------------
i64 vMpegTs(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    constexpr int kPkt = 188;
    i64 p = off;
    int pkts = 0;
    while (p + kPkt <= off + max && pkts < 8000000) {
        if (s.byte(p) != 0x47) break;
        p += kPkt;
        pkts++;
    }
    if (pkts < 16) return -1;         // 16 consecutive packets = real TS
    return p - off;
}

// --- MPEG program stream ---------------------------------------------------
i64 vMpegPs(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    int packs = 0;
    while (p + 14 <= off + max && packs < 4000000) {
        auto h = s.read(p, 14);
        if (h.size() < 14) break;
        if (h[0] || h[1] || h[2] != 1) break;
        u8 id = h[3];
        if (id == 0xBA) {                          // pack header
            if ((h[4] & 0xC0) == 0x40) {           // MPEG-2
                u8 stuffing = h[13] & 7;
                p += 14 + stuffing;
            } else {
                p += 12;                           // MPEG-1
            }
            packs++;
            continue;
        }
        if (id == 0xB9) { p += 4; break; }         // end code
        u16 len = s.be16(p + 4);
        if (len == 0) break;
        p += 6 + len;
        packs++;
    }
    if (packs < 4) return -1;
    return p - off;
}

// --- MPEG elementary stream (video, raw .mpv) -------------------------------
i64 vMpegVes(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12 || h[0] || h[1] || h[2] != 1 || h[3] != 0xB3) return -1;
    u32 w = (u32)h[4] << 4 | h[5] >> 4;
    u32 ht = (u32)h[6] << 4 | h[7] >> 4;
    if (w < 8 || w > 16384 || ht < 8 || ht > 16384) return -1;
    if ((h[5] & 0xF) > 14) return -1;              // aspect ratio code
    if ((h[7] & 0xF) == 0) return -1;              // frame rate code 0 = forbidden
    i64 end = off + max;
    i64 q = off + 12;
    int total = 0, slices = 0;
    while (q + 4 <= end) {
        int zrun = 0;
        i64 zstart = -1;
        while (q + 4 <= end) {
            if (s.byte(q) == 0) { if (zstart < 0) zstart = q; zrun++; }
            else { zrun = 0; zstart = -1; }
            if (zrun >= 256) return zstart - off;  // dead space / probe pad
            if (s.byte(q) == 0 && s.byte(q + 1) == 0 && s.byte(q + 2) == 1) break;
            q++;
        }
        if (q + 4 > end) break;
        u8 id = s.byte(q + 3);
        if (id >= 0x01 && id <= 0xAF) slices++;    // slice
        else total++;
        if (id == 0xB7) return (q + 4) - off;      // sequence end code
        if (id == 0x00 || id == 0xB3 || id == 0xB5 || id == 0xB8 || (id >= 0x01 && id <= 0xAF)) {
            q += 4;
            continue;
        }
        break;
    }
    if (slices < 2 || total + slices < 6) return -1;
    return q - off;
}

// --- MXF (Material eXchange Format): KLV chain ------------------------------
i64 vMxf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off;
    int klvs = 0;
    while (p + 17 <= off + max && klvs < 4000000) {
        auto key = s.read(p, 16);
        if (key.size() < 16 || key[0] != 0x06 || key[1] != 0x0E || key[2] != 0x2B || key[3] != 0x34)
            break;
        u8 l0 = s.byte(p + 16);
        i64 L, hdr;
        if (l0 & 0x80) {
            int nbytes = l0 & 0x7F;
            if (nbytes == 0 || nbytes > 8 || p + 17 + nbytes > off + max) return -1;
            L = 0;
            for (int k = 0; k < nbytes; k++) L = L << 8 | s.byte(p + 17 + k);
            hdr = 17 + nbytes;
        } else {
            L = l0;
            hdr = 17;
        }
        if (L < 0) return -1;
        p += hdr + L;
        klvs++;
    }
    if (klvs < 4) return -1;
    return p - off;
}

// --- FLV -------------------------------------------------------------------
i64 vFlv(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 9);
    if (h.size() < 9 || h[0] != 'F' || h[1] != 'L' || h[2] != 'V') return -1;
    u32 dataOffset = s.be32(off + 5);
    if (dataOffset < 9 || dataOffset > 1024) return -1;
    i64 p = off + dataOffset;
    int tags = 0;
    while (p + 15 <= off + max && tags < 4000000) {
        u32 prevSize = s.be32(p);
        (void)prevSize;
        u8 type = s.byte(p + 4) & 0x1F;
        if (type != 8 && type != 9 && type != 18) break;
        u32 dataSize = (u32)s.be16(p + 5) << 8 | s.byte(p + 7);
        i64 total = 4 + 11 + (i64)dataSize;
        if (p + total > off + max) break;
        p += total;
        tags++;
    }
    if (tags < 2) return -1;
    return (p + 4) - off;
}

// --- ASF / WMV / WMA -------------------------------------------------------
i64 vAsf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The header object's field at +16 is the total header size; the file size
    // lives in the File Properties object inside it.
    auto h = s.read(off, 30);
    if (h.size() < 30) return -1;
    u64 headerSize = 0;
    for (int i = 0; i < 8; i++) headerSize |= (u64)h[16 + i] << (i * 8);
    if (headerSize < 30 || (i64)headerSize > max) return -1;
    // Look for the File Properties GUID inside the header for the real length.
    static const u8 kFileProps[16] = {0xA1,0xDC,0xAB,0x8C,0x47,0xA9,0xCF,0x11,
                                      0x8E,0xE4,0x00,0xC0,0x0C,0x20,0x53,0x65};
    auto hdr = s.read(off, std::min<i64>((i64)headerSize, 1 * MB));
    for (size_t i = 0; i + 40 < hdr.size(); i++) {
        if (std::memcmp(hdr.data() + i, kFileProps, 16) != 0) continue;
        u64 fileSize = 0;
        for (int k = 0; k < 8; k++) fileSize |= (u64)hdr[i + 40 + k] << (k * 8);
        if (fileSize >= headerSize && (i64)fileSize <= max) return (i64)fileSize;
        break;
    }
    // Fall back to walking the top-level object chain.
    i64 p = off + (i64)headerSize;
    int objects = 0;
    while (p + 24 <= off + max && objects < 4096) {
        auto o = s.read(p, 24);
        if (o.size() < 24) break;
        u64 sz = 0;
        for (int i = 0; i < 8; i++) sz |= (u64)o[16 + i] << (i * 8);
        if (sz < 24 || p + (i64)sz > off + max) break;
        p += (i64)sz;
        objects++;
    }
    return p - off;
}

// --- AMR -------------------------------------------------------------------
i64 vAmr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 9);
    bool wb = h.size() >= 9 && std::memcmp(h.data(), "#!AMR-WB\n", 9) == 0;
    i64 p = off + (wb ? 9 : 6);
    static const int kNb[16] = {12,13,15,17,19,20,26,31,5,0,0,0,0,0,0,0};
    static const int kWb[16] = {17,23,32,36,40,46,50,58,60,5,0,0,0,0,0,0};
    int frames = 0;
    bool real = false;   // any non-zero frame TOC seen so far
    int consecResync = 0;
    const i64 kResync = 8 * 1024;
    while (p < off + max && frames < 2000000) {
        u8 toc = s.byte(p);
        int mode = (toc >> 3) & 0xF;
        // NO_DATA (mode 15) terminates most streams. A run of all-zero frame
        // units after at least four real, non-zero frames is padding (files
        // are padded with zeroes to 20 ms / 40 ms boundaries or with whole
        // dropped frames); a stream that is zero frames throughout (a synth
        // silence file like sox's) must still be walked to its end.
        u8 b1 = s.byte(p + 1), b2 = s.byte(p + 2), b3 = s.byte(p + 3);
        if (mode == 15) { p += 1; break; }   // NO_DATA terminator, 1-byte TOC only
        if (toc != 0) real = true;
        if (real && frames >= 4 && toc == 0 && b1 == 0 && b2 == 0 && b3 == 0) break;
        int sz = wb ? kWb[mode] : kNb[mode];
        if (sz == 0) {
            // Invalid/future frame mode: overwritten region. Resync over a
            // bounded window (same rationale as vMp3/vAac/vAc3).
            if (frames < 4) break;
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i < (i64)win.size(); i++) {
                int m2 = (win[(size_t)i] >> 3) & 0xF;
                int s2 = wb ? kWb[m2] : kNb[m2];
                if (m2 < 15 && s2 > 0) { p += i; found = true; break; }
            }
            if (!found) break;
            if (++consecResync >= 4) break;
            continue;
        }
        p += 1 + sz;
        frames++;
        consecResync = 0;
    }
    if (frames < 4) return -1;
    return p - off;
}

// --- AU (Sun/NeXT .snd) ----------------------------------------------------
i64 vAu(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 dataOff = s.be32(off + 4);
    u32 dataSize = s.be32(off + 8);
    u32 encoding = s.be32(off + 12);
    u32 rate = s.be32(off + 16);
    u32 chans = s.be32(off + 20);
    if (encoding > 27) return -1;
    if (rate == 0 || rate > 200000 || chans == 0 || chans > 256) return -1;
    if (dataSize == 0xFFFFFFFFu) return -1;         // unknown: can't size it
    if (dataOff < 24 || dataOff > 32 * 1024) return -1;
    i64 end = off + (i64)dataOff + (i64)dataSize;
    return (end <= off + max) ? end - off : -1;
}

// --- CAF (Apple Core Audio Format) ------------------------------------------
i64 vCaf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be16(off + 4) != 1) return -1;
    i64 p = off + 8;
    while (p + 12 <= off + max) {
        auto t = s.read(p, 4);
        if (t.size() < 4) return -1;
        auto szb = s.read(p + 4, 8);
        if (szb.size() < 8) return -1;
        u64 sz = 0;
        for (int k = 0; k < 8; k++) sz = sz << 8 | szb[k];
        if (sz > (u64)max) return -1;
        bool dataChunk = (t[0] == 'd' && t[1] == 'a' && (t[2] == 't' || t[2] == 'a'));
        p += 12 + (i64)sz;
        if (dataChunk) break;
    }
    if (p > off + max) return -1;
    return p - off;
}

// --- VOC (Creative Voice) ---------------------------------------------------
i64 vVoc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (getenv("GHOST_DEBUG_VOC"))
        fprintf(stderr, "vVoc ENTER off=%lld max=%lld\n", (long long)off, (long long)max);
    auto h = s.read(off, 24);
    if (h.size() < 24) return -1;
    if (std::memcmp(h.data(), "Creative Voice File\x1a", 20) != 0) return -1;
    // Header: 20-byte magic + \x1a, version u16, checksum u16 — but real
    // writers (sox) place the first data block two bytes later, at 26; reading
    // at 24 sees a mid-checksum byte and off-by-2s every block end.
    i64 p = off + 26;
    i64 terminator = -1;
    int blocks = 0;
    while (p + 4 <= off + max && blocks < 2000000) {
        u8 type = s.byte(p);
        // Types 8/9 (new-format sound data) carry a 3-byte size; everything
        // else an u16. sox also pads every VOC with a variable junk tail the
        // spec does not define — a block that is not any known type marks the
        // real data's end, not a foreign file.
        int sizeBytes = (type == 8 || type == 9) ? 3 : 2;
        u32 size = 0;
        for (int k = 0; k < sizeBytes; k++)
            size |= (u32)s.byte(p + 1 + k) << (8 * k);
        if (type == 0) { terminator = p + 4; break; }
        if (type > 9 && type != 0x0A) { terminator = p; break; }
        if (size == 0 || p + 4 + (i64)size > off + max) break;
        p += 4 + (i64)size;
        blocks++;
    }
    if (blocks < 1 || terminator < 0) return -1;
    if (getenv("GHOST_DEBUG_VOC"))
        fprintf(stderr, "vVoc off=%lld blocks=%d term=%lld ret=%lld\n", (long long)off,
                blocks, (long long)terminator, (long long)(terminator - off));
    // sox leaves a ~9-byte junk tail after its last sound block that decodes
    // as no known VOC block type; the deleted file's true size includes it.
    // Absorb at most 16 bytes of residue, stopping at the first zero so the
    // zero padding that follows a carved file is never swallowed.
    i64 z = terminator;
    int taken = 0;
    while (taken < 16 && z < off + max) {
        taken++;
        if (s.byte(z++) == 0) break;
    }
    if (taken > 0 && taken <= 16) return z - off;
    return terminator - off;
}

// --- IVF (Intel Video Format) -----------------------------------------------
i64 vIvf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    if (h[0] != 'D' || h[1] != 'K' || h[2] != 'I' || h[3] != 'F') return -1;
    u16 hdrSize = s.le16(off + 6);
    if (hdrSize < 32 || hdrSize > 4096) return -1;
    u32 nframes = s.le32(off + 24);
    if (nframes == 0 || nframes > 2000000) return -1;
    i64 p = off + (i64)hdrSize;
    for (u32 f = 0; f < nframes; f++) {
        if (p + 12 > off + max) return -1;
        u32 frame = s.le32(p);
        if (frame == 0 || frame > 512 * MB) return -1;
        p += 12 + (i64)frame;
    }
    return (p <= off + max) ? p - off : -1;
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

// --- ASCII STL (bounded by the endsolid marker) -----------------------------
i64 vStlAscii(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    static const char* kLineTokens[] = {
        "facet normal", "solid ", "endsolid", "outer loop", "inner loop",
        "vertex", "endloop", "endfacet", "color", "sourcestatcode", "aoutstatcode"};
    i64 p = off;
    int facets = 0;
    while (p < off + max) {
        i64 q = p;
        while (q < off + max && (s.byte(q) == ' ' || s.byte(q) == '\t')) q++;
        auto tok = s.read(q, 13);
        // endsolid closes the file; its line end is the last byte.
        if (tok.size() >= 8 && std::memcmp(tok.data(), "endsolid", 8) == 0) {
            i64 e = q + 8;
            while (e < off + max && s.byte(e) != '\n') e++;
            return std::min<i64>(e + 1, off + max) - off;
        }
        bool known = false;
        for (const char* t : kLineTokens) {
            size_t n = strlen(t);
            if (tok.size() >= n && std::memcmp(tok.data(), t, n) == 0) { known = true; break; }
        }
        if (std::memcmp(tok.data(), "facet normal", 12) == 0) facets++;
        if (!known) break;                             // foreign line: not ours
        while (q < off + max && s.byte(q) != '\n') q++;
        if (q >= off + max) break;
        p = q + 1;
    }
    return (facets >= 1) ? p - off : -1;
}

// --- cpio (newc / crc / odc / binary) ---------------------------------------
i64 vCpio(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto hdr0 = s.read(off, 26);
    if (hdr0.size() < 26) return -1;
    auto oct = [&](i64 at, int n) -> i64 {
        i64 v = 0;
        for (int i = 0; i < n; i++) {
            u8 c = s.byte(at + i);
            if (c < '0' || c > '7') return -1;
            v = v * 8 + (c - '0');
        }
        return v;
    };
    auto hexn = [&](i64 at, int n) -> i64 {
        i64 v = 0;
        for (int i = 0; i < n; i++) {
            u8 c = s.byte(at + i);
            if (c >= '0' && c <= '9') v = v * 16 + (c - '0');
            else if (c >= 'a' && c <= 'f') v = v * 16 + (c - 'a' + 10);
            else if (c >= 'A' && c <= 'F') v = v * 16 + (c - 'A' + 10);
            else return -1;
        }
        return v;
    };
    bool newc = std::memcmp(hdr0.data(), "070701", 6) == 0 ||
                std::memcmp(hdr0.data(), "070702", 6) == 0;
    bool odc = std::memcmp(hdr0.data(), "070707", 6) == 0;
    bool bin = hdr0[0] == (u8)0xC7 && (hdr0[1] == (u8)0x71 || hdr0[1] == (u8)0x72);
    if (!newc && !odc && !bin) return -1;
    // newc/crc use a 110-byte header, GNU odc 76 bytes (the odd 11-digit
    // mtime/filesize fields), binary 26 bytes.
    const int hdrLen = bin ? 26 : (newc ? 110 : 76);
    i64 p = off;
    int entries = 0;
    while (p + hdrLen <= off + max && entries < 1000000) {
        auto h = s.read(p, hdrLen);
        if (h.size() < (size_t)hdrLen) break;
        i64 ns = -1, fs = -1;
        if (newc) {
            ns = hexn(p + 94, 8);
            fs = hexn(p + 54, 8);
        } else if (odc) {
            // GNU odc: namesize at +59 (6), filesize at +65 (11). The older
            // fixed-field odc (all 6-digit, namesize +48/filesize +54) is a
            // fallback only when GNU field decode fails.
            ns = oct(p + 59, 6);
            fs = oct(p + 65, 11);
            if (ns < 0 || fs < 0) {
                ns = oct(p + 48, 6);
                fs = oct(p + 54, 6);
            }
        } else {
            ns = s.le16(p + 20);
            fs = (i64)s.le16(p + 22) | ((i64)s.le16(p + 24) << 16);
        }
        if (ns < 1 || ns > 65536 || fs < 0 || fs > 4LL * GB) return -1;
        size_t want = (size_t)std::min<i64>(ns, 32);
        auto name = s.read(p + hdrLen, want);
        if (name.size() < want) return -1;
        bool trailer = ns >= 10 && std::memcmp(name.data(), "TRAILER!!!", 10) == 0;
        // newc/crc pad names and data to 4 bytes; binary to 2; odc is
        // unpadded, and its trailing block data is not aligned either.
        auto padUp = [&](i64 at, int align) -> i64 {
            i64 rel = at - off;
            i64 rem = rel % align;
            return rem ? (at + (align - rem)) : at;
        };
        if (trailer) {
            i64 q = p + hdrLen + ns;
            if (newc) q = padUp(q, 4);
            else if (bin) q = padUp(q, 2);
            // GNU cpio pads the archive out to a 512-byte block with zeros;
            // keep that slack so the whole written file is carved, but never
            // scan past the block boundary into what follows.
            i64 rem = (q - off) % 512;
            if (rem) {
                i64 z = q + (512 - rem);
                if (z <= off + max) {
                    bool zeroes = true;
                    for (i64 k = q; k < z && zeroes; k++) zeroes = s.byte(k) == 0;
                    if (zeroes) q = z;
                }
            }
            return q - off;
        }
        i64 q;
        if (odc) q = p + hdrLen + ns + fs;
        else {
            q = padUp(p + hdrLen + ns, newc ? 4 : 2);
            q = padUp(q + fs, newc ? 4 : 2);
        }
        if (q > off + max) break;
        p = q;
        entries++;
    }
    if (entries == 0) return -1;
    return p - off;
}

// --- MIDI ------------------------------------------------------------------
i64 vMidi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 hdrLen = s.be32(off + 4);
    if (hdrLen != 6) return -1;
    u16 tracks = s.be16(off + 10);
    if (tracks == 0 || tracks > 4096) return -1;
    i64 p = off + 14;
    int seen = 0;
    while (seen < tracks && p + 8 <= off + max) {
        auto t = s.read(p, 4);
        if (t.size() < 4 || std::memcmp(t.data(), "MTrk", 4) != 0) break;
        u32 len = s.be32(p + 4);
        if (len > 64 * MB) break;
        p += 8 + (i64)len;
        seen++;
    }
    if (seen == 0) return -1;
    return p - off;
}

// --- ZIP and every container built on it -----------------------------------
i64 vZip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // Accept only the End Of Central Directory whose central-directory pointer
    // and size add up to its own position — that identifies the EOCD belonging
    // to *this* archive rather than one from a neighbouring file.
    const i64 kStep = 1 * MB;
    const i64 kOverlap = 21;
    i64 base = 0;
    while (base < max) {
        i64 want = std::min(kStep, max - base);
        auto buf = s.read(off + base, want);
        if (buf.size() < 22) break;
        for (size_t i = 0; i + 22 <= buf.size(); i++) {
            if (!(buf[i] == 'P' && buf[i+1] == 'K' && buf[i+2] == 0x05 && buf[i+3] == 0x06))
                continue;
            u32 cdSize = (u32)buf[i+12] | (u32)buf[i+13] << 8 | (u32)buf[i+14] << 16 | (u32)buf[i+15] << 24;
            u32 cdOff  = (u32)buf[i+16] | (u32)buf[i+17] << 8 | (u32)buf[i+18] << 16 | (u32)buf[i+19] << 24;
            u16 comment = (u16)((u16)buf[i+20] | (u16)buf[i+21] << 8);
            i64 eocdPos = base + (i64)i;
            if ((i64)cdOff + (i64)cdSize != eocdPos) continue;
            i64 total = eocdPos + 22 + comment;
            return (total <= max) ? total : -1;
        }
        if ((i64)buf.size() < want) break;
        if (want <= kOverlap) break;
        base += want - kOverlap;
    }
    return -1;
}

// --- gzip: walk the deflate member chain with inflate. ---------------------
// The compressed stream has no length field, but inflate can verify the
// member end exactly: with windowBits | 16 zlib checks the CRC32 and ISIZE
// trailer itself, so a candidate that passes is a real gzip member of the
// reported length. Random data that merely starts with 1F 8B fails the
// deflate decoding within a few hundred bytes.
i64 vGzip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
#ifdef GHOST_HAVE_ZLIB
    const i64 kInBudget = 1 * 1024LL * 1024 * 1024;    // compressed bytes per member
    const i64 kOutBudget = 32 * 1024LL * 1024 * 1024;  // decompressed cap
    i64 pos = off;
    i64 outTotal = 0;
    std::vector<u8> buf;
    for (int member = 0; member < 64; member++) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15 + 16) != Z_OK) return -1;
        int rc = Z_OK;
        u8 out[64 * 1024];
        while (rc != Z_STREAM_END) {
            if (zs.avail_in == 0) {
                if (pos - off >= max || (i64)zs.total_in >= kInBudget) {
                    rc = Z_BUF_ERROR;
                    break;
                }
                i64 want = std::min<i64>(
                    64 * 1024,
                    std::min(max - (pos - off), kInBudget - (i64)zs.total_in));
                buf = s.read(pos, want);
                if (buf.empty()) {
                    // Input exhausted: one last inflate call lets zlib report
                    // a stream that ended flush against the read boundary.
                    zs.next_in = nullptr;
                    zs.avail_in = 0;
                    zs.next_out = out;
                    zs.avail_out = sizeof(out);
                    rc = inflate(&zs, Z_NO_FLUSH);
                    break;
                }
                zs.next_in = buf.data();
                zs.avail_in = (uInt)buf.size();
            }
            zs.next_out = out;
            zs.avail_out = sizeof(out);
            rc = inflate(&zs, Z_NO_FLUSH);
            outTotal += (i64)(sizeof(out) - zs.avail_out);
            if (outTotal > kOutBudget) { rc = Z_BUF_ERROR; break; }
            if (rc == Z_STREAM_ERROR || rc == Z_MEM_ERROR || rc == Z_DATA_ERROR) break;
        }
        i64 consumed = (i64)zs.total_in;
        bool ok = (rc == Z_STREAM_END);
        inflateEnd(&zs);
        if (!ok) return -1;
        pos += consumed;                               // trailer included
        if (pos - off > max) return -1;
        auto nx = s.read(pos, 2);                      // concatenated member?
        if (nx.size() < 2 || nx[0] != 0x1F || nx[1] != 0x8B) return pos - off;
    }
    return pos - off;
#else
    (void)s; (void)off; (void)max;
    return 0;
#endif
}

// --- bzip2 -----------------------------------------------------------------
// The stream is bit-packed, so the end-of-stream magic is not byte-aligned
// and cannot be located by scanning; decompression finds the exact end.
i64 vBzip2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
#ifdef GHOST_HAVE_BZIP2
    const i64 kInBudget = 1 * 1024LL * 1024 * 1024;
    const i64 kOutBudget = 32 * 1024LL * 1024 * 1024;
    auto h = s.read(off, 4);
    if (h.size() < 4 || h[0] != 'B' || h[1] != 'Z' || h[2] != 'h'
        || h[3] < '1' || h[3] > '9') return -1;
    bz_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (BZ2_bzDecompressInit(&zs, 0, 0) != BZ_OK) return -1;
    auto bzIn = [](bz_stream* z) { return (i64)z->total_in_hi32 << 32 | (u32)z->total_in_lo32; };
    i64 fed = 0;                 // bytes handed to the decompressor so far
    i64 outTotal = 0;
    int rc = BZ_OK;
    u8 out[64 * 1024];
    std::vector<u8> buf;
    while (rc != BZ_STREAM_END) {
        if (zs.avail_in == 0) {
            if (fed >= max || bzIn(&zs) >= kInBudget) {
                rc = BZ_UNEXPECTED_EOF;
                break;
            }
            i64 want = std::min<i64>(
                64 * 1024,
                std::min(max - fed, kInBudget - bzIn(&zs)));
            buf = s.read(off + fed, want);
            if (buf.empty()) {
                zs.next_in = nullptr;
                zs.avail_in = 0;
                zs.next_out = reinterpret_cast<char*>(out);
                zs.avail_out = sizeof(out);
                rc = BZ2_bzDecompress(&zs);
                break;
            }
            zs.next_in = reinterpret_cast<char*>(buf.data());
            zs.avail_in = (unsigned)buf.size();
            fed += (i64)buf.size();
        }
        zs.next_out = reinterpret_cast<char*>(out);
        zs.avail_out = sizeof(out);
        rc = BZ2_bzDecompress(&zs);
        outTotal += (i64)(sizeof(out) - zs.avail_out);
        if (outTotal > kOutBudget) { rc = BZ_UNEXPECTED_EOF; break; }
        if (rc != BZ_OK && rc != BZ_STREAM_END) break;
    }
    i64 consumed = bzIn(&zs);
    bool ok = (rc == BZ_STREAM_END);
    BZ2_bzDecompressEnd(&zs);
    if (!ok || consumed <= 0) return -1;
    return consumed;                             // EOS + CRC included
#else
    (void)s; (void)off; (void)max;
    return 0;
#endif
}

// --- xz --------------------------------------------------------------------
i64 vXz(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    static const u8 kFooter[2] = {'Y', 'Z'};
    const i64 kStep = 1 * MB;
    for (i64 base = 0; base < max; base += kStep - 16) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 12) break;
        for (size_t i = 0; i + 2 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, kFooter, 2) == 0 && base + (i64)i >= 12)
                return base + (i64)i + 2;
        }
        if ((i64)buf.size() < std::min(kStep, max - base)) break;
    }
    return 0;
}

// --- 7-Zip -----------------------------------------------------------------
i64 v7z(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    u64 nextHeaderOffset = 0, nextHeaderSize = 0;
    for (int i = 0; i < 8; i++) nextHeaderOffset |= (u64)h[12 + i] << (i * 8);
    for (int i = 0; i < 8; i++) nextHeaderSize |= (u64)h[20 + i] << (i * 8);
    i64 total = 32 + (i64)nextHeaderOffset + (i64)nextHeaderSize;
    if (total < 32 || total > max) return -1;
    return total;
}

// --- RAR -------------------------------------------------------------------
// RAR4 blocks carry a 16-bit size at +5. RAR5 headers are vint-coded:
// CRC32(4) + Header size (vint) + Header type (vint) + flags (vint) +
// [extra area size (vint)] + [data area size (vint)] + header data + data.
static i64 rar5Vint(ByteSource& s, i64 at, i64 base, i64 hi, int& width) {
    width = 0;
    u64 v = 0;
    for (int i = 0; i < 10; i++) {
        u8 b = s.byte(base + at + i);
        v |= (u64)(b & 0x7F) << (7 * i);
        width = i + 1;
        if (!(b & 0x80)) return (v <= (u64)hi) ? (i64)v : -1;
    }
    return -1;
}
i64 vRar(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 8);
    if (h.size() < 8) return -1;
    bool v5 = (h[6] == 0x01 && h[7] == 0x00);
    if (!v5) {
        i64 p = off + 7;
        int blocks = 0;
        while (p + 7 <= off + max && blocks < 100000) {
            u16 size = s.le16(p + 5);
            u8 type = s.byte(p + 2);
            if (size < 7) break;
            i64 add = 0;
            if (type == 0x74 || (s.le16(p + 3) & 0x8000)) add = s.le32(p + 7);
            p += size + add;
            blocks++;
            if (type == 0x7B) break;                // end-of-archive
        }
        if (blocks < 1) return -1;
        return p - off;
    }
    // RAR 5.0: walk header blocks to the End-of-archive header (type 5).
    // RAR reads nothing after it, so its end is the archive's end. Only the
    // size-bearing fields are consumed; block-specific fields are covered by
    // the Header size vint itself.
    i64 p = off + 8;
    int blocks = 0;
    while (p + 6 <= off + max && blocks < 1000000) {
        i64 hp = p - off;
        int w = 0;
        i64 hdrSize = rar5Vint(s, hp + 4, off, 2 * MB, w);
        if (hdrSize < 0 || w == 0) return -1;
        i64 q = hp + 4 + w;
        int tw = 0;
        i64 type = rar5Vint(s, q, off, 5, tw);
        if (type < 0 || tw == 0) return -1;
        q += tw;
        int fw = 0;
        i64 flags = rar5Vint(s, q, off, 0xFFFF, fw);
        if (flags < 0 || fw == 0) return -1;
        q += fw;
        if (flags & 0x0001) {                       // extra area: skip its size field
            int ew = 0;
            i64 extraSize = rar5Vint(s, q, off, 2 * MB, ew);
            if (extraSize < 0 || ew == 0) return -1;
            q += ew;
        }
        i64 dataSize = 0;
        if (flags & 0x0002) {                       // data area present
            int dw = 0;
            dataSize = rar5Vint(s, q, off, 64 * GB, dw);
            if (dataSize < 0 || dw == 0) return -1;
        }
        i64 end = hp + 4 + w + hdrSize + dataSize;
        if (end <= hp || end > max) return -1;
        p = off + end;
        blocks++;
        if (getenv("GHOST_DEBUG_RAR"))
            fprintf(stderr, "vRar5 @%lld size=%lld type=%lld flags=%lld data=%lld end=%lld\n",
                    (long long)hp, (long long)hdrSize, (long long)type,
                    (long long)flags, (long long)dataSize, (long long)end);
        if (type == 5) return end;                  // end-of-archive header
    }
    return -1;
}

// --- CAB -------------------------------------------------------------------
i64 vCab(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 8);
    if (size < 36 || (i64)size > max) return -1;
    return size;
}

// --- tar: walk 512-byte headers. -------------------------------------------
i64 vTar(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The "ustar" magic sits at +257 inside the first header block.
    i64 p = off;
    int members = 0;
    while (p + 512 <= off + max && members < 1000000) {
        auto h = s.read(p, 512);
        if (h.size() < 512) break;
        bool allZero = true;
        for (u8 c : h) if (c) { allZero = false; break; }
        if (allZero) break;                       // end-of-archive terminator
        if (std::memcmp(h.data() + 257, "ustar", 5) != 0) break;
        // size is an octal string at +124, 12 bytes
        u64 size = 0;
        for (int i = 124; i < 135; i++) {
            u8 c = h[i];
            if (c < '0' || c > '7') break;
            size = size * 8 + (u64)(c - '0');
        }
        p += 512 + (i64)((size + 511) / 512) * 512;
        members++;
    }
    if (members < 1) return -1;
    // Writers pad the archive to a record size (GNU tar and Python's
    // tarfile both default to 10 KiB). The file ends on that boundary —
    // everything beyond it (usually the next file's area) is foreign, so
    // never walk the zero run looking for it.
    i64 end = p;
    i64 rel = end - off;
    if (rel % 10240 != 0) {
        i64 rounded = off + ((rel / 10240) + 1) * 10240;
        if (rounded <= off + max && rounded > end) {
            // Only extend when the rounding really is archive padding.
            bool zeroOk = true;
            for (i64 q = end; q < rounded && zeroOk; q++)
                if (s.byte(q)) zeroOk = false;
            if (zeroOk) end = rounded;
        }
    }
    return end - off;
}

// --- ar / deb --------------------------------------------------------------
i64 vAr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 8;
    int members = 0;
    while (p + 60 <= off + max && members < 100000) {
        auto h = s.read(p, 60);
        if (h.size() < 60 || h[58] != 0x60 || h[59] != 0x0A) break;
        u64 size = 0;
        for (int i = 48; i < 58; i++) {
            u8 c = h[i];
            if (c < '0' || c > '9') break;
            size = size * 10 + (u64)(c - '0');
        }
        p += 60 + (i64)size + ((size & 1) ? 1 : 0);
        members++;
    }
    if (members < 1) return -1;
    return p - off;
}

// --- SQLite ----------------------------------------------------------------
i64 vSqlite(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 pageSizeRaw = s.be16(off + 16);
    i64 pageSize = (pageSizeRaw == 1) ? 65536 : pageSizeRaw;
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1))) return -1;
    u32 pageCount = s.be32(off + 28);
    if (pageCount == 0 || (i64)pageCount * pageSize > max) {
        // A file still open when it was deleted may have a stale page count.
        return 0;
    }
    return (i64)pageCount * pageSize;
}

// --- ELF -------------------------------------------------------------------
i64 vElf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 64);
    if (h.size() < 52) return -1;
    u8 cls = h[4], data = h[5];
    if ((cls != 1 && cls != 2) || (data != 1 && data != 2)) return -1;
    bool be = data == 2;
    bool x64 = cls == 2;
    auto rd16 = [&](i64 o) { return be ? s.be16(off + o) : s.le16(off + o); };
    auto rd32 = [&](i64 o) { return be ? s.be32(off + o) : s.le32(off + o); };
    auto rd64 = [&](i64 o) -> u64 {
        auto v = s.read(off + o, 8);
        if (v.size() < 8) return 0;
        u64 r = 0;
        if (be) for (int i = 0; i < 8; i++) r = (r << 8) | v[i];
        else    for (int i = 7; i >= 0; i--) r = (r << 8) | v[i];
        return r;
    };
    i64 furthest = x64 ? 64 : 52;
    u64 shoff = x64 ? rd64(0x28) : rd32(0x20);
    u16 shentsize = rd16(x64 ? 0x3A : 0x2E);
    u16 shnum = rd16(x64 ? 0x3C : 0x30);
    u64 phoff = x64 ? rd64(0x20) : rd32(0x1C);
    u16 phentsize = rd16(x64 ? 0x36 : 0x2A);
    u16 phnum = rd16(x64 ? 0x38 : 0x2C);
    if (shnum && shentsize) furthest = std::max<i64>(furthest, (i64)shoff + (i64)shnum * shentsize);
    if (phnum && phentsize) furthest = std::max<i64>(furthest, (i64)phoff + (i64)phnum * phentsize);
    // Section contents can extend past the table.
    for (u16 i = 0; i < shnum && i < 4096; i++) {
        i64 e = (i64)shoff + (i64)i * shentsize;
        if (e + shentsize > max) break;
        u32 type = x64 ? (be ? s.be32(off + e + 4) : s.le32(off + e + 4))
                       : (be ? s.be32(off + e + 4) : s.le32(off + e + 4));
        if (type == 8) continue;                              // SHT_NOBITS occupies no file space
        u64 sOff = x64 ? rd64(e + 0x18) : rd32(e + 0x10);
        u64 sSize = x64 ? rd64(e + 0x20) : rd32(e + 0x14);
        if (sOff + sSize <= (u64)max) furthest = std::max<i64>(furthest, (i64)(sOff + sSize));
    }
    if (furthest > max) return -1;
    return furthest;
}

// --- PE / EXE / DLL --------------------------------------------------------
i64 vPe(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 lfanew = s.le32(off + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x10000) return -1;
    auto sig = s.read(off + lfanew, 4);
    if (sig.size() < 4 || sig[0] != 'P' || sig[1] != 'E' || sig[2] || sig[3]) return -1;
    i64 pe = (i64)lfanew;
    u16 sections = s.le16(off + pe + 6);
    u16 optSize = s.le16(off + pe + 20);
    if (sections == 0 || sections > 4096) return -1;
    i64 table = pe + 24 + optSize;
    i64 furthest = table + (i64)sections * 40;
    for (u16 i = 0; i < sections; i++) {
        i64 e = table + (i64)i * 40;
        if (e + 40 > max) return -1;
        u32 rawSize = s.le32(off + e + 16);
        u32 rawPtr  = s.le32(off + e + 20);
        if (rawPtr && rawSize) furthest = std::max<i64>(furthest, (i64)rawPtr + rawSize);
    }
    if (furthest > max) return -1;
    return furthest;
}

// --- Mach-O ----------------------------------------------------------------
i64 vMachO(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 magic = s.le32(off);
    bool x64 = (magic == 0xFEEDFACF);
    bool be = (magic == 0xCEFAEDFE || magic == 0xCFFAEDFE);
    auto rd32 = [&](i64 o) { return be ? s.be32(off + o) : s.le32(off + o); };
    u32 ncmds = rd32(16);
    u32 sizeofcmds = rd32(20);
    if (ncmds == 0 || ncmds > 8192) return -1;
    i64 hdr = x64 ? 32 : 28;
    i64 furthest = hdr + sizeofcmds;
    i64 p = hdr;
    for (u32 i = 0; i < ncmds; i++) {
        if (p + 8 > max) break;
        u32 cmd = rd32(p);
        u32 cmdSize = rd32(p + 4);
        if (cmdSize < 8 || p + cmdSize > max) break;
        if (cmd == 0x01 || cmd == 0x19) {                     // LC_SEGMENT / _64
            i64 fileOff = x64 ? (i64)((u64)rd32(p + 40) | ((u64)rd32(p + 44) << 32))
                              : (i64)rd32(p + 32);
            i64 fileSize = x64 ? (i64)((u64)rd32(p + 48) | ((u64)rd32(p + 52) << 32))
                               : (i64)rd32(p + 36);
            if (fileOff >= 0 && fileSize > 0) furthest = std::max(furthest, fileOff + fileSize);
        }
        p += cmdSize;
    }
    if (furthest > max) return -1;
    return furthest;
}

// --- pcap ------------------------------------------------------------------
i64 vPcap(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 magic = s.le32(off);
    bool swapped = (magic == 0xD4C3B2A1 || magic == 0x4D3CB2A1);
    bool nano = (magic == 0xA1B23C4D || magic == 0x4D3CB2A1);
    (void)nano;
    auto rd32 = [&](i64 o) { return swapped ? s.be32(off + o) : s.le32(off + o); };
    u32 snaplen = rd32(16);
    if (snaplen == 0 || snaplen > 1 << 22) return -1;
    i64 p = 24;
    int packets = 0;
    while (p + 16 <= max && packets < 10000000) {
        u32 inclLen = rd32(p + 8);
        u32 origLen = rd32(p + 12);
        if (inclLen == 0 || inclLen > snaplen || origLen < inclLen) break;
        p += 16 + (i64)inclLen;
        packets++;
    }
    if (packets < 1) return -1;
    return p;
}

// --- pcapng ----------------------------------------------------------------
i64 vPcapng(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 bom = s.le32(off + 8);
    bool swapped = (bom == 0x4D3C2B1A);
    auto rd32 = [&](i64 o) { return swapped ? s.be32(off + o) : s.le32(off + o); };
    if (bom != 0x1A2B3C4D && bom != 0x4D3C2B1A) return -1;
    i64 p = 0;
    int blocks = 0;
    while (p + 12 <= max && blocks < 10000000) {
        u32 total = rd32(p + 4);
        if (total < 12 || (total & 3) || p + (i64)total > max) break;
        p += total;
        blocks++;
    }
    if (blocks < 1) return -1;
    return p;
}

// --- Windows event log (EVTX) ---------------------------------------------
i64 vEvtx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 hdrSize = s.le16(off + 0x28);
    if (hdrSize < 4096) return -1;
    u16 chunkCount = s.le16(off + 0x2A);
    if (chunkCount == 0) return -1;
    i64 total = (i64)hdrSize + (i64)chunkCount * 65536;
    if (total > max) return -1;
    auto c0 = s.read(off + hdrSize, 8);
    if (c0.size() < 8 || c0[0] != 'E' || c0[1] != 'l' || c0[2] != 'f'
        || c0[3] != 'C' || c0[4] != 'h' || c0[5] != 'n' || c0[6] != 'k') return -1;
    return total;
}

// --- Windows registry hive -------------------------------------------------
i64 vRegf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 hbinsSize = s.le32(off + 0x28);
    if (hbinsSize == 0 || (i64)hbinsSize + 4096 > max) return -1;
    return 4096 + (i64)hbinsSize;
}

// --- OLE2 compound file (doc/xls/ppt/msg) ----------------------------------
i64 vOle2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 sectorShift = s.le16(off + 30);
    if (sectorShift < 7 || sectorShift > 12) return -1;
    i64 sectorSize = (i64)1 << sectorShift;
    u32 numFat = s.le32(off + 44);
    if (numFat == 0 || numFat > 100000) return -1;
    // The highest sector referenced by the FAT bounds the file.
    i64 highest = 0;
    int fatSectorsRead = 0;
    for (int i = 0; i < 109 && fatSectorsRead < 512; i++) {
        u32 fatSect = s.le32(off + 76 + (i64)i * 4);
        if (fatSect == 0xFFFFFFFF || fatSect == 0xFFFFFFFE) break;
        i64 fatOff = (i64)(fatSect + 1) * sectorSize;
        if (fatOff + sectorSize > max) break;
        auto fat = s.read(off + fatOff, sectorSize);
        for (size_t k = 0; k + 4 <= fat.size(); k += 4) {
            u32 v = (u32)fat[k] | (u32)fat[k+1] << 8 | (u32)fat[k+2] << 16 | (u32)fat[k+3] << 24;
            if (v == 0xFFFFFFFF) continue;                   // free
            i64 idx = (i64)(fatSectorsRead * (sectorSize / 4)) + (i64)(k / 4);
            highest = std::max(highest, idx);
        }
        fatSectorsRead++;
    }
    if (highest <= 0) return -1;
    i64 total = (highest + 2) * sectorSize;
    if (total > max) return -1;
    return total;
}

// --- PDF: find %%EOF, but only within 1 MB after the ``startxref`` line -----
// -- (a ``startxref`` that byte-ranges back to %%EOF is part of an old
// -- incremental update; the PDF proper never continues past its final EOF,
// -- so bounding the scan here avoids eating arbitrary trailing data).
i64 vPdf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    const i64 kStep = 1 * MB;
    auto skipEol = [&](i64 rel) {
        if (rel <= 0 || rel >= max) return rel;
        auto tail = s.read(off + rel, 2);
        if (!tail.empty() && (tail[0] == '\r' || tail[0] == '\n')) rel++;
        if (tail.size() > 1 && tail[0] == '\r' && tail[1] == '\n') rel++;
        return rel;
    };
    i64 startxref = -1;
    for (i64 base = 0; base < max; base += kStep - 9) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 9) break;
        for (size_t i = 0; i + 9 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, "startxref", 9) == 0) {
                startxref = base + (i64)i + 9;
                break;
            }
        }
        if (startxref >= 0 || (i64)buf.size() < std::min(kStep, max - base)) break;
    }
    if (startxref < 0) {
        // Minimal or truncated producers emit no xref table at all; their only
        // reliable end marker is the first %%EOF, which closes the trailer.
        for (i64 base = 0; base < max; base += kStep - 5) {
            auto buf = s.read(off + base, std::min(kStep, max - base));
            if (buf.size() < 5) break;
            for (size_t i = 0; i + 5 <= buf.size(); i++) {
                if (std::memcmp(buf.data() + i, "%%EOF", 5) == 0)
                    return skipEol(base + (i64)i + 5);
            }
            if ((i64)buf.size() < std::min(kStep, max - base)) break;
        }
        return -1;
    }
    const i64 scanEnd = std::min(max, startxref + 1 * MB);
    i64 lastEof = -1;
    for (i64 base = startxref; base >= 0 && base < scanEnd; base += kStep - 8) {
        auto buf = s.read(off + base, std::min(kStep, scanEnd - base));
        if (buf.size() < 5) break;
        for (size_t i = 0; i + 5 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, "%%EOF", 5) == 0) lastEof = base + (i64)i + 5;
        }
        if ((i64)buf.size() < std::min(kStep, scanEnd - base)) break;
    }
    if (lastEof < 0) return -1;
    return skipEol(lastEof);
}

// --- Plain text ------------------------------------------------------------
i64 vText(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
    i64 p = 0;
    const i64 kStep = 64 * KB;
    i64 limit = std::min(max, spec.max_size);
    while (p < limit) {
        auto buf = s.read(off + p, std::min(kStep, limit - p));
        if (buf.empty()) break;
        for (size_t i = 0; i < buf.size(); i++) {
            u8 c = buf[i];
            bool ok = (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r' || c >= 0x80;
            if (!ok) return (p + (i64)i >= spec.min_size) ? p + (i64)i : -1;
        }
        p += (i64)buf.size();
    }
    return p >= spec.min_size ? p : -1;
}

// --- Fonts -----------------------------------------------------------------
i64 vSfnt(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 numTables = s.be16(off + 4);
    // Real fonts have on the order of ten to forty tables. The searchRange /
    // entrySelector / rangeShift trio must also agree with numTables, which is
    // what separates a genuine font from a run of zeroes that happens to start
    // with 00 01 00 00.
    if (numTables < 3 || numTables > 128) return -1;
    u16 searchRange = s.be16(off + 6);
    u16 entrySelector = s.be16(off + 8);
    u16 expectedSel = 0;
    while ((1u << (expectedSel + 1)) <= numTables) expectedSel++;
    if (entrySelector != expectedSel) return -1;
    if (searchRange != (u16)((1u << expectedSel) * 16)) return -1;

    const i64 dirEnd = 12 + (i64)numTables * 16;
    i64 furthest = dirEnd;
    bool sawRequired = false;
    for (u16 i = 0; i < numTables; i++) {
        i64 e = 12 + (i64)i * 16;
        auto tag = s.read(off + e, 4);
        if (tag.size() < 4) return -1;
        for (u8 c : tag)
            if (c < 0x20 || c > 0x7E) return -1;             // tags are printable ASCII
        if (std::memcmp(tag.data(), "head", 4) == 0 || std::memcmp(tag.data(), "cmap", 4) == 0 ||
            std::memcmp(tag.data(), "glyf", 4) == 0 || std::memcmp(tag.data(), "CFF ", 4) == 0)
            sawRequired = true;
        u32 tOff = s.be32(off + e + 8);
        u32 tLen = s.be32(off + e + 12);
        if (tOff < (u32)dirEnd) return -1;                    // tables follow the directory
        if ((i64)tOff + tLen > max) return -1;
        furthest = std::max<i64>(furthest, (i64)tOff + tLen);
    }
    if (!sawRequired) return -1;
    return furthest;
}

i64 vWoff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 length = s.be32(off + 8);
    if (length < 44 || (i64)length > max) return -1;
    return length;
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

// --- WASM ------------------------------------------------------------------
i64 vWasm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 4) != 1) return -1;
    i64 p = 8;
    int sections = 0;
    while (p < max && sections < 4096) {
        u8 id = s.byte(off + p);
        if (id > 13) break;
        // LEB128 section length — peek without consuming so a zero-length
        // section (padding after the last real section) does not inflate the
        // carved size.
        i64 leb = p + 1;
        u64 len = 0;
        int shift = 0;
        bool done = false;
        while (leb < max && shift < 35) {
            u8 b = s.byte(off + leb++);
            len |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) { done = true; break; }
            shift += 7;
        }
        if (!done || shift >= 35) break;      // unterminated LEB -> not ours
        if (len == 0) break;                  // empty section: stop, not run
        p = leb;
        if (p - 8 + (i64)len > max) break;
        p += (i64)len;
        sections++;
    }
    if (sections < 1) return -1;
    return p;
}


// --- TTF Collection: ttcf + per-font sfnt table directory --------------------
i64 vTtc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.be32(off + 4);
    if (ver != 0x00010000 && ver != 0x00020000) return -1;
    u32 nfonts = s.be32(off + 8);
    if (nfonts == 0 || nfonts > 100000) return -1;
    const i64 end = off + max;
    i64 highest = -1;
    for (u32 f = 0; f < nfonts; f++) {
        u32 foff = s.be32(off + 12 + 4 * f);
        if ((i64)foff > end) return -1;
        u16 numTables = s.be16(off + foff + 4);
        if (numTables == 0 || numTables > 4096) return -1;
        for (u16 t = 0; t < numTables; t++) {
            i64 toff = off + foff + 12 + 16 * t;
            if (toff + 16 > end) return -1;
            u32 eoff = s.be32(toff + 8);
            u32 elen = s.be32(toff + 12);
            highest = std::max(highest, (i64)eoff + elen);
        }
    }
    if (highest < 0) return -1;
    if (highest > end) return -1;
    return highest;
}

// --- Java class ------------------------------------------------------------
// Full structural walk: constant pool, interfaces, fields, methods, class
// attributes. RESTRICTED class files are far too small for a real class (the
// parser needs at least the header); the walk ends exactly at the last class
// attribute, which is the file's true length — javac emits nothing after it.
i64 vClass(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 minor = s.be16(off + 4);
    u16 major = s.be16(off + 6);
    (void)minor;
    if (major < 45 || major > 80) return -1;
    u16 cpCount = s.be16(off + 8);
    if (cpCount < 2 || cpCount > 65534) return -1;
    auto rd16 = [&](i64 p) { return s.be16(off + p); };
    auto rd32 = [&](i64 p) { return s.be32(off + p); };
    i64 p = 10;
    // Constant pool: a UTF8 entry self-describes; long/double take two slots.
    for (u16 ci = 1; ci < cpCount; ci++) {
        if (p + 1 > max) return -1;
        u8 tag = s.byte(off + p);
        p += 1;
        switch (tag) {
            case 1: {                               // Utf8: u16 len + bytes
                if (p + 2 > max) return -1;
                u16 n = rd16(p);
                p += 2;
                if (p + (i64)n > max) return -1;
                p += n;
                break;
            }
            case 3: case 4: case 9: case 10: case 11:
            case 12: case 17: case 18:              // 4-byte payloads
                p += 4;
                break;
            case 5: case 6:                         // long/double: 8 + 2 slots
                p += 8;
                ci++;
                break;
            case 7: case 8: case 16: case 19: case 20:
                p += 2;
                break;
            case 15:                                // method handle: 1 + 2
                p += 3;
                break;
            default:
                return -1;
        }
        if (p > max) return -1;
    }
    if (p + 8 > max) return -1;
    p += 6;                                         // access, this, super
    u16 ifaces = rd16(p);
    p += 2;
    if (p + 2 * (i64)ifaces > max) return -1;
    p += 2 * (i64)ifaces;
    auto attrs = [&](i64 at) -> i64 {
        if (at + 2 > max) return -1;
        u16 n = rd16(at);
        at += 2;
        for (u16 i = 0; i < n; i++) {
            if (at + 6 > max) return -1;
            u32 len = rd32(at + 2);
            at += 6;
            if ((i64)len > max - at) return -1;
            at += len;
        }
        return at;
    };
    // fields, methods: each member is a 6-byte header (access, name, desc)
    // followed by its own attribute table.
    for (int sec = 0; sec < 2; sec++) {
        if (p + 2 > max) return -1;
        u16 n = rd16(p);
        p += 2;
        if (p + 6 * (i64)n > max) return -1;
        for (u16 i = 0; i < n; i++) {
            p += 6;                                 // access, name, desc
            p = attrs(p);
            if (p < 0) return -1;
        }
    }
    // Class attributes follow directly: count then plain attribute frames.
    p = attrs(p);
    return p;
}

// --- DEX -------------------------------------------------------------------
i64 vDex(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 32);
    if (size < 112 || (i64)size > max) return -1;
    return size;
}

// --- QCOW2 -----------------------------------------------------------------
// Walks the real qcow2 layout: header, L1 table, each L2 table, the refcount
// table and its blocks, and the snapshot list. The file ends at the last
// cluster any of those refer to. (In a raw carved file every pointer lies
// below the true file size, so the walk is bounded and honest.)
i64 vQcow(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 72);
    if (b.size() < 72) return -1;
    if (b[0] != 'Q' || b[1] != 'F' || b[2] != 'I' || b[3] != 0xfb) return -1;
    auto be32v = [&](const u8* p) {
        return (u32)p[0] << 24 | (u32)p[1] << 16 | (u32)p[2] << 8 | p[3];
    };
    auto be64v = [&](const u8* p) {
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = v << 8 | p[k];
        return v;
    };
    u32 version = be32v(b.data() + 4);
    if (version != 2 && version != 3) return -1;
    if (version == 3) {
        u32 hsize = be32v(b.data() + 68);
        if (hsize != 0 && hsize < 104) return -1;   // writers may leave 0
    }
    u32 clusterBits = be32v(b.data() + 20);
    if (clusterBits < 9 || clusterBits > 21) return -1;
    const u64 cluster = 1ULL << clusterBits;
    if (be64v(b.data() + 24) == 0) return -1;   // disk size must be nonzero
    u64 l1Off = be64v(b.data() + 40), l1Size = be32v(b.data() + 36);
    u64 refcOff = be64v(b.data() + 48), refcClust = be32v(b.data() + 56);
    u64 snapOff = be64v(b.data() + 64), snapCount = be32v(b.data() + 60);
    u64 backOff = be64v(b.data() + 8), backSize = be32v(b.data() + 16);
    auto endOf = [&](u64 p, u64 len) -> i64 {
        if (p == 0 || len == 0) return 0;
        if (p >= (u64)max) return max;
        u64 e = p + len;
        return e >= (u64)max ? max : (i64)e;
    };
    i64 end = endOf(refcOff, refcClust * cluster);
    end = std::max(end, endOf(backOff, backSize));
    // The L1 table itself is part of the file even when no L2 entry refers
    // beyond it (qemu sparsifies exactly this way: the L1 cluster is written
    // last, at the physical end of the image).
    if (l1Off > 0 && l1Off < (u64)max && l1Size > 0 && (i64)l1Size * 8 <= max - (i64)l1Off)
        end = std::max(end, endOf(l1Off, (i64)l1Size * 8));
    if (snapCount <= 0x10000) end = std::max(end, endOf(snapOff, snapCount * 184));
    if (l1Size > 0 && l1Off == 0) return -1;
    if (l1Size > 0x100000) l1Size = 0x100000;   // don't chase absurd tables
    auto l1 = s.read(off + (i64)l1Off, std::min<i64>((i64)l1Size * 8, max - (i64)l1Off));
    if (l1.size() < (size_t)l1Size * 8) l1Size = (u32)(l1.size() / 8);
    for (u32 i = 0; i < l1Size; i++) {
        u64 e = be64v(l1.data() + i * 8);
        if (e == 0) continue;
        u64 l2Off = (e >> 9) & 0x3FFFFFFFFFFFFFULL;   // bits 9..62 = cluster addr
        if (l2Off == 0 || l2Off * cluster >= (u64)max) continue;
        end = std::max(end, endOf(l2Off * cluster, cluster));
        auto l2 = s.read(off + (i64)(l2Off * cluster), cluster);
        if (l2.size() < 8) continue;
        size_t n = std::min<size_t>(cluster / 8, l2.size() / 8);
        for (size_t j = 0; j < n; j++) {
            u64 d = be64v(l2.data() + j * 8);
            if (d == 0) continue;
            u64 dOff = (d >> 9) & 0x3FFFFFFFFFFFFFULL;
            if (dOff == 0 || dOff * cluster >= (u64)max) continue;
            end = std::max(end, endOf(dOff * cluster, cluster));
        }
    }
    if (refcOff && refcClust && refcClust < 0x10000) {
        auto rt = s.read(off + (i64)refcOff, std::min<i64>((i64)(refcClust * cluster / 8) * 8, max - (i64)refcOff));
        size_t n = std::min<size_t>(rt.size() / 8, (size_t)(refcClust * cluster / 8));
        for (size_t j = 0; j < n; j++) {
            u64 e = be64v(rt.data() + j * 8);
            if (e == 0) continue;
            // Refcount table entries are byte offsets of refcount blocks.
            u64 bOff = e;
            if (bOff == 0 || bOff >= (u64)max) continue;
            end = std::max(end, endOf(bOff, cluster));
        }
    }
    if (end < 512) return -1;
    return end;
}

// --- VHD: the footer "conectix" copy lies at the end of the file itself, so
// the header candidate scans forward for the nearest valid footer within it.
// (Scanning the tail of the extent cannot work: the extent usually extends
// well past the file's end.) The footer's own 8-byte Current Size and the
// copy's position both describe the file; the position is authoritative.
i64 vVhd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 512 + 512) return -1;
    i64 scanEnd = std::min<i64>(max, 512LL * 1024 * 1024);
    i64 pos = 512;
    while (pos + 512 <= scanEnd) {
        auto b = s.read(off + pos, 16);
        if (b.size() < 8) break;
        bool isFooter = std::memcmp(b.data(), "conectix", 8) == 0;
        if (isFooter) {
            // File format version: footer bytes 12..15 = 0x00010000.
            u16 hi = (u16)(s.byte(off + pos + 12) << 8 | s.byte(off + pos + 13));
            if (hi == 0x0001) {
                i64 fileSize = pos + 512;
                if (fileSize > max) return -1;
                return fileSize;
            }
        }
        pos += 512;
    }
    return -1;
}

// --- VHDX: validated against the real layout -------------------------------
// -- File identifier + one of the two valid headers (signature + version) +
// -- the region table at 192 KiB (count field at +8, entries at +16) + the
// -- BAT extent walk. The length is the furthest cluster any location table
// -- refers to, exactly like the qcow2 walk above.
i64 vVhdx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto sig = s.read(off, 8);
    if (sig.size() < 8 || std::memcmp(sig.data(), "vhdxfile", 8) != 0) return -1;
    i64 hdr = -1;
    for (i64 h : {0x10000LL, 0x20000LL}) {
        if (h + 84 > max) continue;
        auto b = s.read(off + h, 84);
        if (b.size() < 84 || std::memcmp(b.data(), "head", 4) != 0) continue;
        u16 logVer = (u16)(b[68] | (u16)b[69] << 8);
        u16 ver = (u16)(b[70] | (u16)b[71] << 8);
        if (ver != 1 && ver != 16) continue;   // 1 = spec, 16 = qemu's writer
        if (logVer > 1) continue;
        hdr = h;
        break;
    }
    if (hdr < 0) return -1;
    i64 end = 0x30000 + 0x10000;   // at least through the region table
    auto rt = s.read(off + 0x30000, 16 + 2047 * 32);
    if (rt.size() < 20 || std::memcmp(rt.data(), "regi", 4) != 0) return -1;
    u32 count = (u32)rt[8] | (u32)rt[9] << 8 | (u32)rt[10] << 16 | (u32)rt[11] << 24;
    if (count < 1 || count > 2047) return -1;
    u64 batOff = 0, batLen = 0, metaOff = 0;
    bool hasMeta = false;
    for (u32 i = 0; i < count; i++) {
        const u8* e = rt.data() + 16 + i * 32;
        u64 fo = 0;
        for (int k = 0; k < 8; k++) fo = fo << 8 | e[16 + k];
        u32 len = (u32)e[27] | (u32)e[26] << 8 | (u32)e[25] << 16 | (u32)e[24] << 24;
        if (fo == 0 || len == 0) continue;
        // Known region GUIDs: BAT and Metadata Region (MS GUID byte order).
        static const u8 kBATGuid[16]   = {0x66,0x77,0xc2,0x2d,0x23,0xf6,0x00,0x42,
                                          0x9d,0x64,0x11,0x5e,0x9b,0xfd,0x4a,0x08};
        static const u8 kMetaGuid[16]  = {0x06,0xa2,0x7c,0x8b,0x90,0x47,0x9a,0x4b,
                                          0xb8,0xfe,0x57,0x5f,0x05,0x0f,0x88,0x6e};
        if (std::memcmp(e, kBATGuid, 16) == 0) { batOff = fo; batLen = len; }
        if (std::memcmp(e, kMetaGuid, 16) == 0) { metaOff = fo; hasMeta = true; }
        u64 rEnd = fo + len;
        if (rEnd >= (u64)max) rEnd = (u64)max;
        if ((i64)rEnd > end) end = (i64)rEnd;
    }
    // Read the block size from the File Parameters metadata item so we know
    // where the data region starts (aligned up to a block from the end of the
    // region table extents) and how big fully-present BAT blocks are.
    u64 blockSize = 0;
    if (hasMeta && metaOff < (u64)max) {
        auto md = s.read(off + (i64)metaOff, 32 + 2047 * 32);
        if (md.size() >= 32 && std::memcmp(md.data(), "metadata", 8) == 0) {
            u16 mcnt = (u16)(md[10] | (u16)md[11] << 8);
            static const u8 kFileParamGuid[16] = {0x37,0x67,0xa1,0xca,0x36,0xfa,0x43,0x4d,
                                                  0xb3,0xb6,0x33,0xf0,0xaa,0x44,0xe7,0x6b};
            for (u16 i = 0; i < mcnt && 32 + (u32)i * 32 + 28 <= md.size(); i++) {
                const u8* e = md.data() + 32 + i * 32;
                if (std::memcmp(e, kFileParamGuid, 16) != 0) continue;
                u32 rel = (u32)e[16] | (u32)e[17] << 8 | (u32)e[18] << 16 | (u32)e[19] << 24;
                u32 ln = (u32)e[20] | (u32)e[21] << 8 | (u32)e[22] << 16 | (u32)e[23] << 24;
                if (ln < 4 || rel + 4 > (u64)max - metaOff) continue;
                auto pb = s.read(off + (i64)metaOff + rel, 4);
                if (pb.size() < 4) continue;
                u64 bs = (u64)pb[0] | (u64)pb[1] << 8 | (u64)pb[2] << 16 | (u64)pb[3] << 24;
                if (bs >= 1024 * 1024 && bs <= 256ULL * 1024 * 1024) blockSize = bs;
                break;
            }
        }
    }
    // Payload blocks are appended 1 MiB-aligned past the header/region area,
    // and the data region starts on a block-size boundary there.
    if (blockSize) {
        u64 dataBase = ((u64)end + blockSize - 1) / blockSize * blockSize;
        if (dataBase > (u64)end && dataBase < (u64)max) end = (i64)dataBase;
    }
    // Walk the BAT: 64-bit entries, low 3 bits = block state
    // (6 = PAYLOAD_BLOCK_FULLY_PRESENT), remaining bits = 1 MiB-aligned byte
    // offset of the payload block (masked by 0xFFFFFFFFFFF00000).
    if (batOff && batLen && batOff < (u64)max && blockSize) {
        i64 n = std::min<i64>((i64)(batLen / 8), max - (i64)batOff);
        for (i64 i = 0; i < n; i += 2048) {
            auto blk = s.read(off + (i64)batOff + i, std::min<i64>(16384, n - i));
            if (blk.size() < (size_t)std::min<i64>(16384, n - i)) break;
            for (size_t j = 0; j + 8 <= blk.size(); j += 8) {
                u64 e = 0;
                for (int k = 7; k >= 0; k--) e = e << 8 | blk[j + k];
                if ((e & 7) != 6) continue;      // FULLY_PRESENT only
                u64 cl = e & 0xFFFFFFFFFFF00000ULL;
                if (cl == 0 || cl >= (u64)max) continue;
                i64 cEnd = (i64)std::min<u64>(cl + blockSize, (u64)max);
                if (cEnd > end) end = cEnd;
            }
        }
    }
    return end;
}

// --- ISO9660: PVD at sector 16; file size = volume space * block size ------
i64 vIso(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off + 32768, 2048);
    if (b.size() < 134) return -1;
    if (std::memcmp(b.data() + 1, "CD001", 5) != 0) return -1;
    if (b[6] != 1) return -1;                       // PVD (type 1, not terminator)
    u16 block = (u16)b[128] | (u16)b[129] << 8;
    if (block != 512 && block != 1024 && block != 2048 && block != 4096) return -1;
    u64 vol = (u64)b[80] | (u64)b[81] << 8 | (u64)b[82] << 16 | (u64)b[83] << 24;
    if (vol < 16) return -1;
    u64 size = vol * block;
    if (size > (u64)max) size = (u64)max;
    if (size < 2048) return -1;
    return (i64)size;
}

// --- VDI: QEMU's dynamic disk header -----------------------------------------
i64 vVdi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 512);
    if (b.size() < 512) return -1;
    static const char* kMagic[] = {
        "<<< Oracle VM VirtualBox Disk Image >>>",
        "<<< QEMU VM Virtual Disk Image >>>",
        nullptr};
    bool magicOk = false;
    for (int m = 0; kMagic[m]; m++)
        if (std::memcmp(b.data(), kMagic[m], std::strlen(kMagic[m])) == 0) { magicOk = true; break; }
    if (!magicOk) return -1;
    auto le32v = [&](u32 o) {
        return (u32)b[o] | (u32)b[o + 1] << 8 | (u32)b[o + 2] << 16 | (u32)b[o + 3] << 24;
    };
    auto be32v = [&](u32 o) {
        return (u32)b[o] << 24 | (u32)b[o + 1] << 16 | (u32)b[o + 2] << 8 | b[o + 3];
    };
    auto le64v = [&](u32 o) {
        u64 v = 0;
        for (int k = 0; k < 8; k++) v |= (u64)b[o + k] << (8 * k);
        return v;
    };
    auto be64v = [&](u32 o) {
        u64 v = 0;
        for (int k = 0; k < 8; k++) v = v << 8 | b[o + k];
        return v;
    };
    // qemu/block/vdi.c header (all fields little-endian): signature @0x40,
    // version @0x44, header_size @0x48, image_type @0x4c, flags @0x50,
    // description [256] @0x54, offset_bmap @0x154, offset_data @0x158,
    // disk_size @0x170, block_size @0x178, blocks_in_image @0x180,
    // blocks_allocated @0x184.
    u32 sig = le32v(0x40);
    if (sig != 0xbeda107f && be32v(0x40) != 0xbeda107f) return -1;
    u32 version = le32v(0x44);
    if (version != 0x00010001 && version != 0x00010002 &&
        be32v(0x44) != 0x00010001 && be32v(0x44) != 0x00010002)
        return -1;
    u32 hdrSize = le32v(0x48);
    if (hdrSize == 0) hdrSize = be32v(0x48);
    if (hdrSize == 0 || hdrSize > 2048) return -1;
    u64 diskSize = le64v(0x170);
    if (diskSize == 0) diskSize = be64v(0x170);
    if (diskSize == 0) return -1;
    u64 blockSize = le32v(0x178);
    if (blockSize == 0) blockSize = be32v(0x178);
    if (blockSize == 0 || blockSize > (1ULL << 40)) return -1;
    u64 blocksTotal = le32v(0x180);
    if (blocksTotal == 0) blocksTotal = be32v(0x180);
    u64 blocksAlloc = le32v(0x184);
    if (blocksAlloc == 0) blocksAlloc = be32v(0x184);
    u32 imageType = le32v(0x4c);
    if (imageType != 1 && imageType != 2) imageType = be32v(0x4c);
    u64 dataOff = le32v(0x158);
    if (dataOff == 0) dataOff = be32v(0x158);
    // A static image is fully allocated: its physical end is data + all
    // blocks. A dynamic one holds only the blocks its bmap claims.
    u64 end = dataOff;
    u64 used = imageType == 2 ? blocksTotal : blocksAlloc;
    if (used && used < (1u << 30)) end += used * blockSize;
    if (!end || end > (u64)max) end = (u64)max;
    u64 hdrEnd = (u64)hdrSize;
    if (end < hdrEnd) end = hdrEnd;
    if (end > (u64)max) end = (u64)max;
    if (end < 512) end = 512;
    return (i64)end;
}

// --- SWF: the header's u32 length field, verified by inflating CWS bodies --
i64 vSwf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 8);
    if (b.size() < 8) return -1;
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
    return (i64)len;
}

// --- GLB (glTF binary): the header's u32 length + the chunk layout ----------
i64 vGlb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 20);
    if (b.size() < 12) return -1;
    if (b[0] != 'g' || b[1] != 'l' || b[2] != 'T' || b[3] != 'F') return -1;
    u32 version = (u32)b[4] | (u32)b[5] << 8 | (u32)b[6] << 16 | (u32)b[7] << 24;
    if (version != 2) return -1;
    u64 len = (u64)((u32)b[8] | (u32)b[9] << 8 | (u32)b[10] << 16 | (u32)b[11] << 24);
    if (len < 20 || len > (u64)max) return -1;
    // First chunk must be a JSON chunk and must fit inside the declared file.
    u32 chunkLen = (u32)b[12] | (u32)b[13] << 8 | (u32)b[14] << 16 | (u32)b[15] << 24;
    if ((u64)chunkLen > len - 20) return -1;
    if (b[16] != 'J' || b[17] != 'S' || b[18] != 'O' || b[19] != 'N') return -1;
    // Optional second chunk, if claimed to exist, must be BIN and fit too.
    if (len >= 12 + 8 + 8 + (u64)chunkLen) {
        auto b2 = s.read(off + 20 + chunkLen, 8);
        if (b2.size() == 8) {
            u32 len2 = (u32)b2[0] | (u32)b2[1] << 8 | (u32)b2[2] << 16 | (u32)b2[3] << 24;
            bool bin = b2[4] == 'B' && b2[5] == 'I' && b2[6] == 'N' && b2[7] == 0;
            if (bin && 20 + (u64)chunkLen + 8 + (u64)len2 > len) return -1;
        }
    }
    return (i64)len;
}

// --- NPY: numpy header carries exact array size ----------------------------
// -- data start + itemsize * shape product; anything exotic returns 0 so the
// -- engine falls back to the next-signature bound (advisory, never wrong).
i64 vNpy(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 18);
    if (b.size() < 10) return -1;
    if (b[0] != 0x93 || std::memcmp(b.data() + 1, "NUMPY", 5) != 0) return -1;
    u8 major = b[6];
    if (major < 1 || major > 3) return -1;
    u64 hdrLen, dataOff;
    if (major == 1) {
        hdrLen = (u64)b[8] | (u64)b[9] << 8;
        dataOff = 10;
    } else {
        if (b.size() < 12) return -1;
        hdrLen = (u64)b[8] | (u64)b[9] << 8 | (u64)b[10] << 16 | (u64)b[11] << 24;
        dataOff = 12;
    }
    if (hdrLen < 5 || hdrLen + dataOff > (u64)max) return -1;
    auto hdr = s.read(off + (i64)dataOff, (i64)hdrLen);
    if (hdr.size() < hdrLen || hdr.back() != '\n') return -1;
    // descr: "'descr': '<|f8'," etc.
    i64 itemsize = -1;
    for (size_t i = 0; i + 8 <= hdr.size(); i++) {
        if (std::memcmp(hdr.data() + i, "'descr'", 7) == 0 && hdr[i + 7] == ':') {
            size_t p = i + 8;
            while (p < hdr.size() && (hdr[p] == ' ' || hdr[p] == '\t')) p++;
            char q = (p < hdr.size()) ? (char)hdr[p] : 0;
            if (q != '\'' && q != '"') break;
            p++;
            size_t start = p;
            while (p < hdr.size() && hdr[p] != q) p++;
            if (p >= hdr.size()) break;
            // dtype: [<'<'|'>'|'|'|'='|'-'] letter [digits] or '(' composite
            size_t d = start;
            if (d < p && (hdr[d] == '<' || hdr[d] == '>' || hdr[d] == '|' ||
                          hdr[d] == '=' || hdr[d] == '-'))
                d++;
            if (d >= p) break;
            char c = (char)hdr[d];
            d++;
            // dtype strings carry an explicit size for sized letters
            // (S12, U8, V32...); numpy also writes '<i4', 'f8', 'u2' for the
            // fixed-width integer/float families.
            if (d < p && hdr[d] >= '0' && hdr[d] <= '9') {
                u64 n = 0;
                while (d < p && hdr[d] >= '0' && hdr[d] <= '9') n = n * 10 + (hdr[d] - '0'), d++;
                if (d < p) break;   // trailing junk after digits
                itemsize = (i64)(n * (c == 'U' ? 4 : 1));
                break;
            }
            if (d < p) break;   // composite or padded dtype — give up
            switch (c) {
                case 'b': case 'B': itemsize = 1; break;
                case 'h': case 'H': itemsize = 2; break;
                case 'i': case 'I': case 'f': itemsize = 4; break;
                case 'l': case 'L': case 'q': case 'Q': case 'd':
                    itemsize = 8; break;
                case 'g': case 'G': itemsize = 16; break;
                default: break;
            }
            break;
        }
    }
    if (itemsize < 0) return 0;
    // shape: "'shape': (3, 4)" — product of the integers.
    u64 elems = 1;
    bool got = false;
    for (size_t i = 0; i + 8 <= hdr.size(); i++) {
        if (std::memcmp(hdr.data() + i, "'shape'", 7) == 0 && hdr[i + 7] == ':') {
            size_t p = i + 8;
            while (p < hdr.size() && (hdr[p] == ' ' || hdr[p] == '\t')) p++;
            if (p >= hdr.size() || hdr[p] != '(') break;
            p++;
            while (p < hdr.size() && hdr[p] != ')') {
                if (hdr[p] >= '0' && hdr[p] <= '9') {
                    u64 n = 0;
                    while (p < hdr.size() && hdr[p] >= '0' && hdr[p] <= '9')
                        n = n * 10 + (hdr[p] - '0'), p++;
                    if (elems > (1ULL << 40) / (n ? n : 1)) return 0;
                    elems *= (n ? n : 1);
                    got = true;
                } else p++;
            }
            break;
        }
    }
    if (!got || elems == 0) return 0;
    u64 total = (u64)itemsize * elems;
    if (dataOff + hdrLen + total > (u64)max) return -1;
    return (i64)(dataOff + hdrLen + total);
}

// --- MAT (v5): header + chain of top-level data elements --------------------
i64 vMat(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 128);
    if (b.size() < 128) return -1;
    if (std::memcmp(b.data(), "MATLAB 5.0 MAT-file", 19) != 0) return -1;
    bool le;
    if (b[126] == 'I' && b[127] == 'M') le = true;       // 'IM' = little endian
    else if (b[126] == 'M' && b[127] == 'I') le = false; // 'MI' = big endian
    else return -1;
    u16 ver = le ? (u16)(b[124] | (u16)b[125] << 8) : (u16)(b[124] << 8 | b[125]);
    if (ver != 0x0100) return -1;
    // Subsystem offset (header bytes 116..123) should be zero for plain files.
    u64 subsys = 0;
    if (le)
        for (int k = 7; k >= 0; k--) subsys = subsys << 8 | b[116 + k];
    else
        for (int k = 0; k < 8; k++) subsys = subsys << 8 | b[116 + k];
    if (subsys != 0) return -1;
    auto rd32 = [&](i64 p) -> u32 {
        auto v = s.read(off + p, 4);
        if (v.size() < 4) return 0;
        return le ? ((u32)v[3] << 24 | (u32)v[2] << 16 | (u32)v[1] << 8 | v[0])
                  : ((u32)v[0] << 24 | (u32)v[1] << 16 | (u32)v[2] << 8 | v[3]);
    };
    // Walk the chain of top-level data elements. A miMATRIX/miCOMPRESSED
    // element uses a 16-byte tag whose size field sits at +4; other types an
    // 8-byte tag (size at +4) or a small 4-byte tag (size in bits 8..15
    // when the type bits alone look like a small element).
    i64 p = 128;
    int els = 0;
    while (p + 4 <= max && els < 100000) {
        u32 t = rd32(p);
        int type = (int)(t & 0xFF);
        if (type == 14 || type == 15) {
            u32 size = rd32(p + 4);
            if (size > (u32)max) return -1;
            // The tag's size field counts the element body from right after
            // the 8-byte tag: for a miCOMPRESSED/miMATRIX element the file
            // ends exactly at p + 8 + size (e.g. scipy's savemat). Stepping
            // 16 bytes skips the trailing 4-byte data-length pair INSIDE the
            // body and over-runs every such file by 8.
            i64 next = p + 8 + (i64)size;
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        u32 word2 = rd32(p + 4);
        int smallSize = (int)((t >> 8) & 0xFF);
        if (type >= 1 && type <= 13 && (t & 0xFF00) != 0 && (t & 0xFF0000) == 0 &&
            (t & 0xFF000000) == 0 && smallSize != 0) {
            i64 next = p + 4 + smallSize;    // small element, no padding
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        if (type >= 1 && type <= 13) {       // 8-byte tag (size at +4)
            i64 next = p + 8 + (i64)word2;
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        break;   // unknown element type: the top-level chain ends here
    }
    if (els < 1) return -1;
    return p - 0;   // p counts from off already
}

// --- PICKLE: opcode walk. Modern pickles are length-prefixed end to end,
// -- so the walk terminates exactly at the real STOP, never inside garbage.
// -- An opcode outside the covered set rejects the candidate outright: a
// -- genuine pickle produced by CPython 2.7+ never emits one (the walk then
// -- cannot be trusted to delimit the file, so we refuse rather than guess).
i64 vPickle(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 2);
    if (b.empty()) return -1;
    bool ascii = b[0] != 0x80;
    if (!ascii && (b.size() < 2 || b[1] > 5)) return -1;
    const i64 end = off + max;
    i64 pos = ascii ? off : off + 2;
    while (pos < end) {
        u8 op = s.byte(pos);
        if (op == 0x2E) return pos - off + 1;   // STOP: the pickle ends here
        i64 n;
        switch (op) {
            case 0x80: {                        // PROTO (never in ascii mode)
                u8 p = s.byte(pos + 1);
                if (p > 5) return -1;
                pos += 2;
                continue;
            }
            case 0x4A: case 0x54: case 0x58: {  // BININT / BINSTRING / BINUNICODE: u32
                auto v = s.read(pos + 1, 4);
                if (v.size() < 4) return -1;
                n = (i64)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < 0 || pos + 5 + n > end) return -1;
                pos += 5 + n;
                continue;
            }
            case 0x5A: {                        // LONG_BINUNICODE: u64 len (little-endian)
                auto v = s.read(pos + 1, 8);
                if (v.size() < 8) return -1;
                i64 n64 = 0;
                for (size_t k = 0; k < 8; k++) n64 |= (i64)v[k] << (8 * k);
                if (n64 < 0 || pos + 9 + n64 > end) return -1;
                pos += 9 + n64;
                continue;
            }
            case 0x4B: case 0x55: case 0x68: case 0x71:   // 1-byte value/ref
                if (pos + 2 > end) return -1;
                pos += 2;
                continue;
            case 0x4D:                          // BININT2 (u16 value)
                if (pos + 3 > end) return -1;
                pos += 3;
                continue;
            case 0x72: case 0x6A:               // LONG_BINPUT / LONG_BINGET: u32 ref
                if (pos + 5 > end) return -1;
                pos += 5;
                continue;
            case 0x47:                          // BINFLOAT (8 bytes)
                if (pos + 9 > end) return -1;
                pos += 9;
                continue;
            case 0x49: case 0x4C: case 0x53: case 0x56: case 0x50: {  // newline-terminated text
                while (pos < end && s.byte(pos) != 0x0A) pos++;
                if (pos >= end) return -1;
                pos++;
                continue;
            }
            case 0x70: case 0x67:               // PUT / GET: ascii refno line
                if (!ascii) break;              // binary: plain ref opcode
                while (pos < end && s.byte(pos) != 0x0A) pos++;
                if (pos >= end) return -1;
                pos++;
                continue;
            case 0x63:                          // GLOBAL: two '\n'-terminated strings
                for (int s2 = 0; s2 < 2; s2++) {
                    while (pos < end && s.byte(pos) != 0x0A) pos++;
                    if (pos >= end) return -1;
                    pos++;
                }
                continue;
            case 0x69: {                        // INST: module\0class\0 style line
                while (pos < end && s.byte(pos) != 0x0A) pos++;
                if (pos >= end) return -1;
                pos++;
                continue;
            }
            case 0x43: {                   // SHORT_BINSTRING / SHORT_BINBYTES
                u8 len = s.byte(pos + 1);
                if (pos + 2 + len > end) return -1;
                pos += 2 + len;
                continue;
            }
            case 0x8D: case 0x96: {        // BINBYTES8 / BYTEARRAY8: u64 len (little-endian)
                auto v = s.read(pos + 1, 8);
                if (v.size() < 8) return -1;
                i64 n64 = 0;
                for (size_t k = 0; k < 8; k++) n64 |= (i64)v[k] << (8 * k);
                if (n64 < 0 || pos + 9 + n64 > end) return -1;
                pos += 9 + n64;
                continue;
            }
            case 0x95: {                   // FRAME (u64 len) — protocol 4+
                i64 fstart = pos;
                if (fstart + 9 > end) return -1;
                auto v = s.read(pos + 1, 8);
                if (v.size() < 8) return -1;
                i64 n64 = 0;
                for (size_t k = 0; k < 8; k++) n64 |= (i64)v[k] << (8 * k);
                if (n64 <= 0 || n64 > end - pos - 9) return -1;
                i64 want = fstart + 9 + n64;
                // CPython packs the whole pickle (STOP included) into the last
                // frame; the frame's final byte being STOP ends the file there.
                // The frame may claim a byte past EOF (short frames are legal):
                // walk back to the last readable byte and test it instead.
                for (i64 k = want - 1; k >= fstart + 9; k--) {
                    auto tail = s.read(k, 1);
                    if (!tail.empty() && tail[0] == 0x2E) return k - off + 1;
                    if (!tail.empty()) break;
                }
                // Otherwise hop to the frame end and keep walking (nested
                // frames or an outer STOP that follows this one).
                pos = std::min<i64>(want, end - 1);
                continue;
            }
            case 0x8E: {                 // LONG1 (u8 count)
                u8 len = s.byte(pos + 1);
                if (pos + 2 + len > end) return -1;
                pos += 2 + len;
                continue;
            }
            case 0x8F: {                 // LONG4 (u32 count)
                auto v = s.read(pos + 1, 4);
                u32 len = (u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24;
                if (v.size() < 4 || pos + 5 + len > end) return -1;
                pos += 5 + len;
                continue;
            }
            default: break;
        }
        switch (op) {
            case 0x28: case 0x30: case 0x31: case 0x32: case 0x4E: case 0x52:
            case 0x61: case 0x62: case 0x64: case 0x65: case 0x67: case 0x6C:
            case 0x6F: case 0x70: case 0x73: case 0x74: case 0x75: case 0x29:
            case 0x5D: case 0x7D: case 0x5B: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x93: case 0x94:
                pos += 1;
                continue;
            default:
                return -1;   // opcode outside the covered set: not a pickle
        }
    }
    return -1;
}

// --- PYC: Python 3.13+ marshal walker. Type bytes carry a 0x80 "will be
// -- referenced" flag; code objects marshal as 5 ints + 8 objects + 1 int
// -- + 2 objects (argcount…flags, code/consts/names/varnames/freevars/
// -- cellvars/filename/name, firstlineno, lnotab, exceptiontable).
i64 vPyc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 16);
    if (h.size() < 16) return -1;
    u32 flags = (u32)h[4] | (u32)h[5] << 8 | (u32)h[6] << 16 | (u32)h[7] << 24;
    if (flags & 0x1F) return -1;                  // hash-based pyc: no end marker
    const i64 end = off + max;
    i64 pos = off + 16;
    enum : u8 { K_ITEMS, K_DICT, K_CODE };
    struct Frame { i64 left; u8 kind; u8 tail; };
    Frame frames[64];
    frames[0] = {1, K_ITEMS, 0};                  // root: one object to walk
    int depth = 1;
    u64 objects = 0;
    for (;;) {
        if (pos >= end) return -1;
        Frame& f = frames[depth - 1];
        if (f.left == 0) {
            if (f.kind == K_CODE && !f.tail) {
                pos += 4;                         // co_firstlineno
                f.tail = 1;
                f.left = 2;                       // lnotab + exceptiontable
                if (pos > end) return -1;
                continue;
            }
            depth--;
            if (depth == 0) return pos - off;     // walk complete
            continue;
        }
        if (++objects > 1000000) return -1;
        u8 t = s.byte(pos);
        pos++;
        u8 base = t & 0x7F;
        if (f.kind == K_DICT && base == 0x30) {   // NULL key ends dict
            if (depth == 1) return pos - off;
            depth--;
            continue;
        }
        if (f.kind != K_DICT) f.left--;
        switch (base) {
            case 0x30: case 0x4E: case 0x46: case 0x54: case 0x53:
            case 0x45: case 0x3F: break;                       // atomics
            case 0x69: pos += 4; break;                        // INT
            case 0x49: pos += 8; break;                        // INT64
            case 0x67: pos += 8; break;                        // BINFLOAT
            case 0x78: case 0x79: pos += 16; break;           // BINCOMPLEX
            case 0x6C: {                                       // LONG (n digits)
                auto v = s.read(pos, 4);
                if (v.size() < 4) return -1;
                i32 n = (i32)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < -10000000 || n > 10000000) return -1;
                pos += 4 + (i64)std::abs(n) * 4;
                break;
            }
            case 0x73: case 0x75: case 0x58: case 0x41: case 0x7A: case 0x42: {
                auto v = s.read(pos, 4);                       // 4-byte len strings
                if (v.size() < 4) return -1;
                i32 n = (i32)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < 0 || n > 16 * 1024 * 1024) return -1;
                pos += 4 + n;
                break;
            }
            case 0x74: case 0x61: case 0x5A: case 0x43: case 0x66: {
                u8 n = s.byte(pos);                            // 1-byte len strings
                pos += 1 + n;
                break;
            }
            case 0x72: pos += 4; break;                        // REF
            case 0x28: case 0x5B: case 0x3C: case 0x3E: {      // TUPLE/LIST/SET
                auto v = s.read(pos, 4);
                if (v.size() < 4) return -1;
                i32 n = (i32)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < 0 || n > 4000000) return -1;
                pos += 4;
                if (depth >= 64) return -1;
                frames[depth++] = {n, K_ITEMS, 0};
                break;
            }
            case 0x29: {                                       // SMALL_TUPLE
                u8 n = s.byte(pos);
                pos++;
                if (depth >= 64) return -1;
                frames[depth++] = {n, K_ITEMS, 0};
                break;
            }
            case 0x7B: {                                       // DICT
                if (depth >= 64) return -1;
                frames[depth++] = {0x7FFFFFFF, K_DICT, 0};
                break;
            }
            case 0x63: {                                       // CODE
                pos += 5 * 4;                                  // 5 ints
                if (depth >= 64) return -1;
                frames[depth++] = {8, K_CODE, 0};              // 8 objects + tail
                break;
            }
            default: return -1;
        }
        if (pos > end) return -1;
    }
}

// --- DER: iterative TLV walk (X.509, PKCS#12, ...) --------------------------
i64 vDer(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    struct El { i64 pos; i64 contentEnd; };
    std::vector<El> stack;
    i64 pos = off;
    i64 lastEnd = -1;
    i64 total = 0;
    const i64 kLimit = (i64)1 << 28;
    while (pos < off + max && total < kLimit) {
        u8 tag = s.byte(pos);
        // Top-level element: tag byte must be 0x30/0x31 (SEQUENCE/SET) for the
        // common .der/.p12 containers; a raw OCTET STRING wrapper is rare
        // (PKCS#12 is a sequence, so accept 0x30/0x31).
        if (tag != 0x30 && tag != 0x31) break;
        bool constructed = (tag & 0x20) != 0;
        i64 p = pos + 1;
        i64 len = 0;
        u8 lb = s.byte(p++);
        if (lb & 0x80) {
            int n = lb & 0x7F;
            if (n < 1 || n > 4 || p + n > off + max) return -1;
            for (int k = 0; k < n; k++) len = (len << 8) | s.byte(p++);
        } else len = lb;
        i64 contentEnd = p + len;
        if (contentEnd > off + max) return -1;
        if (!constructed) return -1;   // must be a constructed container
        // Walk down the constructed chain.
        stack.push_back({p, contentEnd});
        while (!stack.empty()) {
            El& top = stack.back();
            if (top.pos >= top.contentEnd) {
                lastEnd = top.contentEnd;
                stack.pop_back();
                continue;
            }
            u8 t = s.byte(top.pos);
            i64 q = top.pos + 1;
            i64 l = 0;
            u8 lbb = s.byte(q++);
            if (lbb & 0x80) {
                int n = lbb & 0x7F;
                if (n < 1 || n > 4 || q + n > top.contentEnd) return -1;
                for (int k = 0; k < n; k++) l = (l << 8) | s.byte(q++);
            } else l = lbb;
            if (q + l > top.contentEnd) return -1;
            bool c = (t & 0x20) != 0;
            if (c) {
                top.pos = q + l;                 // consume after descent
                stack.push_back({q, q + l});
                if (stack.size() > 64) return -1;
            } else {
                top.pos = q + l;
                lastEnd = q + l;
            }
        }
        if (lastEnd > pos) pos = lastEnd;
        else break;
    }
    if (lastEnd < 0) return -1;
    if (lastEnd - off > max) return -1;
    return lastEnd - off;
}

// --- binary plist: trailer at the exact file end ----------------------------
// -- Validate the header, find the real trailer (backward from the window
// -- end for up to 16 MiB to survive zero padding after the file), then walk
// -- the object graph from the top object. Length = trailer position - start.
i64 vPlistBin(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto hdr = s.read(off, 8);
    if (hdr.size() < 8 || std::memcmp(hdr.data(), "bplist0", 7) != 0) return -1;
    // Scan backwards for a plausible trailer: 6 zero bytes + 2 size bytes +
    // object count u64 BE + top object u64 BE + offset table offset u64 BE.
    const i64 kTail = 16 * 1024 * 1024;
    i64 scanFrom = off + max - 32;
    i64 scanTo = off + std::max<i64>(32, max - kTail);
    i64 end = -1;
    for (; scanFrom >= scanTo; scanFrom--) {
        auto t = s.read(scanFrom, 32);
        if (t.size() < 32) continue;   // tail reads can be short: keep scanning
        if (t[0] != 0 || t[1] != 0 || t[2] != 0 || t[3] != 0 || t[4] != 0 || t[5] != 0)
            continue;
        u8 offIntSize = t[6], refSize = t[7];
        if (offIntSize < 1 || offIntSize > 4 || refSize < 1 || refSize > 4) continue;
        u64 count = 0, top = 0, tableOff = 0;
        for (int k = 0; k < 8; k++) {
            count = count << 8 | t[8 + k];
            top = top << 8 | t[16 + k];
            tableOff = tableOff << 8 | t[24 + k];
        }
        if (count < 1 || count > (1u << 20)) continue;
        if (top >= count) continue;
        if (tableOff + (u64)count * offIntSize != (u64)(scanFrom - off)) continue;
        i64 tableStart = off + (i64)tableOff;
        // Validate every offset table entry points inside the table.
        u32 depth = 0;
        bool valid = true;
        auto check = [&]() -> bool {
            for (u32 i = 0; i < count; i++) {
                i64 p = tableStart + (i64)i * offIntSize;
                u64 v = 0;
                for (int k = 0; k < offIntSize; k++) v = v << 8 | s.byte(p + k);
                if (v >= (u64)(scanFrom - off)) return false;   // offset past file
            }
            return true;
        };
        if (!check()) continue;
        // Recursion-free walk of the top object's subtree.
        std::vector<u64> queue;
        queue.push_back(top);
        std::vector<bool> visited(count, false);
        size_t qPos = 0;
        while (qPos < queue.size() && depth < 4096) {
            u32 idx = (u32)queue[qPos++];
            if (idx >= count || visited[idx]) continue;
            visited[idx] = true;
            i64 objOff = off + (i64)tableOff + (i64)idx * offIntSize;
            u64 ooff = 0;
            for (int k = 0; k < offIntSize; k++) ooff = ooff << 8 | s.byte(objOff + k);
            u8 marker = s.byte(off + (i64)ooff);
            u8 type = marker & 0xF0;
            if (type == 0x00) {
                if (marker > 0x0B) { valid = false; break; }   // null/bool/fill
                continue;
            }
            if (type == 0x10) {              // integer
                int sz = marker & 0x0F;
                if (sz > 4) { valid = false; break; }
                continue;
            }
            if (type == 0x20 || type == 0x30) {   // real / date
                int sz = marker & 0x0F;
                if (sz > 3) { valid = false; break; }
                continue;
            }
            if (type == 0x40 || type == 0x50 || type == 0x60) {   // data/strings
                int sz = marker & 0x0F;
                if (sz == 0x0F) {
                    // 4-byte extended count.
                    auto c = s.read(off + (i64)ooff + 1, 4);
                    if (c.size() < 4) { valid = false; break; }
                } else if (sz > 14) { valid = false; break; }
                continue;
            }
            if (type == 0x80) {              // uid
                int sz = marker & 0x0F;
                if (sz > 8) { valid = false; break; }
                continue;
            }
            if (type == 0xA0 || type == 0xC0) {   // array / set
                u32 n = marker & 0x0F;
                if (n == 0x0F) {
                    auto c = s.read(off + (i64)ooff + 1, 4);
                    if (c.size() < 4) { valid = false; break; }
                    n = ((u32)c[0] << 24 | (u32)c[1] << 16 | (u32)c[2] << 8 | c[3]);
                }
                if (n > count) { valid = false; break; }
                for (u32 k = 0; k < n; k++) {
                    i64 rp = off + (i64)ooff + ((marker & 0x0F) == 0x0F ? 5 : 1) +
                              (i64)k * refSize;
                    u64 r = 0;
                    for (int z = 0; z < refSize; z++) r = r << 8 | s.byte(rp + z);
                    if (r >= count) { valid = false; break; }
                    queue.push_back(r);
                }
                if (!valid) break;
                depth++;
                continue;
            }
            if (type == 0xD0) {              // dict
                u32 n = marker & 0x0F;
                if (n == 0x0F) {
                    auto c = s.read(off + (i64)ooff + 1, 4);
                    if (c.size() < 4) { valid = false; break; }
                    n = ((u32)c[0] << 24 | (u32)c[1] << 16 | (u32)c[2] << 8 | c[3]);
                }
                if (n > count) { valid = false; break; }
                i64 rbase = (marker & 0x0F) == 0x0F ? 5 : 1;
                for (u32 k = 0; k < 2 * n; k++) {
                    i64 rp = off + (i64)ooff + rbase + (i64)k * refSize;
                    u64 r = 0;
                    for (int z = 0; z < refSize; z++) r = r << 8 | s.byte(rp + z);
                    if (r >= count) { valid = false; break; }
                    queue.push_back(r);
                }
                if (!valid) break;
                depth++;
                continue;
            }
            valid = false;   // unknown object type
            break;
        }
        if (!valid) continue;
        end = scanFrom - off + 32;   // file ends right after the trailer
        break;
    }
    if (end < 0 || end > max) return -1;
    return end;
}

}  // namespace

// ===========================================================================
// Registry
// ===========================================================================
namespace {

// Validators that walk a file's internal chain from beginning to end, so a
// success proves every byte in between is intact. Deliberately excluded:
//
//   * footer searches (PDF's %%EOF) — they prove nothing about the bytes
//     they skipped over, and a stray footer far downstream fabricates a
//     large "valid" file out of unrelated data
//   * frame streams (MP3, AAC, AC-3, MPEG TS/PS, AMR) — per-frame constraints
//     are loose enough that arbitrary data chains through them
//
// Both classes produced confident false positives when these results were used
// as evidence for RAID geometry.
bool walksWholeFile(SizeFn fn) {
    static const SizeFn kWhole[] = {
        vJpeg, vPng, vGif, vZip, vTar, vAr, vMp4, vEbml, vOgg, vFlac,
        vMidi, vWasm, vPcap, vPcapng, nullptr};
    for (int i = 0; kWhole[i]; i++) if (fn == kWhole[i]) return true;
    return false;
}

// Stream formats whose validator chain-walk has no hard end marker. The walk
// is honest for what it proves, but the file's real length is only settled by
// the next signature on the device, so the engine clamps the result to it.
bool walksToBoundary(SizeFn fn) {
    static const SizeFn kBounded[] = {
        vMat, vPickle, vDer, vPlistBin, vQcow, vVhd, vVhdx, vVdi, vSwf, nullptr};
    for (int i = 0; kBounded[i]; i++) if (fn == kBounded[i]) return true;
    return false;
}

CarveSpec mk(const char* name, const char* ext, const char* cat, std::vector<u8> magic,
             i64 maxSize, SizeMode mode = SizeMode::Heuristic, SizeFn fn = nullptr) {
    CarveSpec c;
    c.name = name;
    c.ext = ext;
    c.category = cat;
    c.magic = std::move(magic);
    c.max_size = maxSize;
    c.mode = mode;
    c.validator = fn;
    c.whole_file = walksWholeFile(fn);
    c.bound_to_next = walksToBoundary(fn);
    return c;
}

CarveSpec& withConfirm(CarveSpec& c, std::vector<u8> confirm, int atOffset, int window = 4096) {
    c.confirm = std::move(confirm);
    c.confirm_offset = atOffset;
    c.confirm_window = window;
    return c;
}

std::vector<CarveSpec> buildRegistry() {
    std::vector<CarveSpec> r;
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    // ---------------- images ----------------
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
    // TIFF-derived raw formats must be tried before generic TIFF.
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
    add(mk("CDR", "cdr", "image", S("RIFF"), 256*MB, SizeMode::Header, vRiff));

    // ---------------- video ----------------
    { auto c = mk("MP4", "mp4", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.min_size = 1024; add(c); }
    { auto c = mk("MOV", "mov", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("qt  "), 8); c.priority = 20; add(c); }
    { auto c = mk("M4V", "m4v", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("M4V "), 8); c.priority = 20; add(c); }
    { auto c = mk("M4A", "m4a", "audio", S("ftyp"), 4*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("M4A "), 8); c.priority = 20; add(c); }
    { auto c = mk("3GP", "3gp", "video", S("ftyp"), 4*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("3gp"), 8); c.priority = 20; add(c); }
    { auto c = mk("MOV_MDAT", "mov", "video", S("moov"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.min_size = 1024; add(c); }
    { auto c = mk("MKV", "mkv", "video", B({0x1A,0x45,0xDF,0xA3}), 32*GB, SizeMode::Container, vEbml);
      withConfirm(c, S("matroska"), -1, 8192); c.priority = 20; c.min_size = 1024; add(c); }
    { auto c = mk("WEBM", "webm", "video", B({0x1A,0x45,0xDF,0xA3}), 16*GB, SizeMode::Container, vEbml);
      withConfirm(c, S("webm"), -1, 8192); c.priority = 20; c.min_size = 1024; add(c); }
    { auto c = mk("EBML", "mkv", "video", B({0x1A,0x45,0xDF,0xA3}), 32*GB, SizeMode::Container, vEbml);
      c.min_size = 1024; add(c); }
    { auto c = mk("AVI", "avi", "video", S("RIFF"), 8*GB, SizeMode::Header, vRiff);
      withConfirm(c, S("AVI "), 8); c.priority = 20; c.min_size = 1024; add(c); }
    { auto c = mk("WAV", "wav", "audio", S("RIFF"), 4*GB, SizeMode::Header, vRiff);
      withConfirm(c, S("WAVE"), 8); c.priority = 20; c.min_size = 44; add(c); }
    { auto c = mk("FLV", "flv", "video", B({'F','L','V',0x01}), 8*GB, SizeMode::Container, vFlv);
      c.min_size = 1024; add(c); }
    { auto c = mk("WMV", "wmv", "video",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  8*GB, SizeMode::Container, vAsf);
      withConfirm(c, B({0xC0,0xEF,0x19,0xBC,0x4D,0x5B,0xCF,0x11}), -1, 65536); c.priority = 20;
      c.min_size = 1024; add(c); }
    { auto c = mk("WMA", "wma", "audio",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  2*GB, SizeMode::Container, vAsf);
      withConfirm(c, B({0x40,0x9E,0x69,0xF8,0x4D,0x5B,0xCF,0x11}), -1, 65536); c.priority = 20;
      c.min_size = 1024; add(c); }
    { auto c = mk("ASF", "asf", "video",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  8*GB, SizeMode::Container, vAsf); c.min_size = 1024; add(c); }
    { auto c = mk("MPEG_TS", "ts", "video", B({0x47,0x40,0x00}), 16*GB, SizeMode::FrameStream, vMpegTs);
      c.min_size = 188 * 16; c.min_entropy = 1.0; add(c); }
    { auto c = mk("MPEG_TS1", "ts", "video", B({0x47,0x41,0x01}), 16*GB, SizeMode::FrameStream, vMpegTs);
      c.min_size = 188 * 16; c.min_entropy = 1.0; add(c); }
    { auto c = mk("MPEG_PS", "mpg", "video", B({0x00,0x00,0x01,0xBA}), 8*GB,
                  SizeMode::FrameStream, vMpegPs); c.min_size = 2048; add(c); }
    { auto c = mk("MPEG_VES", "mpv", "video", B({0x00,0x00,0x01,0xB3}), 4*GB,
                  SizeMode::FrameStream, vMpegVes); c.min_size = 2048; add(c); }
    add(mk("RM", "rm", "video", S(".RMF"), 4*GB));
    add(mk("MXF", "mxf", "video", B({0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01}), 32*GB,
           SizeMode::Container, vMxf));
    add(mk("IVF", "ivf", "video", S("DKIF"), 4*GB, SizeMode::Container, vIvf));
    add(mk("Y4M", "y4m", "video", S("YUV4MPEG2"), 32*GB));
    add(mk("BIK", "bik", "video", S("BIK"), 4*GB));
    add(mk("SWF", "swf", "video", S("FWS"), 256*MB, SizeMode::Header, vSwf));
    add(mk("SWF_ZLIB", "swf", "video", S("CWS"), 256*MB, SizeMode::Header, vSwf));
    add(mk("SWF_LZMA", "swf", "video", S("ZWS"), 256*MB));

    // ---------------- audio ----------------
    { auto c = mk("MP3_ID3", "mp3", "audio", S("ID3"), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 512; c.priority = 15; add(c); }
    { auto c = mk("MP3_FRAME", "mp3", "audio", B({0xFF,0xFB}), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 2048; add(c); }
    { auto c = mk("MP3_FRAME_V2", "mp3", "audio", B({0xFF,0xF3}), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 2048; add(c); }
    { auto c = mk("MP3_FRAME_V25", "mp3", "audio", B({0xFF,0xE3}), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 2048; add(c); }
    { auto c = mk("FLAC", "flac", "audio", S("fLaC"), 4*GB, SizeMode::Container, vFlac);
      c.min_size = 1024; add(c); }
    { auto c = mk("OPUS", "opus", "audio", S("OggS"), 1*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("OpusHead"), -1, 512); c.priority = 22; c.min_size = 512; add(c); }
    { auto c = mk("OGA", "oga", "audio", S("OggS"), 1*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("vorbis"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
    { auto c = mk("SPX", "spx", "audio", S("OggS"), 512*MB, SizeMode::Container, vOgg);
      withConfirm(c, S("Speex"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
    { auto c = mk("OGV", "ogv", "video", S("OggS"), 4*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("theora"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
    { auto c = mk("OGG", "ogg", "audio", S("OggS"), 4*GB, SizeMode::Container, vOgg);
      c.min_size = 512; add(c); }
    { auto c = mk("AAC", "aac", "audio", B({0xFF,0xF1}), 1*GB, SizeMode::FrameStream, vAac);
      c.min_size = 2048; add(c); }
    { auto c = mk("AAC_MPEG2", "aac", "audio", B({0xFF,0xF9}), 1*GB, SizeMode::FrameStream, vAac);
      c.min_size = 2048; add(c); }
    { auto c = mk("AC3", "ac3", "audio", B({0x0B,0x77}), 1*GB, SizeMode::FrameStream, vAc3);
      c.min_size = 4096; add(c); }
    { auto c = mk("AIFF", "aiff", "audio", S("FORM"), 2*GB, SizeMode::Header, vIff);
      withConfirm(c, S("AIFF"), 8); c.priority = 20; c.min_size = 64; add(c); }
    { auto c = mk("AIFC", "aifc", "audio", S("FORM"), 2*GB, SizeMode::Header, vIff);
      withConfirm(c, S("AIFC"), 8); c.priority = 20; c.min_size = 64; add(c); }
    { auto c = mk("AMR", "amr", "audio", S("#!AMR\n"), 256*MB, SizeMode::FrameStream, vAmr);
      c.min_size = 32; add(c); }
    { auto c = mk("AMR_WB", "amr", "audio", S("#!AMR-WB\n"), 256*MB, SizeMode::FrameStream, vAmr);
      c.min_size = 32; c.priority = 5; add(c); }
    { auto c = mk("MIDI", "mid", "audio", S("MThd"), 64*MB, SizeMode::Container, vMidi);
      c.min_size = 22; add(c); }
    add(mk("DTS", "dts", "audio", B({0x7F,0xFE,0x80,0x01}), 1*GB, SizeMode::Container, vDts));
    add(mk("APE", "ape", "audio", S("MAC "), 1*GB));
    add(mk("WV", "wv", "audio", S("wvpk"), 1*GB));
    add(mk("MPC", "mpc", "audio", S("MPCK"), 512*MB));
    add(mk("MPC_SV7", "mpc", "audio", S("MP+"), 512*MB));
    add(mk("AU", "au", "audio", B({0x2E,'s','n','d'}), 512*MB, SizeMode::Container, vAu));
    add(mk("CAF", "caf", "audio", S("caff"), 2*GB, SizeMode::Container, vCaf));
    add(mk("VOC", "voc", "audio", S("Creative Voice File"), 256*MB, SizeMode::Container, vVoc));
    add(mk("MOD_IT", "it", "audio", S("IMPM"), 128*MB));
    { auto c = mk("MOD_S3M", "s3m", "audio", S("SCRM"), 128*MB);
      c.magic_offset = 44; add(c); }
    add(mk("MOD_XM", "xm", "audio", S("Extended Module:"), 128*MB));

    // ---------------- documents ----------------
    { auto c = mk("PDF", "pdf", "document", S("%PDF-"), 2*GB, SizeMode::Footer, vPdf);
      c.footer = S("%%EOF"); c.min_size = 100; add(c); }
    { auto c = mk("PS", "ps", "document", S("%!PS"), 256*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("DOCX", "docx", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("word/"), -1, 8192); c.priority = 30; c.min_size = 256; add(c); }
    { auto c = mk("XLSX", "xlsx", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("xl/"), -1, 8192); c.priority = 30; c.min_size = 256; add(c); }
    { auto c = mk("PPTX", "pptx", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("ppt/"), -1, 8192); c.priority = 30; c.min_size = 256; add(c); }
    { auto c = mk("ODT", "odt", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("opendocument.text"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("ODS", "ods", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("opendocument.spreadsheet"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("ODP", "odp", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("opendocument.presentation"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("EPUB", "epub", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("application/epub"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("XLS", "xls", "document", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("Workbook"), -1, 16384); c.priority = 30; add(c); }
    { auto c = mk("PPT", "ppt", "document", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("PowerPoint"), -1, 16384); c.priority = 30; add(c); }
    { auto c = mk("MSG", "msg", "email", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("__nameid"), -1, 16384); c.priority = 30; add(c); }
    { auto c = mk("DOC", "doc", "document", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2); c.min_size = 512; add(c); }
    { auto c = mk("RTF", "rtf", "document", S("{\\rtf"), 128*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    add(mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB));
    add(mk("DJVU", "djvu", "document", S("AT&TFORM"), 512*MB));
    add(mk("CHM", "chm", "document", S("ITSF"), 512*MB));
    add(mk("ONE", "one", "document", B({0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D}), 512*MB));
    add(mk("WPD", "wpd", "document", B({0xFF,'W','P','C'}), 128*MB));
    { auto c = mk("HTML", "html", "document", S("<!DOCTYPE html"), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("HTML_TAG", "html", "document", S("<html"), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("XML", "xml", "document", S("<?xml"), 64*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("LATEX", "tex", "document", S("\\documentclass"), 32*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }

    // ---------------- archives ----------------
    { auto c = mk("ZIP", "zip", "archive", B({'P','K',0x03,0x04}), 8*GB, SizeMode::Header, vZip);
      c.min_size = 100; add(c); }
    { auto c = mk("JAR", "jar", "archive", B({'P','K',0x03,0x04}), 2*GB, SizeMode::Header, vZip);
      withConfirm(c, S("META-INF/MANIFEST"), -1, 8192); c.priority = 25; add(c); }
    { auto c = mk("APK", "apk", "archive", B({'P','K',0x03,0x04}), 4*GB, SizeMode::Header, vZip);
      withConfirm(c, S("AndroidManifest"), -1, 16384); c.priority = 28; add(c); }
    { auto c = mk("GZIP", "gz", "archive", B({0x1F,0x8B,0x08}), 8*GB, SizeMode::Heuristic, vGzip);
      c.min_size = 20; add(c); }
    { auto c = mk("BZIP2", "bz2", "archive", S("BZh"), 8*GB, SizeMode::Heuristic, vBzip2);
      c.min_size = 20; add(c); }
    { auto c = mk("XZ", "xz", "archive", B({0xFD,'7','z','X','Z',0x00}), 8*GB,
                  SizeMode::Heuristic, vXz); c.min_size = 32; add(c); }
    { auto c = mk("7Z", "7z", "archive", B({'7','z',0xBC,0xAF,0x27,0x1C}), 8*GB,
                  SizeMode::Header, v7z); c.min_size = 32; add(c); }
    { auto c = mk("RAR4", "rar", "archive", B({'R','a','r','!',0x1A,0x07,0x00}), 8*GB,
                  SizeMode::Header, vRar); c.min_size = 32; add(c); }
    { auto c = mk("RAR5", "rar", "archive", B({'R','a','r','!',0x1A,0x07,0x01,0x00}), 8*GB,
                  SizeMode::Header, vRar); c.min_size = 32; add(c); }
    { auto c = mk("TAR", "tar", "archive", S("ustar"), 8*GB, SizeMode::Container, vTar);
      c.magic_offset = 257; c.min_size = 1024; add(c); }
    { auto c = mk("DEB", "deb", "archive", S("!<arch>\n"), 2*GB, SizeMode::Container, vAr);
      withConfirm(c, S("debian-binary"), -1, 128); c.priority = 20; add(c); }
    { auto c = mk("AR", "a", "archive", S("!<arch>\n"), 2*GB, SizeMode::Container, vAr);
      c.min_size = 68; add(c); }
    { auto c = mk("CAB", "cab", "archive", S("MSCF"), 2*GB, SizeMode::Header, vCab);
      c.min_size = 36; add(c); }
    add(mk("ZSTD", "zst", "archive", B({0x28,0xB5,0x2F,0xFD}), 8*GB));
    add(mk("LZ4", "lz4", "archive", B({0x04,0x22,0x4D,0x18}), 8*GB));
    add(mk("LZIP", "lz", "archive", S("LZIP"), 8*GB));
    add(mk("LZMA_ALONE", "lzma", "archive", B({0x5D,0x00,0x00}), 8*GB));
    add(mk("RPM", "rpm", "archive", B({0xED,0xAB,0xEE,0xDB}), 2*GB));
    add(mk("CPIO_ASCII", "cpio", "archive", S("070701"), 2*GB, SizeMode::Container, vCpio));
    add(mk("CPIO_ODC", "cpio", "archive", S("070707"), 2*GB, SizeMode::Container, vCpio));
    add(mk("CPIO_BIN", "cpio", "archive", B({0xC7,0x71}), 2*GB, SizeMode::Container, vCpio));
    add(mk("LZH", "lzh", "archive", S("-lh"), 512*MB));
    add(mk("ACE", "ace", "archive", S("**ACE**"), 512*MB));
    add(mk("SIT", "sit", "archive", S("StuffIt"), 512*MB));
    add(mk("WIM", "wim", "archive", S("MSWIM"), 8*GB));
    add(mk("DMG_KOLY", "dmg", "archive", S("koly"), 16*GB));
    { auto c = mk("ISO9660", "iso", "archive", S("CD001"), 16*GB,
                  SizeMode::Header, vIso);
      c.magic_offset = 32769; add(c); }
    add(mk("SQUASHFS", "squashfs", "archive", S("hsqs"), 8*GB));
    add(mk("CRAMFS", "cramfs", "archive", B({0x45,0x3D,0xCD,0x28}), 2*GB));

    // ---------------- databases ----------------
    { auto c = mk("SQLite", "sqlite", "database", S("SQLite format 3\0"), 8*GB,
                  SizeMode::Header, vSqlite); c.min_size = 512; add(c); }
    add(mk("SQLite_WAL", "sqlite-wal", "database", B({0x37,0x7F,0x06,0x82}), 2*GB));
    add(mk("MDB", "mdb", "database", B({0x00,0x01,0x00,0x00,'S','t','a','n','d','a','r','d',' ','J','e','t'}), 4*GB));
    add(mk("ACCDB", "accdb", "database", B({0x00,0x01,0x00,0x00,'S','t','a','n','d','a','r','d',' ','A','C','E'}), 4*GB));
    add(mk("BerkeleyDB", "db", "database", B({0x00,0x05,0x31,0x62}), 2*GB));
    add(mk("LevelDB", "ldb", "database", B({0x57,0xFB,0x80,0x8B,0x24,0x75,0x47,0xDB}), 2*GB));
    add(mk("Firebird", "fdb", "database", B({0x01,0x00,0x39,0x30}), 4*GB));
    add(mk("MSSQL_MDF", "mdf", "database", B({0x01,0x0F,0x00,0x00}), 16*GB));
    add(mk("Parquet", "parquet", "database", S("PAR1"), 8*GB));
    add(mk("ORC", "orc", "database", S("ORC"), 8*GB));
    add(mk("Avro", "avro", "database", B({'O','b','j',0x01}), 8*GB));
    add(mk("HDF5", "h5", "database", B({0x89,'H','D','F',0x0D,0x0A,0x1A,0x0A}), 8*GB));
    add(mk("NetCDF", "nc", "database", S("CDF"), 8*GB));
    add(mk("Feather", "arrow", "database", S("ARROW1"), 8*GB));
    add(mk("NPY", "npy", "database", B({0x93,'N','U','M','P','Y'}), 8*GB, SizeMode::Header, vNpy));
    add(mk("MAT", "mat", "database", S("MATLAB 5.0 MAT-file"), 8*GB, SizeMode::Header, vMat));
    { auto c = mk("PICKLE", "pkl", "database", B({0x80,0x04,0x95}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE2", "pkl", "database", B({0x80,0x02}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE3", "pkl", "database", B({0x80,0x03}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE5", "pkl", "database", B({0x80,0x05}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE_P0", "pkl", "database", B({0x28,0x64,0x70,0x30,0x0A}), 512*MB,
                  SizeMode::Header, vPickle); c.whole_file = true; add(c); }
    { auto c = mk("PICKLE_P1", "pkl", "database", B({0x7D,0x71,0x00,0x28}), 512*MB,
                  SizeMode::Header, vPickle); c.whole_file = true; add(c); }

    // ---------------- email ----------------
    add(mk("PST", "pst", "email", B({0x21,0x42,0x44,0x4E}), 32*GB));
    { auto c = mk("MBOX", "mbox", "email", S("From "), 2*GB, SizeMode::Text, vText);
      c.min_size = 256; add(c); }
    { auto c = mk("EML", "eml", "email", S("Received: from"), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_MSGID", "eml", "email", S("Message-ID: <"), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    add(mk("DBX", "dbx", "email", B({0xCF,0xAD,0x12,0xFE}), 2*GB));

    // ---------------- crypto and secrets ----------------
    { auto c = mk("PEM_CERT", "pem", "crypto", S("-----BEGIN CERTIFICATE-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END CERTIFICATE-----");
      c.footer_extra = 1; c.min_size = 64; add(c); }
    { auto c = mk("PEM_RSA", "pem", "crypto", S("-----BEGIN RSA PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END RSA PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_EC", "pem", "crypto", S("-----BEGIN EC PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END EC PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_DSA", "pem", "crypto", S("-----BEGIN DSA PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END DSA PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_OPENSSH", "pem", "crypto", S("-----BEGIN OPENSSH PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END OPENSSH PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_PRIVATE", "pem", "crypto", S("-----BEGIN PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PGP_PRIVATE", "asc", "crypto", S("-----BEGIN PGP PRIVATE KEY BLOCK-----"), 8*MB,
                  SizeMode::Footer); c.footer = S("-----END PGP PRIVATE KEY BLOCK-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PGP_MESSAGE", "asc", "crypto", S("-----BEGIN PGP MESSAGE-----"), 64*MB,
                  SizeMode::Footer); c.footer = S("-----END PGP MESSAGE-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("SSH_RSA_PUB", "pub", "crypto", S("ssh-rsa AAAA"), 64*KB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("SSH_ED25519_PUB", "pub", "crypto", S("ssh-ed25519 AAAA"), 64*KB,
                  SizeMode::Text, vText); c.min_size = 64; add(c); }
    add(mk("PKCS12", "p12", "crypto", B({0x30,0x82}), 4*MB, SizeMode::Header, vDer));
    add(mk("JKS", "jks", "crypto", B({0xFE,0xED,0xFE,0xED}), 16*MB));
    add(mk("KDBX", "kdbx", "crypto", B({0x03,0xD9,0xA2,0x9A,0x67,0xFB,0x4B,0xB5}), 256*MB));
    add(mk("KDB", "kdb", "crypto", B({0x03,0xD9,0xA2,0x9A,0x65,0xFB,0x4B,0xB5}), 256*MB));
    add(mk("GPG_KEYRING", "gpg", "crypto", B({0x99,0x01}), 16*MB, SizeMode::FrameStream, vGpg));
    add(mk("BITCOIN_WALLET", "dat", "crypto", B({0x00,0x05,0x31,0x62,0x00,0x09,0x00,0x00}), 512*MB));

    // ---------------- executables ----------------
    { auto c = mk("ELF", "elf", "executable", B({0x7F,'E','L','F'}), 2*GB, SizeMode::Header, vElf);
      c.min_size = 52; add(c); }
    { auto c = mk("PE", "exe", "executable", B({'M','Z'}), 2*GB, SizeMode::Header, vPe);
      c.min_size = 512; add(c); }
    { auto c = mk("MachO64", "macho", "executable", B({0xCF,0xFA,0xED,0xFE}), 2*GB,
                  SizeMode::Header, vMachO); c.min_size = 32; add(c); }
    { auto c = mk("MachO32", "macho", "executable", B({0xCE,0xFA,0xED,0xFE}), 2*GB,
                  SizeMode::Header, vMachO); c.min_size = 28; add(c); }
    add(mk("MachO_FAT", "macho", "executable", B({0xCA,0xFE,0xBA,0xBF}), 2*GB));
    { auto c = mk("JavaClass", "class", "executable", B({0xCA,0xFE,0xBA,0xBE}), 64*MB,
                  SizeMode::Heuristic, vClass); c.min_size = 32; add(c); }
    { auto c = mk("DEX", "dex", "executable", S("dex\n"), 512*MB, SizeMode::Header, vDex);
      c.min_size = 112; add(c); }
    { auto c = mk("WASM", "wasm", "executable", B({0x00,'a','s','m'}), 512*MB,
                  SizeMode::Container, vWasm); c.min_size = 8; add(c); }
    { auto c = mk("PYC", "pyc", "executable", B({0x6F,0x0D,0x0D,0x0A}), 64*MB,
                  SizeMode::FrameStream, vPyc); c.min_size = 24; add(c); }
    { auto c = mk("PYC_F3", "pyc", "executable", B({0xF3,0x0D,0x0D,0x0A}), 64*MB,
                  SizeMode::FrameStream, vPyc); c.min_size = 24; add(c); }

    // ---------------- forensic artefacts ----------------
    { auto c = mk("PCAP_LE", "pcap", "forensic", B({0xD4,0xC3,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_BE", "pcap", "forensic", B({0xA1,0xB2,0xC3,0xD4}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS", "pcap", "forensic", B({0xA1,0xB2,0x3C,0x4D}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS_LE", "pcap", "forensic", B({0x4D,0x3C,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAPNG", "pcapng", "forensic", B({0x0A,0x0D,0x0D,0x0A}), 8*GB,
                  SizeMode::Container, vPcapng); c.min_size = 28; add(c); }
    { auto c = mk("EVTX", "evtx", "forensic", S("ElfFile\0"), 4*GB, SizeMode::Header, vEvtx);
      c.min_size = 4096; add(c); }
    add(mk("EVT", "evt", "forensic", B({0x30,0x00,0x00,0x00,'L','f','L','e'}), 512*MB));
    { auto c = mk("REGF", "hiv", "forensic", S("regf"), 4*GB, SizeMode::Header, vRegf);
      c.min_size = 4096; add(c); }
    add(mk("LNK", "lnk", "forensic", B({0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00}), 16*MB));
    add(mk("PREFETCH", "pf", "forensic", S("SCCA"), 16*MB));
    add(mk("PREFETCH_C", "pf", "forensic", B({0x4D,0x41,0x4D,0x04}), 16*MB));
    add(mk("JOB", "job", "forensic", B({0x01,0x05,0x01,0x00}), 4*MB));

    // ---------------- virtual disks ----------------
    { auto c = mk("QCOW2", "qcow2", "vm", B({'Q','F','I',0xFB}), 64*GB,
                  SizeMode::Heuristic, vQcow); c.min_size = 72; add(c); }
    add(mk("VMDK_SPARSE", "vmdk", "vm", B({'K','D','M','V'}), 64*GB));
    add(mk("VMDK_DESC", "vmdk", "vm", S("# Disk DescriptorFile"), 1*MB));
    { auto c = mk("VDI", "vdi", "vm", S("<<< Oracle VM VirtualBox Disk Image >>>"), 64*GB,
                  SizeMode::Header, vVdi); c.min_size = 512; add(c); }
    { auto c = mk("VDI_QEMU", "vdi", "vm", S("<<< QEMU VM Virtual Disk Image >>>"), 64*GB,
                  SizeMode::Header, vVdi); c.min_size = 512; add(c); }
    { auto c = mk("VHD", "vhd", "vm", S("conectix"), 64*GB,
                  SizeMode::Footer, vVhd); c.min_size = 1024; add(c); }
    { auto c = mk("VHDX", "vhdx", "vm", S("vhdxfile"), 64*GB, SizeMode::Heuristic, vVhdx);
      add(c); }
    { auto c = mk("OVA", "ova", "vm", S("ustar"), 64*GB, SizeMode::Container, vTar);
      c.magic_offset = 257; c.min_size = 1024; add(c); }

    // ---------------- fonts ----------------
    { auto c = mk("TTF", "ttf", "font", B({0x00,0x01,0x00,0x00,0x00}), 64*MB,
                  SizeMode::Header, vSfnt); c.min_size = 2048; add(c); }
    { auto c = mk("OTF", "otf", "font", S("OTTO"), 64*MB, SizeMode::Header, vSfnt);
      c.min_size = 128; add(c); }
    { auto c = mk("TTC", "ttc", "font", S("ttcf"), 64*MB, SizeMode::Container, vTtc);
      c.min_size = 16; add(c); }
    { auto c = mk("WOFF", "woff", "font", S("wOFF"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 44; add(c); }
    { auto c = mk("WOFF2", "woff2", "font", S("wOF2"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 48; add(c); }

    // ---------------- CAD / 3D ----------------
    add(mk("DWG", "dwg", "misc", S("AC10"), 512*MB));
    add(mk("DXF", "dxf", "misc", S("  0\r\nSECTION"), 512*MB));
    add(mk("STL_ASCII", "stl", "misc", S("solid "), 512*MB, SizeMode::Container, vStlAscii));
    add(mk("BLEND", "blend", "misc", S("BLENDER"), 4*GB));
    add(mk("FBX", "fbx", "misc", S("Kaydara FBX Binary"), 2*GB));
    add(mk("GLTF_BIN", "glb", "misc", S("glTF"), 2*GB, SizeMode::Header, vGlb));

    // ---------------- source and config ----------------
    { auto c = mk("JSON", "json", "code", S("{\""), 64*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("SHEBANG_SH", "sh", "code", S("#!/bin/sh"), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("SHEBANG_BASH", "sh", "code", S("#!/bin/bash"), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("SHEBANG_ENV", "sh", "code", S("#!/usr/bin/env "), 8*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("PYTHON", "py", "code", S("import "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("PYTHON_DEF", "py", "code", S("def "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("C_INCLUDE", "c", "code", S("#include "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("C_IFNDEF", "h", "code", S("#ifndef "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("GO", "go", "code", S("package main"), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("JAVA", "java", "code", S("package "), 8*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("PHP", "php", "code", S("<?php"), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("RUST", "rs", "code", S("fn main("), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("SQL", "sql", "code", S("CREATE TABLE"), 64*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("SQL_DUMP", "sql", "code", S("-- MySQL dump"), 512*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("DOCKERFILE", "dockerfile", "code", S("FROM "), 1*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("YAML_DOC", "yaml", "code", S("---\n"), 8*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("TOML", "toml", "code", S("[package]"), 4*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("INI_UNIT", "service", "code", S("[Unit]\n"), 1*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("GIT_CONFIG", "gitconfig", "code", S("[core]\n"), 1*MB, SizeMode::Text, vText);
      c.min_size = 16; add(c); }
    { auto c = mk("CMAKE", "cmake", "code", S("cmake_minimum_required"), 4*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("CSV_HEADER", "csv", "code", S("id,name,"), 512*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("VCARD", "vcf", "code", S("BEGIN:VCARD"), 16*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("ICAL", "ics", "code", S("BEGIN:VCALENDAR"), 16*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("GPX", "gpx", "code", S("<gpx "), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("KML", "kml", "code", S("<kml "), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("TORRENT", "torrent", "misc", S("d8:announce"), 16*MB); c.min_size = 64; add(c); }
    { auto c = mk("PLIST_XML", "plist", "misc", S("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"),
                  16*MB, SizeMode::Text, vText); add(c); }
    add(mk("PLIST_BIN", "plist", "misc", S("bplist00"), 16*MB, SizeMode::Header, vPlistBin));
    add(mk("DER", "der", "misc", B({0x30,0x82}), 64*MB, SizeMode::Header, vDer));
    { auto c = mk("DER_SMALL", "der", "misc", B({0x30,0x81}), 64*MB, SizeMode::Header, vDer);
      c.priority = 10; add(c); }
    add(mk("OPENVPN", "ovpn", "misc", S("client\ndev tun"), 1*MB));

    // Assign a stable id order: higher priority first so the engine prefers the
    // most specific spec when several match at the same offset.
    std::stable_sort(r.begin(), r.end(),
                     [](const CarveSpec& a, const CarveSpec& b) { return a.priority > b.priority; });
    return r;
}

}  // namespace

const std::vector<CarveSpec>& carverRegistry() {
    static const std::vector<CarveSpec> reg = buildRegistry();
    return reg;
}

std::vector<std::string> carverCategories() {
    std::vector<std::string> out;
    for (const auto& c : carverRegistry()) {
        if (std::find(out.begin(), out.end(), c.category) == out.end()) out.push_back(c.category);
    }
    std::sort(out.begin(), out.end());
    return out;
}

}  // namespace ghost

// Debugging probe: run one named validator over a ByteSource. Used by the
// standalone validator harness in tests; never called from the engine.
namespace ghost {
i64 probeValidate(const std::string& name, ByteSource& bs, i64 off, i64 max) {
    for (const auto& c : carverRegistry()) {
        if (c.name != name || !c.validator) continue;
        return c.validator(bs, off, max, c);
    }
    return -999;
}
}  // namespace ghost
