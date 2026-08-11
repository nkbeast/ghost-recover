// GHOST//RECOVER — carver signature registry and format validators.
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
    while (p + 4 <= off + max && segments < 65536) {
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
        u16 len = s.be16(p + 2);
        if (len < 2) return -1;
        segments++;
        if (marker == 0xDA) {
            // Start of scan: entropy data follows until the next real marker.
            i64 q = p + 2 + len;
            while (q + 1 < off + max) {
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
    }
    return segments >= 2 ? 0 : -1;   // structurally plausible, length unknown
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
            // StripOffsets/StripByteCounts and the JPEG-preview pointers tell
            // us where the pixel data actually ends.
            if ((tag == 273 || tag == 324 || tag == 513) && n == 1 && bytes <= 4) {
                i64 so = rd32(e + 8);
                furthest = std::max(furthest, so);
            }
            if ((tag == 279 || tag == 325 || tag == 514) && n == 1 && bytes <= 4) {
                furthest += rd32(e + 8);
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
        if (!knownEbmlId(id)) {
            if (++unknownStreak > 2) break;
            p++;
            elems++;
            continue;
        }
        unknownStreak = 0;
        valid++;
        int szW = 0;
        u64 sz = ebmlNum(s, p + idW, szW, true);
        if (szW == 0) break;
        i64 hdr = idW + szW;
        bool unknownSize = true;
        {
            // All-ones size field means "unknown length".
            u64 allOnes = (szW >= 8) ? ~0ull : ((1ull << (szW * 7)) - 1);
            unknownSize = (sz >= allOnes);
        }
        if (unknownSize) {
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
i64 vFlac(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 4;
    bool last = false;
    int blocks = 0;
    while (!last && p + 4 <= off + max && blocks < 128) {
        auto h = s.read(p, 4);
        if (h.size() < 4) break;
        last = (h[0] & 0x80) != 0;
        u8 type = h[0] & 0x7F;
        if (type > 6 && type != 127) return -1;
        u32 len = (u32)h[1] << 16 | (u32)h[2] << 8 | h[3];
        if (p + 4 + (i64)len > off + max) break;
        p += 4 + len;
        blocks++;
    }
    if (blocks == 0) return -1;
    // Frames follow: sync 0xFF 0xF8/0xF9. Track the last one and stop after a
    // long run without a sync word.
    i64 lastSync = p;
    i64 q = p;
    const i64 kMaxGap = 1 << 20;
    while (q + 2 < off + max) {
        auto chunk = s.read(q, 64 * KB);
        if (chunk.empty()) break;
        bool any = false;
        for (size_t i = 0; i + 1 < chunk.size(); i++) {
            if (chunk[i] == 0xFF && (chunk[i + 1] & 0xFC) == 0xF8) {
                lastSync = q + (i64)i;
                any = true;
            }
        }
        q += (i64)chunk.size();
        if (!any && q - lastSync > kMaxGap) break;
    }
    if (lastSync == p) return p - off;
    i64 size = lastSync + 8192 - off;
    return std::min(size, max);
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
    while (p + 4 <= off + max && frames < 4000000) {
        auto f = s.read(p, 4);
        if (f.size() < 4 || f[0] != 0xFF) break;
        int layer = 0, ver = 0, sr = 0;
        int size = mpegFrameSize(f[1], f[2], f[3], &layer, &ver, &sr);
        if (!size) break;
        if (frames == 0) { layer0 = layer; ver0 = ver; sr0 = sr; }
        else if (layer != layer0 || ver != ver0 || sr != sr0) break;
        if (p + size > off + max) break;
        lastEnd = p + size;
        p = lastEnd;
        frames++;
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
    }
    if (frames < 4) return -1;
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
    while (p + 6 <= off + max && frames < 2000000) {
        auto h = s.read(p, 6);
        if (h.size() < 6 || h[0] != 0x0B || h[1] != 0x77) break;
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
    while (p < off + max && frames < 2000000) {
        u8 toc = s.byte(p);
        int mode = (toc >> 3) & 0xF;
        int sz = wb ? kWb[mode] : kNb[mode];
        if (sz == 0) break;
        p += 1 + sz;
        frames++;
    }
    if (frames < 4) return -1;
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

// --- gzip: walk deflate members is expensive; use the member chain. --------
i64 vGzip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 10);
    if (h.size() < 10 || h[0] != 0x1F || h[1] != 0x8B || h[2] != 8) return -1;
    if (h[3] & 0xE0) return -1;                 // reserved flags must be zero
    return 0;                                    // structurally valid, size unknown
}

// --- bzip2 -----------------------------------------------------------------
i64 vBzip2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 10);
    if (h.size() < 10) return -1;
    if (h[3] < '1' || h[3] > '9') return -1;
    // Blocks start with the pi magic 0x314159265359; the stream ends with
    // 0x177245385090 followed by a CRC.
    static const u8 kEnd[6] = {0x17, 0x72, 0x45, 0x38, 0x50, 0x90};
    const i64 kStep = 1 * MB;
    for (i64 base = 0; base < max; base += kStep - 8) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 6) break;
        for (size_t i = 0; i + 6 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, kEnd, 6) == 0)
                return base + (i64)i + 10;       // end magic + CRC, rounded up
        }
        if ((i64)buf.size() < std::min(kStep, max - base)) break;
    }
    return 0;
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
i64 vRar(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 8);
    if (h.size() < 8) return -1;
    bool v5 = (h[6] == 0x01 && h[7] == 0x00);
    // Walk block headers; RAR4 blocks carry a 16-bit size at +5.
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
    return 0;
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
    i64 start = off;
    i64 p = start;
    int members = 0;
    while (p + 512 <= start + max && members < 1000000) {
        auto h = s.read(p, 512);
        if (h.size() < 512) break;
        bool allZero = true;
        for (u8 c : h) if (c) { allZero = false; break; }
        if (allZero) { p += 512; break; }                 // end-of-archive marker
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
    return (p + 512) - start;
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
    u64 chunkCount = s.le32(off + 0x28);
    if (chunkCount == 0 || chunkCount > 1000000) return -1;
    i64 total = 4096 + (i64)chunkCount * 65536;
    if (total > max) return -1;
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

// --- PDF: find the last %%EOF. ---------------------------------------------
i64 vPdf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    const i64 kStep = 1 * MB;
    i64 lastEof = -1;
    for (i64 base = 0; base < max; base += kStep - 8) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 5) break;
        for (size_t i = 0; i + 5 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, "%%EOF", 5) == 0) lastEof = base + (i64)i + 5;
        }
        if ((i64)buf.size() < std::min(kStep, max - base)) break;
        // A PDF rarely continues far past its last EOF; stop once we have one
        // and the stream has gone quiet.
        if (lastEof >= 0 && base > lastEof + 16 * MB) break;
    }
    if (lastEof < 0) return -1;
    // Trailing newline after %%EOF.
    auto tail = s.read(off + lastEof, 2);
    if (!tail.empty() && (tail[0] == '\r' || tail[0] == '\n')) lastEof++;
    if (tail.size() > 1 && tail[0] == '\r' && tail[1] == '\n') lastEof++;
    return lastEof;
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
        p++;
        // LEB128 section length
        u64 len = 0;
        int shift = 0;
        while (p < max && shift < 35) {
            u8 b = s.byte(off + p++);
            len |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) break;
            shift += 7;
        }
        if (p + (i64)len > max) break;
        p += (i64)len;
        sections++;
    }
    if (sections < 1) return -1;
    return p;
}

// --- Java class ------------------------------------------------------------
i64 vClass(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 minor = s.be16(off + 4);
    u16 major = s.be16(off + 6);
    (void)minor;
    if (major < 45 || major > 80) return -1;
    u16 cpCount = s.be16(off + 8);
    if (cpCount < 2 || cpCount > 65534) return -1;
    return 0;   // structurally sound; length needs a full constant-pool walk
}

// --- DEX -------------------------------------------------------------------
i64 vDex(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 32);
    if (size < 112 || (i64)size > max) return -1;
    return size;
}

// --- QCOW2 -----------------------------------------------------------------
i64 vQcow(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 version = s.be32(off + 4);
    if (version != 2 && version != 3) return -1;
    return 0;
}

// --- VHD footer / VHDX / VDI ----------------------------------------------
i64 vVhdx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    (void)s; (void)off;
    return std::min<i64>(max, 4 * GB);
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
    add(mk("JXL", "jxl", "image", B({0xFF,0x0A}), 256*MB));
    add(mk("JXL_ISO", "jxl", "image", B({0x00,0x00,0x00,0x0C,'J','X','L',0x20}), 256*MB));
    add(mk("QOI", "qoi", "image", S("qoif"), 256*MB));
    add(mk("DDS", "dds", "image", S("DDS "), 512*MB));
    add(mk("EXR", "exr", "image", B({0x76,0x2F,0x31,0x01}), 512*MB));
    add(mk("HDR", "hdr", "image", S("#?RADIANCE"), 256*MB));
    add(mk("PCX", "pcx", "image", B({0x0A,0x05,0x01,0x08}), 64*MB));
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
    { auto c = mk("MPEG_PS", "mpg", "video", B({0x00,0x00,0x01,0xBA}), 8*GB,
                  SizeMode::FrameStream, vMpegPs); c.min_size = 2048; add(c); }
    { auto c = mk("MPEG_VES", "mpv", "video", B({0x00,0x00,0x01,0xB3}), 4*GB); c.min_size = 2048; add(c); }
    add(mk("RM", "rm", "video", S(".RMF"), 4*GB));
    add(mk("MXF", "mxf", "video", B({0x06,0x0E,0x2B,0x34,0x02,0x05,0x01,0x01}), 32*GB));
    add(mk("IVF", "ivf", "video", S("DKIF"), 4*GB));
    add(mk("Y4M", "y4m", "video", S("YUV4MPEG2"), 32*GB));
    add(mk("BIK", "bik", "video", S("BIK"), 4*GB));
    add(mk("SWF", "swf", "video", S("FWS"), 256*MB));
    add(mk("SWF_ZLIB", "swf", "video", S("CWS"), 256*MB));
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
    add(mk("DTS", "dts", "audio", B({0x7F,0xFE,0x80,0x01}), 1*GB));
    add(mk("APE", "ape", "audio", S("MAC "), 1*GB));
    add(mk("WV", "wv", "audio", S("wvpk"), 1*GB));
    add(mk("MPC", "mpc", "audio", S("MPCK"), 512*MB));
    add(mk("MPC_SV7", "mpc", "audio", S("MP+"), 512*MB));
    add(mk("AU", "au", "audio", B({0x2E,'s','n','d'}), 512*MB));
    add(mk("CAF", "caf", "audio", S("caff"), 2*GB));
    add(mk("VOC", "voc", "audio", S("Creative Voice File"), 256*MB));
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
    add(mk("CPIO_ASCII", "cpio", "archive", S("070701"), 2*GB));
    add(mk("CPIO_ODC", "cpio", "archive", S("070707"), 2*GB));
    add(mk("CPIO_BIN", "cpio", "archive", B({0xC7,0x71}), 2*GB));
    add(mk("LZH", "lzh", "archive", S("-lh"), 512*MB));
    add(mk("ACE", "ace", "archive", S("**ACE**"), 512*MB));
    add(mk("SIT", "sit", "archive", S("StuffIt"), 512*MB));
    add(mk("WIM", "wim", "archive", S("MSWIM"), 8*GB));
    add(mk("DMG_KOLY", "dmg", "archive", S("koly"), 16*GB));
    add(mk("ISO9660", "iso", "archive", S("CD001"), 16*GB));
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
    add(mk("NPY", "npy", "database", B({0x93,'N','U','M','P','Y'}), 8*GB));
    add(mk("MAT", "mat", "database", S("MATLAB 5.0 MAT-file"), 8*GB));
    add(mk("PICKLE", "pkl", "database", B({0x80,0x04,0x95}), 512*MB));

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
    add(mk("PKCS12", "p12", "crypto", B({0x30,0x82}), 4*MB));
    add(mk("JKS", "jks", "crypto", B({0xFE,0xED,0xFE,0xED}), 16*MB));
    add(mk("KDBX", "kdbx", "crypto", B({0x03,0xD9,0xA2,0x9A,0x67,0xFB,0x4B,0xB5}), 256*MB));
    add(mk("KDB", "kdb", "crypto", B({0x03,0xD9,0xA2,0x9A,0x65,0xFB,0x4B,0xB5}), 256*MB));
    add(mk("GPG_KEYRING", "gpg", "crypto", B({0x99,0x01}), 16*MB));
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
    add(mk("PYC", "pyc", "executable", B({0x6F,0x0D,0x0D,0x0A}), 64*MB));

    // ---------------- forensic artefacts ----------------
    { auto c = mk("PCAP_LE", "pcap", "forensic", B({0xD4,0xC3,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_BE", "pcap", "forensic", B({0xA1,0xB2,0xC3,0xD4}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS", "pcap", "forensic", B({0xA1,0xB2,0x3C,0x4D}), 8*GB,
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
    add(mk("VDI", "vdi", "vm", S("<<< Oracle VM VirtualBox Disk Image >>>"), 64*GB));
    add(mk("VHD", "vhd", "vm", S("conectix"), 64*GB));
    { auto c = mk("VHDX", "vhdx", "vm", S("vhdxfile"), 64*GB, SizeMode::Heuristic, vVhdx);
      add(c); }
    add(mk("OVA", "ova", "vm", S("ustar"), 64*GB));

    // ---------------- fonts ----------------
    { auto c = mk("TTF", "ttf", "font", B({0x00,0x01,0x00,0x00,0x00}), 64*MB,
                  SizeMode::Header, vSfnt); c.min_size = 2048; add(c); }
    { auto c = mk("OTF", "otf", "font", S("OTTO"), 64*MB, SizeMode::Header, vSfnt);
      c.min_size = 128; add(c); }
    { auto c = mk("TTC", "ttc", "font", S("ttcf"), 64*MB); add(c); }
    { auto c = mk("WOFF", "woff", "font", S("wOFF"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 44; add(c); }
    { auto c = mk("WOFF2", "woff2", "font", S("wOF2"), 64*MB, SizeMode::Header, vWoff);
      c.min_size = 48; add(c); }

    // ---------------- CAD / 3D ----------------
    add(mk("DWG", "dwg", "misc", S("AC10"), 512*MB));
    add(mk("DXF", "dxf", "misc", S("  0\r\nSECTION"), 512*MB));
    add(mk("STL_ASCII", "stl", "misc", S("solid "), 512*MB));
    add(mk("BLEND", "blend", "misc", S("BLENDER"), 4*GB));
    add(mk("FBX", "fbx", "misc", S("Kaydara FBX Binary"), 2*GB));
    add(mk("GLTF_BIN", "glb", "misc", S("glTF"), 2*GB));

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
    add(mk("PLIST_BIN", "plist", "misc", S("bplist00"), 16*MB));
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
