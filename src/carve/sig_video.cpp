// GHOST RECOVER — carver signature specs and validators for Video.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif

namespace ghost {


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
    u64 unknownParent = 0;
    int unknownChildDepth = -1;
    i64 firstSegEnd = -1;   // end of the first top-level Segment: the file's
                            // last byte — a real MKV is header+Segment, and
                            // anything after it is the next file on the disk.

    while (p < off + max && elems < 2000000) {
        while (depth > 0 && p >= limits[depth]) depth--;
        if (depth == 0 && firstSegEnd >= 0 && p >= firstSegEnd) break;
        int idW = 0;
        u64 id = ebmlNum(s, p, idW, false);
        if (idW == 0 || id == 0) break;
        // Inside an unknown-length Segment/Cluster only that container's
        // children may continue the walk. The classic streaming MKV writes
        // "Segment size = unknown", so the walker trusts the cluster chain to
        // end the file — but the chain of *sized* elements it happily merged
        // kept consuming the next file on the disk (another MKV's EBML header
        // is itself a valid sized element). Seeing a known id outside the
        // container's child set means a foreign document starts here: stop.
        if (unknownParent && depth == unknownChildDepth) {
            bool child = false;
            switch (unknownParent) {
                case 0x18538067:   // Segment children
                    child = id == 0x114D9B74 || id == 0x1549A966 ||
                            id == 0x1654AE6B || id == 0x1F43B675 ||
                            id == 0x1C53BB6B || id == 0x1941A469 ||
                            id == 0x1043A770 || id == 0x1254C367 ||
                            id == 0xEC || id == 0xBF;
                    break;
                case 0x1F43B675:   // Cluster children
                    child = id == 0xE7 || id == 0xAB || id == 0xA3 ||
                            id == 0xA0 || id == 0xA7 || id == 0xA5 ||
                            id == 0xEC || id == 0xEF || id == 0xA6;
                    break;
                default: child = true;
            }
            if (!child && knownEbmlId(id)) break;
        }
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
                if (id == 0x18538067 || id == 0x1F43B675) {
                    unknownParent = id;
                    unknownChildDepth = depth;
                }
                elems++;
                continue;
            }
            break;
        }
        i64 end = p + hdr + (i64)sz;
        if (end <= p || end > limits[depth]) break;
        lastValid = end;
        if (depth == 0 && id == 0x18538067 && firstSegEnd < 0) firstSegEnd = end;
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

// --- SWF: the header's u32 length field, verified by inflating CWS bodies --
i64 vSwf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 9);
    if (b.size() < 9) return -1;
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
    if (!fws) return -1;
    // FWS: the length field is only a hint — random data can forge it and
    // mask every file that follows. Walk the RECT field and the tag stream
    // to the End tag; the chain end must agree with the declared length.
    i64 nbits = b[8] >> 3;
    if (nbits > 31) return -1;
    i64 p = off + 8 + 1 + ((nbits * 4 + 7) / 8);
    if (p + 2 > off + max) return -1;
    i64 chainEnd = -1;
    int guard = 0;
    while (p + 2 <= off + max && guard++ < 100000) {
        u16 t = s.le16(p);
        int code = (t >> 6) & 0x3FF;
        i64 tl = t & 0x3F;
        i64 hdr = 2;
        if (tl == 0x3F) {
            if (p + 6 > off + max) return -1;
            tl = s.le32(p + 2);
            hdr = 6;
        }
        if (code == 0 && tl == 0) { chainEnd = p + hdr - off; break; }
        if (tl < 0 || p + hdr + tl > off + max) return -1;
        p += hdr + tl;
    }
    if (chainEnd < 0) return -1;
    i64 diff = chainEnd > (i64)len ? chainEnd - (i64)len : (i64)len - chainEnd;
    if (diff > 64) return -1;
    return chainEnd;
}

// --- ZWS (SWF in LZMA): the header self-describes the compressed payload
// ("ZWS" + version + u32 LE compressed length + u32 LE uncompressed length),
// so the file length is exact: 12 + compressedLen. ---------------------------
i64 vZws(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 16) return -1;
    u32 compLen = s.le32(off + 4);
    u32 uncompLen = s.le32(off + 8);
    if (compLen < 5 || compLen > 512 * MB || uncompLen < 1) return -1;
    i64 size = 12 + (i64)compLen;
    if (size > max) return -1;
    return size;
}

// --- Bink video: the header names the width/height/frames and the frame
// size table that immediately follows the header (4 bytes per frame), so the
// walk over the table yields the exact file length. Field layout (RAD bink):
// "BIK" + version char + u32 version/width/height/frames/fps/flags, then for
// v2/v3 the audio frame counts/rate; v1 keeps 12 reserved bytes. Frame sizes
// sum to the total frame data that follows the table. ------------------------
i64 vBik(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u8 ver = s.byte(off + 3);
    if (ver != 'b' && ver != 'f' && ver != 'g') return -1;
    i64 hdrLen = (ver == 'b') ? 40 : 48;
    if (max < hdrLen + 4) return -1;
    u32 width = s.le32(off + 8), height = s.le32(off + 12);
    u32 frames = s.le32(off + 16), fps = s.le32(off + 20);
    if (width < 1 || width > 32768 || height < 1 || height > 32768) return -1;
    if (frames < 1 || frames > (1u << 20)) return -1;
    if (fps < 1 || fps > 100000) return -1;
    u32 total = (ver == 'b') ? frames
                             : s.le32(off + 28) + s.le32(off + 32);
    if (total < 1 || total > (1u << 20)) return -1;
    i64 tableEnd = hdrLen + 4LL * total;
    if (tableEnd > max) return -1;
    i64 sum = 0;
    for (u32 i = 0; i < total; i++) {
        u32 fs = s.le32(off + hdrLen + 4LL * i);
        if (fs < 1 || fs > 128 * MB) return -1;
        sum += fs;
    }
    i64 size = tableEnd + sum;
    if (size > max) return -1;
    return size;
}

void registerVideo(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MP4", "mp4", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; c.min_size = 1024; add(c); }
    { auto c = mk("MOV", "mov", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("qt  "), 8); c.priority = 20; add(c); }
    { auto c = mk("M4V", "m4v", "video", S("ftyp"), 16*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("M4V "), 8); c.priority = 20; add(c); }
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
    { auto c = mk("FLV", "flv", "video", B({'F','L','V',0x01}), 8*GB, SizeMode::Container, vFlv);
      c.min_size = 1024; add(c); }
    { auto c = mk("WMV", "wmv", "video",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  8*GB, SizeMode::Container, vAsf);
      withConfirm(c, B({0xC0,0xEF,0x19,0xBC,0x4D,0x5B,0xCF,0x11}), -1, 65536); c.priority = 20;
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
    { auto c = mk("BIK", "bik", "video", S("BIK"), 4*GB, SizeMode::Container, vBik);
      c.min_size = 64; add(c); }
    add(mk("SWF", "swf", "video", S("FWS"), 256*MB, SizeMode::Header, vSwf));
    add(mk("SWF_ZLIB", "swf", "video", S("CWS"), 256*MB, SizeMode::Header, vSwf));
    { auto c = mk("SWF_LZMA", "swf", "video", S("ZWS"), 256*MB, SizeMode::Header, vZws);
      c.min_size = 32; add(c); }
    { auto c = mk("OGV", "ogv", "video", S("OggS"), 4*GB, SizeMode::Container, vOgg);
      withConfirm(c, S("theora"), -1, 512); c.priority = 20; c.min_size = 512; add(c); }
}

}  // namespace ghost
