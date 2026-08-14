// GHOST RECOVER — mkv signature family (one file per format).
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
}bool knownEbmlId(u64 id) {
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
}static bool ebmlContainerId(u64 id) {
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
}i64 vEbml(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
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
}void registerFmt_mkv(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MKV", "mkv", "video", B({0x1A,0x45,0xDF,0xA3}), 32*GB, SizeMode::Container, vEbml);
      withConfirm(c, S("matroska"), -1, 8192); c.priority = 20; c.min_size = 1024; add(c); }
    { auto c = mk("WEBM", "webm", "video", B({0x1A,0x45,0xDF,0xA3}), 16*GB, SizeMode::Container, vEbml);
      withConfirm(c, S("webm"), -1, 8192); c.priority = 20; c.min_size = 1024; add(c); }
    { auto c = mk("EBML", "mkv", "video", B({0x1A,0x45,0xDF,0xA3}), 32*GB, SizeMode::Container, vEbml);
      c.min_size = 1024; add(c); }
}

}  // namespace ghost
