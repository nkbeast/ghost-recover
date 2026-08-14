// GHOST RECOVER — flac signature family (one file per format).
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

static u8 flacCrc8Step(u8 crc, u8 b) {
    crc ^= b;
    for (int i = 0; i < 8; i++)
        crc = (crc & 0x80) ? (u8)((crc << 1) ^ 0x07) : (u8)(crc << 1);
    return crc;
}static u16 flacCrc16Step(u16 crc, u8 b) {
    crc ^= (u16)b << 8;
    for (int i = 0; i < 8; i++)
        crc = (crc & 0x8000) ? (u16)((crc << 1) ^ 0x8005) : (u16)(crc << 1);
    return crc;
}i64 vFlac(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
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
        // whether the frame ends at i+3. Random payload data can fake a match
        // a couple percent of the time, and false matches in the data that
        // follows a deleted file would otherwise swallow the next region. So
        // of all matching positions take the LAST one that is followed by a
        // valid frame sync (the next frame's CRC boundary is always followed
        // by one); the final frame's own CRC sits at the very end and wins the
        // fallback. Matches beyond the encoder-stated max frame size are
        // rejected outright.
        i64 frameCap = maxFramesize > 0 ? (i64)maxFramesize : 8192;
        i64 limit = frameCap + 2;
        i64 L = -1;
        i64 fallback = -1;
        i64 runStart = -1;                       // first pos of a contiguous match run
        i64 prevMatch = -2;
        u16 crc16 = 0;
        const u8* d = fr.data();
        size_t n = fr.size();
        for (size_t i = 0; i + 3 <= n; i++) {
            crc16 = flacCrc16Step(crc16, d[i]);
            if (i + 1 >= (size_t)(at - q) && crc16 == ((u16)d[i + 1] << 8 | d[i + 2])) {
                i64 pos = (i64)i + 3;
                if (pos > limit) break;          // past the plausible frame end
                if (pos == prevMatch + 1) {
                    if (runStart < 0) runStart = prevMatch;
                } else {
                    runStart = -1;
                }
                prevMatch = pos;
                fallback = pos;
                if (pos + 4 <= (i64)n && d[pos] == 0xFF && (d[pos + 1] & 0xFC) == 0xF8)
                    L = pos;
            }
        }
        if (L < 0) {
            // No synced successor: final frame. A zero tail makes the CRC
            // match at every position, so prefer the start of a contiguous
            // run of matches — the genuine frame CRC — over the last match.
            L = (runStart >= 0) ? runStart : fallback;
        }
        if (L < 0) break;                        // no valid boundary: foreign data
        q += L;
        frames++;
    }
    if (frames == 0) return p - off;             // metadata-only file
    return q - off;
}void registerFmt_flac(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("FLAC", "flac", "audio", S("fLaC"), 4*GB, SizeMode::Container, vFlac);
      c.min_size = 1024; add(c); }
}

}  // namespace ghost
