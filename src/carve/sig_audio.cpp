// GHOST RECOVER — carver signature specs and validators for Audio.
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


// --- AIFF / other IFF: big-endian length. ----------------------------------
i64 vIff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 sz = s.be32(off + 4);
    i64 total = (i64)sz + 8;
    if (total < 12 || total > max) return -1;
    return total;
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
    int frames = 0, sr0 = -1, prof0 = -1, h1_0 = -1;
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
        if (frames == 0) { sr0 = sr; prof0 = prof; h1_0 = h[1]; }
        else if (sr != sr0 || prof != prof0 || h[1] != h1_0) break;
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
            gap = nxt[0] != 0xFF || (nxt[1] & 0xF0) != 0xF0 || nxt[1] != h1_0 ||
                  len2 < 7 || len2 > 8192 || sr2 != sr0 || prof2 != prof0;
        }
        if (gap) {
            const i64 scanEnd = std::min<i64>(off + max, p + kResync);
            auto win = s.read(p, scanEnd - p);
            bool found = false;
            for (i64 i = 0; i + 7 <= (i64)win.size(); i++) {
                if (win[(size_t)i] != 0xFF || (win[(size_t)(i + 1)] & 0xF0) != 0xF0 ||
                    win[(size_t)(i + 1)] != h1_0) continue;
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
    int chunks = 0;
    while (p + 12 <= off + max && chunks < 100000) {
        auto t = s.read(p, 4);
        if (t.size() < 4) return -1;
        auto szb = s.read(p + 4, 8);
        if (szb.size() < 8) return -1;
        u64 sz = 0;
        for (int k = 0; k < 8; k++) sz = sz << 8 | szb[k];
        if (sz > (u64)max) return -1;
        // Chunk types are four printable ASCII letters; a run of zeroes (the
        // gap after a deleted file) or foreign data stops the chain here.
        bool printable = true;
        for (u8 c : t)
            if (c < 0x20 || c > 0x7E) { printable = false; break; }
        if (!printable) break;
        p += 12 + (i64)sz;
        chunks++;
    }
    if (chunks == 0) return -1;
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
        if (s.byte(z) == 0) break;
        taken++;
        z++;
    }
    if (taken > 0 && taken <= 16) return z - off;
    return terminator - off;
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

// --- MPC (Musepack): both stream versions carry a total size in the header.
// SV8 "MPCK": u32 LE size at +8 (whole stream incl. 8-byte header). SV7 "MP+":
// version byte 0x07 at +3, u32 BE size at +4 (incl. 16-byte header). A size
// that parses and fits the device is exact, so MPC is a length-verified file.
i64 vMpc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 16) return -1;
    if (s.byte(off) == 'M' && s.byte(off + 1) == 'P' && s.byte(off + 2) == 'C' &&
        s.byte(off + 3) == 'K') {
        i64 size = (i64)s.le32(off + 8);
        if (size < 12 || size > max) return -1;
        return size;
    }
    if (s.byte(off + 3) != 0x07) return -1;
    i64 size = (i64)s.be32(off + 4);
    if (size < 16 || size > max) return -1;
    return size;
}

i64 vWv(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // WavPack: a chain of wvpk blocks; each block's ckSize spans everything
    // after its own 8-byte header, so p += 8 + ckSize lands exactly on the
    // next block. The final block sets flag 0x0002; without it (some encoders
    // omit the flag), the chain runs to the region boundary, where the byte
    // right after the last block is not another wvpk header.
    i64 p = off;
    int blocks = 0;
    while (p + 32 <= off + max && blocks < 1000000) {
        auto h = s.read(p, 32);
        if (h.size() < 32) return -1;
        if (h[0] != 'w' || h[1] != 'v' || h[2] != 'p' || h[3] != 'k') return -1;
        u32 ckSize = s.le32(p + 4);
        if (ckSize < 24) return -1;
        if (p + 8 + (i64)ckSize > off + max) return -1;
        u32 flags = s.le32(p + 23);
        p += 8 + (i64)ckSize;
        blocks++;
        if (flags & 0x0002) break;
        if (p + 4 <= off + max) {
            auto nx = s.read(p, 4);
            if (nx.size() < 4 || memcmp(nx.data(), "wvpk", 4) != 0) break;
        }
    }
    if (blocks == 0) return -1;
    return p - off;
}

void registerAudio(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("M4A", "m4a", "audio", S("ftyp"), 4*GB, SizeMode::Container, vMp4);
      c.magic_offset = 4; withConfirm(c, S("M4A "), 8); c.priority = 20; add(c); }
    { auto c = mk("WAV", "wav", "audio", S("RIFF"), 4*GB, SizeMode::Header, vRiff);
      withConfirm(c, S("WAVE"), 8); c.priority = 20; c.min_size = 44; add(c); }
    { auto c = mk("WMA", "wma", "audio",
                  B({0x30,0x26,0xB2,0x75,0x8E,0x66,0xCF,0x11,0xA6,0xD9,0x00,0xAA,0x00,0x62,0xCE,0x6C}),
                  2*GB, SizeMode::Container, vAsf);
      withConfirm(c, B({0x40,0x9E,0x69,0xF8,0x4D,0x5B,0xCF,0x11}), -1, 65536); c.priority = 20;
      c.min_size = 1024; add(c); }
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
    add(mk("WV", "wv", "audio", S("wvpk"), 1*GB, SizeMode::Container, vWv));
    { auto c = mk("MPC", "mpc", "audio", S("MPCK"), 512*MB, SizeMode::Header, vMpc);
      c.min_size = 32; add(c); }
    { auto c = mk("MPC_SV7", "mpc", "audio", S("MP+"), 512*MB, SizeMode::Header, vMpc);
      c.min_size = 32; add(c); }
    add(mk("AU", "au", "audio", B({0x2E,'s','n','d'}), 512*MB, SizeMode::Container, vAu));
    add(mk("CAF", "caf", "audio", S("caff"), 2*GB, SizeMode::Container, vCaf));
    add(mk("VOC", "voc", "audio", S("Creative Voice File"), 256*MB, SizeMode::Container, vVoc));
    add(mk("MOD_IT", "it", "audio", S("IMPM"), 128*MB));
    { auto c = mk("MOD_S3M", "s3m", "audio", S("SCRM"), 128*MB);
      c.magic_offset = 44; add(c); }
    add(mk("MOD_XM", "xm", "audio", S("Extended Module:"), 128*MB));
}

}  // namespace ghost
