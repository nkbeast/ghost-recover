// GHOST RECOVER — mp3 signature family (one file per format).
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
}i64 vMp3(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
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
}void registerFmt_mp3(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MP3_ID3", "mp3", "audio", S("ID3"), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 512; c.priority = 15; add(c); }
    { auto c = mk("MP3_FRAME", "mp3", "audio", B({0xFF,0xFB}), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 2048; add(c); }
    { auto c = mk("MP3_FRAME_V2", "mp3", "audio", B({0xFF,0xF3}), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 2048; add(c); }
    { auto c = mk("MP3_FRAME_V25", "mp3", "audio", B({0xFF,0xE3}), 1*GB, SizeMode::FrameStream, vMp3);
      c.min_size = 2048; add(c); }
}

}  // namespace ghost
