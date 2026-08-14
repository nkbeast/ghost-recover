// GHOST RECOVER — PNM_P1 image signatures; PNM_P2 image signatures; PNM_P3 image signatures; PNM_P4 image signatures; PNM_P5 image signatures; PNM_P6 image signatures.
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

i64 vPnm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 3 > off + max) return -1;
    u8 t = s.byte(off + 1);
    if (t < '1' || t > '6') return -1;
    i64 p = off + 2;
    bool ok = true;
    auto skipSpace = [&]() {
        while (p < off + max) {
            u8 b = s.byte(p);
            if (b == '#') {
                while (p < off + max && s.byte(p) != '\n') p++;
            } else if (b == ' ' || b == '\t' || b == '\r' || b == '\n') {
                p++;
            } else {
                break;
            }
        }
        if (p >= off + max) ok = false;
    };
    auto readInt = [&]() -> i64 {
        skipSpace();
        if (!ok) return -1;
        i64 v = 0;
        bool any = false;
        while (p < off + max) {
            u8 b = s.byte(p);
            if (b == '#' || b == ' ' || b == '\t' || b == '\r' || b == '\n') break;
            if (b < '0' || b > '9') { ok = false; return -1; }
            v = v * 10 + (b - '0');
            any = true;
            p++;
        }
        if (!any) { ok = false; return -1; }
        return v;
    };
    auto scanText = [&]() -> i64 {
        // ASCII raster: run until the first non-text byte (the zero gap).
        i64 p0 = off;
        while (p0 < off + max) {
            auto buf = s.read(p0, std::min<i64>(64 * KB, off + max - p0));
            if (buf.empty()) break;
            for (size_t i = 0; i < buf.size(); i++) {
                u8 c = buf[i];
                bool txt = (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r' || c >= 0x80;
                if (!txt) return (p0 + (i64)i) - off;
            }
            p0 += (i64)buf.size();
        }
        return -1;
    };
    i64 w = readInt(), h = readInt();
    if (!ok || w <= 0 || h <= 0) return -1;
    if (t == '1') return scanText();
    if (t == '4') {
        // advance past the whitespace separating the header from the raster
        if (p < off + max) {
            u8 b = s.byte(p);
            if (b == ' ' || b == '\t' || b == '\n' || b == '\r') p++;
            if (p < off + max && s.byte(p) == '#') {
                while (p < off + max && s.byte(p) != '\n') p++;
                if (p < off + max) p++;
            }
        }
        i64 row = (w + 7) / 8;
        i64 end = (p - off) + row * h;
        return end <= max ? end : -1;
    }
    i64 mx = readInt();
    if (!ok || mx < 1 || mx > 65535) return -1;
    if (t == '2' || t == '3') return scanText();
    // advance past the whitespace separating the header from the raster
    if (p < off + max) {
        u8 b = s.byte(p);
        if (b == ' ' || b == '\t' || b == '\n' || b == '\r') p++;
        if (p < off + max && s.byte(p) == '#') {
            while (p < off + max && s.byte(p) != '\n') p++;
            if (p < off + max) p++;
        }
    }
    i64 bpc = (mx > 255) ? 2 : 1;
    i64 dataLen = (t == '5') ? w * h * bpc : w * h * 3 * bpc;
    i64 end = (p - off) + dataLen;
    return end <= max ? end : -1;
}

void registerFmt_pnm(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PNM_P1", "pnm", "image", B({0x50, 0x31, 0x0A}), 64*MB, SizeMode::Container, vPnm); c.min_size = 32; add(c); }
    { auto c = mk("PNM_P2", "pgm", "image", B({0x50, 0x32, 0x0A}), 64*MB, SizeMode::Container, vPnm); c.min_size = 32; add(c); }
    { auto c = mk("PNM_P3", "ppm", "image", B({0x50, 0x33, 0x0A}), 64*MB, SizeMode::Container, vPnm); c.min_size = 32; add(c); }
    { auto c = mk("PNM_P4", "pbm", "image", B({0x50, 0x34, 0x0A}), 64*MB, SizeMode::Container, vPnm); c.min_size = 32; add(c); }
    { auto c = mk("PNM_P5", "pgm", "image", B({0x50, 0x35, 0x0A}), 64*MB, SizeMode::Container, vPnm); c.min_size = 32; add(c); }
    { auto c = mk("PNM_P6", "ppm", "image", B({0x50, 0x36, 0x0A}), 64*MB, SizeMode::Container, vPnm); c.min_size = 32; add(c); }
}

}  // namespace ghost
