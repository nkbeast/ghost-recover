// GHOST RECOVER — y4m signature family (one file per format).
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

i64 vY4m(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto head = s.read(off, 4096);
    if (head.size() < 16) return -1;
    if (std::memcmp(head.data(), "YUV4MPEG2", 9) != 0) return -1;
    i64 w = 0, h = 0, bpp = 0;
    bool sawW = false, sawH = false, sawC = false;
    size_t i = 9;
    for (; i < head.size(); i++) {
        u8 c = head[i];
        if (c == '\n') break;
        if (c == ' ') continue;
        size_t j = i + 1;
        if (c == 'W' || c == 'H') {
            i64 v = 0;
            bool digits = false;
            while (j < head.size() && head[j] >= '0' && head[j] <= '9') {
                v = v * 10 + (head[j] - '0');
                if (v > 100000) return -1;
                j++; digits = true;
            }
            if (!digits) return -1;
            if (c == 'W') { w = v; sawW = true; }
            else { h = v; sawH = true; }
        } else if (c == 'C') {
            sawC = true;
            if (j + 3 <= head.size() && std::memcmp(head.data() + j, "420", 3) == 0) bpp = 15;
            else if (j + 3 <= head.size() && std::memcmp(head.data() + j, "422", 3) == 0) bpp = 20;
            else if (j + 3 <= head.size() && std::memcmp(head.data() + j, "444", 3) == 0) bpp = 30;
            else if (j + 4 <= head.size() && std::memcmp(head.data() + j, "mono", 4) == 0) bpp = 10;
            else if (j + 3 <= head.size() && std::memcmp(head.data() + j, "400", 3) == 0) bpp = 10;
            else return -1;
            while (j < head.size() && head[j] != ' ' && head[j] != '\n') j++;
        } else if (c == 'F' || c == 'I' || c == 'A' || c == 'X' || c == 'N' ||
                   c == 'M' || c == 'S') {
            // Frame rate / interlacing / aspect / colour range / n/a params
            // vary by producer; skip the value token.
            while (j < head.size() && head[j] != ' ' && head[j] != '\n') j++;
        } else {
            return -1;
        }
        i = j - 1;
    }
    if (i >= head.size()) return -1;
    if (!sawW || !sawH || !sawC) return -1;
    i64 p = off + (i64)i + 1;
    i64 frameBytes = w * h * bpp / 10;
    for (int guard = 0; guard < (1 << 24); guard++) {
        if (p + 6 > off + max) break;
        auto f = s.read(p, 6);
        if (f.size() < 6 || std::memcmp(f.data(), "FRAME", 5) != 0) break;
        i64 q = p + 5;
        while (q < off + max && s.byte(q) != '\n') q++;
        if (q >= off + max) return -1;
        q++;
        if (q + frameBytes > off + max) return -1;
        p = q + frameBytes;
    }
    return (p > off) ? p - off : -1;
}void registerFmt_y4m(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("Y4M", "y4m", "video", S("YUV4MPEG2"), 32*GB, SizeMode::Header, vY4m));
}

}  // namespace ghost
