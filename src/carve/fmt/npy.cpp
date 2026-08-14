// GHOST RECOVER — npy signature family (one file per format).
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
}void registerFmt_npy(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("NPY", "npy", "database", B({0x93,'N','U','M','P','Y'}), 8*GB, SizeMode::Header, vNpy));
}

}  // namespace ghost
