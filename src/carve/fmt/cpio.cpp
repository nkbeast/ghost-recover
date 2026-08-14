// GHOST RECOVER — cpio signature family (one file per format).
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
        // Every entry must carry the archive magic: the walk jumps straight
        // to the next header via namesize/filesize, so without this check
        // arbitrary data can chain (random filesize fields advance the walk
        // and the "magic" from the candidate offset is never re-tested) and
        // a bogus archive can span hundreds of MB.
        bool okMagic = newc ? (std::memcmp(h.data(), "070701", 6) == 0 ||
                               std::memcmp(h.data(), "070702", 6) == 0)
                            : (odc ? std::memcmp(h.data(), "070707", 6) == 0
                                   : (h[0] == (u8)0xC7 &&
                                      (h[1] == (u8)0x71 || h[1] == (u8)0x72)));
        if (!okMagic) return -1;
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
            ns = s.be16(p + 20);
            fs = ((i64)s.be16(p + 22) << 16) | s.be16(p + 24);
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
}void registerFmt_cpio(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("CPIO_ASCII", "cpio", "archive", S("070701"), 2*GB, SizeMode::Container, vCpio));
    add(mk("CPIO_ODC", "cpio", "archive", S("070707"), 2*GB, SizeMode::Container, vCpio));
    add(mk("CPIO_BIN", "cpio", "archive", B({0xC7,0x71}), 2*GB, SizeMode::Container, vCpio));
}

}  // namespace ghost
