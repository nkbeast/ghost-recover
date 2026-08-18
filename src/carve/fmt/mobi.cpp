// GHOST RECOVER — mobi signature family (one file per format).
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

i64 vMobi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 60) != 0x424F4F4B) return -1;             // "BOOK"
    if (s.be32(off + 64) != 0x4D4F4249) return -1;             // "MOBI"
    u32 num = s.be16(off + 76);
    if (num < 1 || num > 100000) return -1;
    i64 table = off + 78;
    if (table + 8 * (i64)num > off + max) return -1;
    u32 prev = 78 + 8 * num;                   // record 0 must follow the table
    u32 last_rec_off = 0;
    for (u32 i = 0; i < num; i++) {
        u32 o = s.be32(table + 8 * (i64)i);
        if (o < prev) return -1;
        prev = o;
        if (i == num - 1) last_rec_off = o;
    }
    // Record 0 is the MOBI header; its first 8 bytes are the PalmDoc magic.
    u32 r0 = s.be32(table);
    auto sig = s.read(off + (i64)r0, 8);
    if (sig.size() < 8 || std::memcmp(sig.data(), "TEXtREAd", 8) != 0) return -1;
    i64 last_off = off + (i64)last_rec_off;
    if (last_off >= off + max) return -1;

    i64 last_len = 0;
    if (last_off + 4 <= off + max) {
        u32 tag = s.be32(last_off);
        if (tag == 0x464C4953) {        // "FLIS"
            u32 len = s.be32(last_off + 4);
            last_len = (len > 0 && len <= 1048576) ? 8 + (i64)len : 36;
        } else if (tag == 0x46434953) { // "FCIS"
            u32 len = s.be32(last_off + 4);
            last_len = (len > 0 && len <= 1048576) ? 8 + (i64)len : 44;
        } else if (tag == 0x46445354) { // "FDST"
            u32 len = s.be32(last_off + 4);
            last_len = (len > 0 && len <= 1048576) ? 8 + (i64)len : 12;
        } else if (tag == 0x494E4458) { // "INDX"
            u32 len = s.be32(last_off + 4);
            last_len = (len > 0 && len <= 1048576) ? 8 + (i64)len : 192;
        } else if (tag == 0x53524353) { // "SRCS"
            u32 len = s.be32(last_off + 4);
            last_len = (len > 0 && len <= 1048576) ? 8 + (i64)len : 16;
        } else if (tag == 0xE98E0D0A) { // MOBI EOF record marker
            last_len = 4;
        } else if (tag == 0x89504E47) { // PNG image record
            // Walk the chunk chain from the signature: each chunk is
            // [len(4)][type(4)][data][crc(4)]. A raw "find IEND" scan can
            // truncate on the byte sequence inside a compressed IDAT stream.
            i64 p = last_off + 8;
            while (p + 12 <= off + max) {
                u32 clen = s.be32(p);
                u32 ctype = s.be32(p + 4);
                if (ctype == 0x49454E44) { last_len = (p + 12) - last_off; break; }
                if (clen > 0x7FFFFFFF) break;
                i64 next = p + 12 + (i64)clen;
                if (next > off + max) break;
                p = next;
            }
        } else if ((tag & 0xFFFF0000) == 0xFFD80000) { // JPEG image record
            // Walk the segment chain from SOI. EOI (FF D9) is only valid at
            // the real end of the image; a byte scan would truncate on an
            // FF D9 inside an APPn/COM payload. Segments are skipped by
            // their declared length, and the terminator is only searched
            // for inside entropy-coded data (after SOS).
            i64 p = last_off + 2;
            while (p + 2 <= off + max) {
                u16 m = s.be16(p);
                if (m == 0xFFD9) { last_len = (p + 2) - last_off; break; }
                if (m == 0xFFD8) { p += 2; continue; }   // SOI carries no length
                if ((m & 0xFF00) != 0xFF00) break;       // not a marker
                p += 2;
                if (p + 2 > off + max) break;
                u16 seg = s.be16(p);
                if (seg < 2) break;
                p += (i64)seg;
                if (m == 0xFFDA) {       // SOS: entropy data until EOI
                    for (; p + 2 <= off + max; p++) {
                        if (s.be16(p) == 0xFFD9) {
                            last_len = (p + 2) - last_off;
                            break;
                        }
                    }
                    break;
                }
            }
        }
    }

    if (last_len <= 0) {
        if (num > 1) {
            i64 prev_span = (i64)last_rec_off - (i64)r0;
            i64 avg_size = prev_span / (i64)(num - 1);
            last_len = std::min<i64>(std::max<i64>(avg_size, 16), 65536);
        } else {
            last_len = 240;
        }
    }

    i64 total_size = (i64)last_rec_off + last_len;
    if (total_size > max) return -1;
    return total_size;
}

void registerFmt_mobi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB, SizeMode::Header, vMobi);
      c.magic_offset = 60; add(c); }
}

}  // namespace ghost
