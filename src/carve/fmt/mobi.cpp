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
            last_len = (len > 0 && len <= 1048576) ? (i64)len : 192;
        } else if (tag == 0x53524353) { // "SRCS"
            u32 len = s.be32(last_off + 4);
            last_len = (len > 0 && len <= 1048576) ? 8 + (i64)len : 16;
        } else if (tag == 0xE98E0D0A) { // MOBI EOF record marker
            last_len = 4;
        } else if (tag == 0x89504E47) { // PNG image record
            for (i64 p = last_off + 8; p + 12 <= off + max; p++) {
                if (s.be32(p + 4) == 0x49454E44) {
                    last_len = (p + 12) - last_off;
                    break;
                }
            }
        } else if ((tag & 0xFFFF0000) == 0xFFD80000) { // JPEG image record
            for (i64 p = last_off + 2; p + 2 <= off + max; p++) {
                if (s.be16(p) == 0xFFD9) {
                    last_len = (p + 2) - last_off;
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
}void registerFmt_mobi(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB, SizeMode::Header, vMobi);
      c.magic_offset = 60; add(c); }
}

}  // namespace ghost
