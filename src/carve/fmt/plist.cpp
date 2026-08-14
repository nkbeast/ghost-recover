// GHOST RECOVER — plist signature family (one file per format).
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

i64 vPlistBin(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto hdr = s.read(off, 8);
    if (hdr.size() < 8 || std::memcmp(hdr.data(), "bplist0", 7) != 0) return -1;
    // Scan backwards for a plausible trailer: 6 zero bytes + 2 size bytes +
    // object count u64 BE + top object u64 BE + offset table offset u64 BE.
    const i64 kTail = 16 * 1024 * 1024;
    i64 scanFrom = off + max - 32;
    i64 scanTo = off + std::max<i64>(32, max - kTail);
    i64 end = -1;
    for (; scanFrom >= scanTo; scanFrom--) {
        auto t = s.read(scanFrom, 32);
        if (t.size() < 32) continue;   // tail reads can be short: keep scanning
        if (t[0] != 0 || t[1] != 0 || t[2] != 0 || t[3] != 0 || t[4] != 0 || t[5] != 0)
            continue;
        u8 offIntSize = t[6], refSize = t[7];
        if (offIntSize < 1 || offIntSize > 4 || refSize < 1 || refSize > 4) continue;
        u64 count = 0, top = 0, tableOff = 0;
        for (int k = 0; k < 8; k++) {
            count = count << 8 | t[8 + k];
            top = top << 8 | t[16 + k];
            tableOff = tableOff << 8 | t[24 + k];
        }
        if (count < 1 || count > (1u << 20)) continue;
        if (top >= count) continue;
        if (tableOff + (u64)count * offIntSize != (u64)(scanFrom - off)) continue;
        i64 tableStart = off + (i64)tableOff;
        // Validate every offset table entry points inside the table.
        u32 depth = 0;
        bool valid = true;
        auto check = [&]() -> bool {
            for (u32 i = 0; i < count; i++) {
                i64 p = tableStart + (i64)i * offIntSize;
                u64 v = 0;
                for (int k = 0; k < offIntSize; k++) v = v << 8 | s.byte(p + k);
                if (v >= (u64)(scanFrom - off)) return false;   // offset past file
            }
            return true;
        };
        if (!check()) continue;
        // Recursion-free walk of the top object's subtree.
        std::vector<u64> queue;
        queue.push_back(top);
        std::vector<bool> visited(count, false);
        size_t qPos = 0;
        while (qPos < queue.size() && depth < 4096) {
            u32 idx = (u32)queue[qPos++];
            if (idx >= count || visited[idx]) continue;
            visited[idx] = true;
            i64 objOff = off + (i64)tableOff + (i64)idx * offIntSize;
            u64 ooff = 0;
            for (int k = 0; k < offIntSize; k++) ooff = ooff << 8 | s.byte(objOff + k);
            u8 marker = s.byte(off + (i64)ooff);
            u8 type = marker & 0xF0;
            if (type == 0x00) {
                if (marker > 0x0B) { valid = false; break; }   // null/bool/fill
                continue;
            }
            if (type == 0x10) {              // integer
                int sz = marker & 0x0F;
                if (sz > 4) { valid = false; break; }
                continue;
            }
            if (type == 0x20 || type == 0x30) {   // real / date
                int sz = marker & 0x0F;
                if (sz > 3) { valid = false; break; }
                continue;
            }
            if (type == 0x40 || type == 0x50 || type == 0x60) {   // data/strings
                int sz = marker & 0x0F;
                if (sz == 0x0F) {
                    // 4-byte extended count.
                    auto c = s.read(off + (i64)ooff + 1, 4);
                    if (c.size() < 4) { valid = false; break; }
                } else if (sz > 14) { valid = false; break; }
                continue;
            }
            if (type == 0x80) {              // uid
                int sz = marker & 0x0F;
                if (sz > 8) { valid = false; break; }
                continue;
            }
            if (type == 0xA0 || type == 0xC0) {   // array / set
                u32 n = marker & 0x0F;
                if (n == 0x0F) {
                    auto c = s.read(off + (i64)ooff + 1, 4);
                    if (c.size() < 4) { valid = false; break; }
                    n = ((u32)c[0] << 24 | (u32)c[1] << 16 | (u32)c[2] << 8 | c[3]);
                }
                if (n > count) { valid = false; break; }
                for (u32 k = 0; k < n; k++) {
                    i64 rp = off + (i64)ooff + ((marker & 0x0F) == 0x0F ? 5 : 1) +
                              (i64)k * refSize;
                    u64 r = 0;
                    for (int z = 0; z < refSize; z++) r = r << 8 | s.byte(rp + z);
                    if (r >= count) { valid = false; break; }
                    queue.push_back(r);
                }
                if (!valid) break;
                depth++;
                continue;
            }
            if (type == 0xD0) {              // dict
                u32 n = marker & 0x0F;
                if (n == 0x0F) {
                    auto c = s.read(off + (i64)ooff + 1, 4);
                    if (c.size() < 4) { valid = false; break; }
                    n = ((u32)c[0] << 24 | (u32)c[1] << 16 | (u32)c[2] << 8 | c[3]);
                }
                if (n > count) { valid = false; break; }
                i64 rbase = (marker & 0x0F) == 0x0F ? 5 : 1;
                for (u32 k = 0; k < 2 * n; k++) {
                    i64 rp = off + (i64)ooff + rbase + (i64)k * refSize;
                    u64 r = 0;
                    for (int z = 0; z < refSize; z++) r = r << 8 | s.byte(rp + z);
                    if (r >= count) { valid = false; break; }
                    queue.push_back(r);
                }
                if (!valid) break;
                depth++;
                continue;
            }
            valid = false;   // unknown object type
            break;
        }
        if (!valid) continue;
        end = scanFrom - off + 32;   // file ends right after the trailer
        break;
    }
    if (end < 0 || end > max) return -1;
    return end;
}void registerFmt_plist(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PLIST_XML", "plist", "misc", S("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist"),
                  16*MB, SizeMode::Text, vText); add(c); }
    add(mk("PLIST_BIN", "plist", "misc", S("bplist00"), 16*MB, SizeMode::Header, vPlistBin));
}

}  // namespace ghost
