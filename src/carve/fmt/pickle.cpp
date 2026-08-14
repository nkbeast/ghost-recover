// GHOST RECOVER — pickle signature family (one file per format).
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

i64 vPickle(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 2);
    if (b.empty()) return -1;
    bool ascii = b[0] != 0x80;
    if (!ascii && (b.size() < 2 || b[1] > 5)) return -1;
    const i64 end = off + max;
    i64 pos = ascii ? off : off + 2;
    while (pos < end) {
        u8 op = s.byte(pos);
        if (op == 0x2E) {                       // STOP: the pickle ends here
            if (pos - off + 1 < 10) return -1;  // reject empty-opcode stubs
            return pos - off + 1;
        }
        i64 n;
        switch (op) {
            case 0x80: {                        // PROTO (never in ascii mode)
                u8 p = s.byte(pos + 1);
                if (p > 5) return -1;
                pos += 2;
                continue;
            }
            case 0x4A: case 0x54: case 0x58: {  // BININT / BINSTRING / BINUNICODE: u32
                auto v = s.read(pos + 1, 4);
                if (v.size() < 4) return -1;
                n = (i64)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < 0 || pos + 5 + n > end) return -1;
                pos += 5 + n;
                continue;
            }
            case 0x5A: {                        // LONG_BINUNICODE: u64 len (little-endian)
                auto v = s.read(pos + 1, 8);
                if (v.size() < 8) return -1;
                i64 n64 = 0;
                for (size_t k = 0; k < 8; k++) n64 |= (i64)v[k] << (8 * k);
                if (n64 < 0 || pos + 9 + n64 > end) return -1;
                pos += 9 + n64;
                continue;
            }
            case 0x4B: case 0x55: case 0x68: case 0x71:   // 1-byte value/ref
                if (pos + 2 > end) return -1;
                pos += 2;
                continue;
            case 0x4D:                          // BININT2 (u16 value)
                if (pos + 3 > end) return -1;
                pos += 3;
                continue;
            case 0x72: case 0x6A:               // LONG_BINPUT / LONG_BINGET: u32 ref
                if (pos + 5 > end) return -1;
                pos += 5;
                continue;
            case 0x47:                          // BINFLOAT (8 bytes)
                if (pos + 9 > end) return -1;
                pos += 9;
                continue;
            case 0x49: case 0x4C: case 0x53: case 0x56: case 0x50: {  // newline-terminated text
                while (pos < end && s.byte(pos) != 0x0A) pos++;
                if (pos >= end) return -1;
                pos++;
                continue;
            }
            case 0x70: case 0x67:               // PUT / GET: ascii refno line
                if (!ascii) break;              // binary: plain ref opcode
                while (pos < end && s.byte(pos) != 0x0A) pos++;
                if (pos >= end) return -1;
                pos++;
                continue;
            case 0x63:                          // GLOBAL: two '\n'-terminated strings
                for (int s2 = 0; s2 < 2; s2++) {
                    while (pos < end && s.byte(pos) != 0x0A) pos++;
                    if (pos >= end) return -1;
                    pos++;
                }
                continue;
            case 0x69: {                        // INST: module\0class\0 style line
                while (pos < end && s.byte(pos) != 0x0A) pos++;
                if (pos >= end) return -1;
                pos++;
                continue;
            }
            case 0x43: {                   // SHORT_BINSTRING / SHORT_BINBYTES
                u8 len = s.byte(pos + 1);
                if (pos + 2 + len > end) return -1;
                pos += 2 + len;
                continue;
            }
            case 0x8D: case 0x96: {        // BINBYTES8 / BYTEARRAY8: u64 len (little-endian)
                auto v = s.read(pos + 1, 8);
                if (v.size() < 8) return -1;
                i64 n64 = 0;
                for (size_t k = 0; k < 8; k++) n64 |= (i64)v[k] << (8 * k);
                if (n64 < 0 || pos + 9 + n64 > end) return -1;
                pos += 9 + n64;
                continue;
            }
            case 0x95: {                   // FRAME (u64 len) — protocol 4+
                i64 fstart = pos;
                if (fstart + 9 > end) return -1;
                auto v = s.read(pos + 1, 8);
                if (v.size() < 8) return -1;
                i64 n64 = 0;
                for (size_t k = 0; k < 8; k++) n64 |= (i64)v[k] << (8 * k);
                if (n64 <= 0 || n64 > end - pos - 9) return -1;
                i64 want = fstart + 9 + n64;
                // CPython packs the whole pickle (STOP included) into the last
                // frame; the frame's final byte being STOP ends the file there.
                // The frame may claim a byte past EOF (short frames are legal):
                // walk back to the last readable byte and test it instead.
                for (i64 k = want - 1; k >= fstart + 9; k--) {
                    auto tail = s.read(k, 1);
                    if (!tail.empty() && tail[0] == 0x2E) return k - off + 1;
                    if (!tail.empty()) break;
                }
                // Otherwise hop to the frame end and keep walking (nested
                // frames or an outer STOP that follows this one).
                pos = std::min<i64>(want, end - 1);
                continue;
            }
            case 0x8E: {                 // LONG1 (u8 count)
                u8 len = s.byte(pos + 1);
                if (pos + 2 + len > end) return -1;
                pos += 2 + len;
                continue;
            }
            case 0x8F: {                 // LONG4 (u32 count)
                auto v = s.read(pos + 1, 4);
                u32 len = (u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24;
                if (v.size() < 4 || pos + 5 + len > end) return -1;
                pos += 5 + len;
                continue;
            }
            default: break;
        }
        switch (op) {
            case 0x28: case 0x30: case 0x31: case 0x32: case 0x4E: case 0x52:
            case 0x61: case 0x62: case 0x64: case 0x65: case 0x67: case 0x6C:
            case 0x6F: case 0x70: case 0x73: case 0x74: case 0x75: case 0x29:
            case 0x5D: case 0x7D: case 0x5B: case 0x85: case 0x86: case 0x87:
            case 0x88: case 0x89: case 0x93: case 0x94:
                pos += 1;
                continue;
            default:
                return -1;   // opcode outside the covered set: not a pickle
        }
    }
    return -1;
}void registerFmt_pickle(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PICKLE", "pkl", "database", B({0x80,0x04,0x95}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE2", "pkl", "database", B({0x80,0x02}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE3", "pkl", "database", B({0x80,0x03}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE5", "pkl", "database", B({0x80,0x05}), 512*MB, SizeMode::Header, vPickle);
      c.whole_file = true; add(c); }
    { auto c = mk("PICKLE_P0", "pkl", "database", B({0x28,0x64,0x70,0x30,0x0A}), 512*MB,
                  SizeMode::Header, vPickle); c.whole_file = true; add(c); }
    { auto c = mk("PICKLE_P1", "pkl", "database", B({0x7D,0x71,0x00,0x28}), 512*MB,
                  SizeMode::Header, vPickle); c.whole_file = true; add(c); }
}

}  // namespace ghost
