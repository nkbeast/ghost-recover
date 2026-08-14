// GHOST RECOVER — pyc signature family (one file per format).
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

i64 vPyc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 16);
    if (h.size() < 16) return -1;
    u32 flags = (u32)h[4] | (u32)h[5] << 8 | (u32)h[6] << 16 | (u32)h[7] << 24;
    if (flags & 0x1F) return -1;                  // hash-based pyc: no end marker
    const i64 end = off + max;
    i64 pos = off + 16;
    enum : u8 { K_ITEMS, K_DICT, K_CODE };
    struct Frame { i64 left; u8 kind; u8 tail; };
    Frame frames[64];
    frames[0] = {1, K_ITEMS, 0};                  // root: one object to walk
    int depth = 1;
    u64 objects = 0;
    for (;;) {
        if (pos >= end) return -1;
        Frame& f = frames[depth - 1];
        if (f.left == 0) {
            if (f.kind == K_CODE && !f.tail) {
                pos += 4;                         // co_firstlineno
                f.tail = 1;
                f.left = 2;                       // lnotab + exceptiontable
                if (pos > end) return -1;
                continue;
            }
            depth--;
            if (depth == 0) return pos - off;     // walk complete
            continue;
        }
        if (++objects > 1000000) return -1;
        u8 t = s.byte(pos);
        pos++;
        u8 base = t & 0x7F;
        if (f.kind == K_DICT && base == 0x30) {   // NULL key ends dict
            if (depth == 1) return pos - off;
            depth--;
            continue;
        }
        if (f.kind != K_DICT) f.left--;
        switch (base) {
            case 0x30: case 0x4E: case 0x46: case 0x54: case 0x53:
            case 0x45: case 0x2E: case 0x3F: break;                // atomics
            case 0x69: pos += 4; break;                            // INT
            case 0x49: pos += 8; break;                            // INT64
            case 0x66: pos += 4; break;                            // FLOAT
            case 0x67: pos += 8; break;                            // BINFLOAT
            case 0x78: case 0x79: pos += 16; break;           // BINCOMPLEX
            case 0x6C: {                                       // LONG (n digits)
                auto v = s.read(pos, 4);
                if (v.size() < 4) return -1;
                i32 n = (i32)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < -10000000 || n > 10000000) return -1;
                pos += 4 + (i64)std::abs(n) * 4;
                break;
            }
            case 0x73: case 0x75: case 0x61: case 0x41: {
                auto v = s.read(pos, 4);                       // 4-byte len strings
                if (v.size() < 4) return -1;
                i32 n = (i32)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < 0 || n > 16 * 1024 * 1024) return -1;
                pos += 4 + n;
                break;
            }
            case 0x74: case 0x7A: case 0x5A: {
                u8 n = s.byte(pos);                            // 1-byte len strings
                pos += 1 + n;
                break;
            }
            case 0x72: pos += 4; break;                        // REF
            case 0x28: case 0x5B: case 0x3C: case 0x3E: {      // TUPLE/LIST/SET
                auto v = s.read(pos, 4);
                if (v.size() < 4) return -1;
                i32 n = (i32)((u32)v[0] | (u32)v[1] << 8 | (u32)v[2] << 16 | (u32)v[3] << 24);
                if (n < 0 || n > 4000000) return -1;
                pos += 4;
                if (depth >= 64) return -1;
                frames[depth++] = {n, K_ITEMS, 0};
                break;
            }
            case 0x29: {                                       // SMALL_TUPLE
                u8 n = s.byte(pos);
                pos++;
                if (depth >= 64) return -1;
                frames[depth++] = {n, K_ITEMS, 0};
                break;
            }
            case 0x7B: {                                       // DICT
                if (depth >= 64) return -1;
                frames[depth++] = {0x7FFFFFFF, K_DICT, 0};
                break;
            }
            case 0x63: {                                       // CODE
                pos += 5 * 4;                                  // 5 ints
                if (depth >= 64) return -1;
                frames[depth++] = {8, K_CODE, 0};              // 8 objects + tail
                break;
            }
            default: return -1;
        }
        if (pos > end) return -1;
    }
}void registerFmt_pyc(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PYC", "pyc", "executable", B({0x6F,0x0D,0x0D,0x0A}), 64*MB,
                  SizeMode::FrameStream, vPyc); c.min_size = 24; add(c); }
    { auto c = mk("PYC_F3", "pyc", "executable", B({0xF3,0x0D,0x0D,0x0A}), 64*MB,
                  SizeMode::FrameStream, vPyc); c.min_size = 24; add(c); }
}

}  // namespace ghost
