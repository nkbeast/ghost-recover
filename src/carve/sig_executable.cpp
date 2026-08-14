// GHOST RECOVER — carver signature specs and validators for Executables.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

namespace ghost {


// --- ELF -------------------------------------------------------------------
i64 vElf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 64);
    if (h.size() < 52) return -1;
    u8 cls = h[4], data = h[5];
    if ((cls != 1 && cls != 2) || (data != 1 && data != 2)) return -1;
    bool be = data == 2;
    bool x64 = cls == 2;
    auto rd16 = [&](i64 o) { return be ? s.be16(off + o) : s.le16(off + o); };
    auto rd32 = [&](i64 o) { return be ? s.be32(off + o) : s.le32(off + o); };
    auto rd64 = [&](i64 o) -> u64 {
        auto v = s.read(off + o, 8);
        if (v.size() < 8) return 0;
        u64 r = 0;
        if (be) for (int i = 0; i < 8; i++) r = (r << 8) | v[i];
        else    for (int i = 7; i >= 0; i--) r = (r << 8) | v[i];
        return r;
    };
    i64 furthest = x64 ? 64 : 52;
    u64 shoff = x64 ? rd64(0x28) : rd32(0x20);
    u16 shentsize = rd16(x64 ? 0x3A : 0x2E);
    u16 shnum = rd16(x64 ? 0x3C : 0x30);
    u64 phoff = x64 ? rd64(0x20) : rd32(0x1C);
    u16 phentsize = rd16(x64 ? 0x36 : 0x2A);
    u16 phnum = rd16(x64 ? 0x38 : 0x2C);
    if (shnum && shentsize) furthest = std::max<i64>(furthest, (i64)shoff + (i64)shnum * shentsize);
    if (phnum && phentsize) furthest = std::max<i64>(furthest, (i64)phoff + (i64)phnum * phentsize);
    // Section contents can extend past the table.
    for (u16 i = 0; i < shnum && i < 4096; i++) {
        i64 e = (i64)shoff + (i64)i * shentsize;
        if (e + shentsize > max) break;
        u32 type = x64 ? (be ? s.be32(off + e + 4) : s.le32(off + e + 4))
                       : (be ? s.be32(off + e + 4) : s.le32(off + e + 4));
        if (type == 8) continue;                              // SHT_NOBITS occupies no file space
        u64 sOff = x64 ? rd64(e + 0x18) : rd32(e + 0x10);
        u64 sSize = x64 ? rd64(e + 0x20) : rd32(e + 0x14);
        if (sOff + sSize <= (u64)max) furthest = std::max<i64>(furthest, (i64)(sOff + sSize));
    }
    if (furthest > max) return -1;
    return furthest;
}

// --- PE / EXE / DLL --------------------------------------------------------
i64 vPe(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 lfanew = s.le32(off + 0x3C);
    if (lfanew < 0x40 || lfanew > 0x10000) return -1;
    auto sig = s.read(off + lfanew, 4);
    if (sig.size() < 4 || sig[0] != 'P' || sig[1] != 'E' || sig[2] || sig[3]) return -1;
    i64 pe = (i64)lfanew;
    u16 sections = s.le16(off + pe + 6);
    u16 optSize = s.le16(off + pe + 20);
    if (sections == 0 || sections > 4096) return -1;
    i64 table = pe + 24 + optSize;
    i64 furthest = table + (i64)sections * 40;
    for (u16 i = 0; i < sections; i++) {
        i64 e = table + (i64)i * 40;
        if (e + 40 > max) return -1;
        u32 rawSize = s.le32(off + e + 16);
        u32 rawPtr  = s.le32(off + e + 20);
        if (rawPtr && rawSize) furthest = std::max<i64>(furthest, (i64)rawPtr + rawSize);
    }
    if (furthest > max) return -1;
    return furthest;
}

// --- Mach-O ----------------------------------------------------------------
i64 vMachO(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 magic = s.le32(off);
    bool x64 = (magic == 0xFEEDFACF);
    bool be = (magic == 0xCEFAEDFE || magic == 0xCFFAEDFE);
    auto rd32 = [&](i64 o) { return be ? s.be32(off + o) : s.le32(off + o); };
    u32 ncmds = rd32(16);
    u32 sizeofcmds = rd32(20);
    if (ncmds == 0 || ncmds > 8192) return -1;
    i64 hdr = x64 ? 32 : 28;
    i64 furthest = hdr + sizeofcmds;
    i64 p = hdr;
    for (u32 i = 0; i < ncmds; i++) {
        if (p + 8 > max) break;
        u32 cmd = rd32(p);
        u32 cmdSize = rd32(p + 4);
        if (cmdSize < 8 || p + cmdSize > max) break;
        if (cmd == 0x01 || cmd == 0x19) {                     // LC_SEGMENT / _64
            i64 fileOff = x64 ? (i64)((u64)rd32(p + 40) | ((u64)rd32(p + 44) << 32))
                              : (i64)rd32(p + 32);
            i64 fileSize = x64 ? (i64)((u64)rd32(p + 48) | ((u64)rd32(p + 52) << 32))
                               : (i64)rd32(p + 36);
            if (fileOff >= 0 && fileSize > 0) furthest = std::max(furthest, fileOff + fileSize);
        }
        p += cmdSize;
    }
    if (furthest > max) return -1;
    return furthest;
}

// --- WASM ------------------------------------------------------------------
i64 vWasm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 4) != 1) return -1;
    i64 p = 8;
    int sections = 0;
    while (p < max && sections < 4096) {
        u8 id = s.byte(off + p);
        if (id > 13) break;
        // LEB128 section length — peek without consuming so a zero-length
        // section (padding after the last real section) does not inflate the
        // carved size.
        i64 leb = p + 1;
        u64 len = 0;
        int shift = 0;
        bool done = false;
        while (leb < max && shift < 35) {
            u8 b = s.byte(off + leb++);
            len |= (u64)(b & 0x7F) << shift;
            if (!(b & 0x80)) { done = true; break; }
            shift += 7;
        }
        if (!done || shift >= 35) break;      // unterminated LEB -> not ours
        if (len == 0) break;                  // empty section: stop, not run
        p = leb;
        if (p - 8 + (i64)len > max) break;
        p += (i64)len;
        sections++;
    }
    if (sections < 1) return -1;
    return p;
}

// --- Java class ------------------------------------------------------------
// Full structural walk: constant pool, interfaces, fields, methods, class
// attributes. RESTRICTED class files are far too small for a real class (the
// parser needs at least the header); the walk ends exactly at the last class
// attribute, which is the file's true length — javac emits nothing after it.
i64 vClass(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 minor = s.be16(off + 4);
    u16 major = s.be16(off + 6);
    (void)minor;
    if (major < 45 || major > 80) return -1;
    u16 cpCount = s.be16(off + 8);
    if (cpCount < 2 || cpCount > 65534) return -1;
    auto rd16 = [&](i64 p) { return s.be16(off + p); };
    auto rd32 = [&](i64 p) { return s.be32(off + p); };
    i64 p = 10;
    // Constant pool: a UTF8 entry self-describes; long/double take two slots.
    for (u16 ci = 1; ci < cpCount; ci++) {
        if (p + 1 > max) return -1;
        u8 tag = s.byte(off + p);
        p += 1;
        switch (tag) {
            case 1: {                               // Utf8: u16 len + bytes
                if (p + 2 > max) return -1;
                u16 n = rd16(p);
                p += 2;
                if (p + (i64)n > max) return -1;
                p += n;
                break;
            }
            case 3: case 4: case 9: case 10: case 11:
            case 12: case 17: case 18:              // 4-byte payloads
                p += 4;
                break;
            case 5: case 6:                         // long/double: 8 + 2 slots
                p += 8;
                ci++;
                break;
            case 7: case 8: case 16: case 19: case 20:
                p += 2;
                break;
            case 15:                                // method handle: 1 + 2
                p += 3;
                break;
            default:
                return -1;
        }
        if (p > max) return -1;
    }
    if (p + 8 > max) return -1;
    p += 6;                                         // access, this, super
    u16 ifaces = rd16(p);
    p += 2;
    if (p + 2 * (i64)ifaces > max) return -1;
    p += 2 * (i64)ifaces;
    auto attrs = [&](i64 at) -> i64 {
        if (at + 2 > max) return -1;
        u16 n = rd16(at);
        at += 2;
        for (u16 i = 0; i < n; i++) {
            if (at + 6 > max) return -1;
            u32 len = rd32(at + 2);
            at += 6;
            if ((i64)len > max - at) return -1;
            at += len;
        }
        return at;
    };
    // fields, methods: each member is a 6-byte header (access, name, desc)
    // followed by its own attribute table.
    for (int sec = 0; sec < 2; sec++) {
        if (p + 2 > max) return -1;
        u16 n = rd16(p);
        p += 2;
        if (p + 6 * (i64)n > max) return -1;
        for (u16 i = 0; i < n; i++) {
            p += 6;                                 // access, name, desc
            p = attrs(p);
            if (p < 0) return -1;
        }
    }
    // Class attributes follow directly: count then plain attribute frames.
    p = attrs(p);
    return p;
}

// --- DEX -------------------------------------------------------------------
i64 vDex(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 32);
    if (size < 112 || (i64)size > max) return -1;
    return size;
}

// --- PYC: Python 3.13+ marshal walker. Type bytes carry a 0x80 "will be
// -- referenced" flag; code objects marshal as 5 ints + 8 objects + 1 int
// -- + 2 objects (argcount…flags, code/consts/names/varnames/freevars/
// -- cellvars/filename/name, firstlineno, lnotab, exceptiontable).
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
}

void registerExecutables(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ELF", "elf", "executable", B({0x7F,'E','L','F'}), 2*GB, SizeMode::Header, vElf);
      c.min_size = 52; add(c); }
    { auto c = mk("PE", "exe", "executable", B({'M','Z'}), 2*GB, SizeMode::Header, vPe);
      c.min_size = 512; add(c); }
    { auto c = mk("MachO64", "macho", "executable", B({0xCF,0xFA,0xED,0xFE}), 2*GB,
                  SizeMode::Header, vMachO); c.min_size = 32; add(c); }
    { auto c = mk("MachO32", "macho", "executable", B({0xCE,0xFA,0xED,0xFE}), 2*GB,
                  SizeMode::Header, vMachO); c.min_size = 28; add(c); }
    add(mk("MachO_FAT", "macho", "executable", B({0xCA,0xFE,0xBA,0xBF}), 2*GB));
    { auto c = mk("JavaClass", "class", "executable", B({0xCA,0xFE,0xBA,0xBE}), 64*MB,
                  SizeMode::Heuristic, vClass); c.min_size = 32; add(c); }
    { auto c = mk("DEX", "dex", "executable", S("dex\n"), 512*MB, SizeMode::Header, vDex);
      c.min_size = 112; add(c); }
    { auto c = mk("WASM", "wasm", "executable", B({0x00,'a','s','m'}), 512*MB,
                  SizeMode::Container, vWasm); c.min_size = 8; add(c); }
    { auto c = mk("PYC", "pyc", "executable", B({0x6F,0x0D,0x0D,0x0A}), 64*MB,
                  SizeMode::FrameStream, vPyc); c.min_size = 24; add(c); }
    { auto c = mk("PYC_F3", "pyc", "executable", B({0xF3,0x0D,0x0D,0x0A}), 64*MB,
                  SizeMode::FrameStream, vPyc); c.min_size = 24; add(c); }
}

}  // namespace ghost
