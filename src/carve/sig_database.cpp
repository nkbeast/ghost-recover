// GHOST RECOVER — carver signature specs and validators for Databases.
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


// --- SQLite ----------------------------------------------------------------
i64 vSqlite(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 pageSizeRaw = s.be16(off + 16);
    i64 pageSize = (pageSizeRaw == 1) ? 65536 : pageSizeRaw;
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1))) return -1;
    u32 pageCount = s.be32(off + 28);
    if (pageCount == 0 || (i64)pageCount * pageSize > max) {
        // A file still open when it was deleted may have a stale page count.
        return 0;
    }
    return (i64)pageCount * pageSize;
}

// --- NPY: numpy header carries exact array size ----------------------------
// -- data start + itemsize * shape product; anything exotic returns 0 so the
// -- engine falls back to the next-signature bound (advisory, never wrong).
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
}

// --- MAT (v5): header + chain of top-level data elements --------------------
i64 vMat(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off, 128);
    if (b.size() < 128) return -1;
    if (std::memcmp(b.data(), "MATLAB 5.0 MAT-file", 19) != 0) return -1;
    bool le;
    if (b[126] == 'I' && b[127] == 'M') le = true;       // 'IM' = little endian
    else if (b[126] == 'M' && b[127] == 'I') le = false; // 'MI' = big endian
    else return -1;
    u16 ver = le ? (u16)(b[124] | (u16)b[125] << 8) : (u16)(b[124] << 8 | b[125]);
    if (ver != 0x0100) return -1;
    // Subsystem offset (header bytes 116..123) should be zero for plain files.
    u64 subsys = 0;
    if (le)
        for (int k = 7; k >= 0; k--) subsys = subsys << 8 | b[116 + k];
    else
        for (int k = 0; k < 8; k++) subsys = subsys << 8 | b[116 + k];
    if (subsys != 0) return -1;
    auto rd32 = [&](i64 p) -> u32 {
        auto v = s.read(off + p, 4);
        if (v.size() < 4) return 0;
        return le ? ((u32)v[3] << 24 | (u32)v[2] << 16 | (u32)v[1] << 8 | v[0])
                  : ((u32)v[0] << 24 | (u32)v[1] << 16 | (u32)v[2] << 8 | v[3]);
    };
    // Walk the chain of top-level data elements. A miMATRIX/miCOMPRESSED
    // element uses a 16-byte tag whose size field sits at +4; other types an
    // 8-byte tag (size at +4) or a small 4-byte tag (size in bits 8..15
    // when the type bits alone look like a small element).
    i64 p = 128;
    int els = 0;
    while (p + 4 <= max && els < 100000) {
        u32 t = rd32(p);
        int type = (int)(t & 0xFF);
        if (type == 14 || type == 15) {
            u32 size = rd32(p + 4);
            if (size > (u32)max) return -1;
            // The tag's size field counts the element body from right after
            // the 8-byte tag: for a miCOMPRESSED/miMATRIX element the file
            // ends exactly at p + 8 + size (e.g. scipy's savemat). Stepping
            // 16 bytes skips the trailing 4-byte data-length pair INSIDE the
            // body and over-runs every such file by 8.
            i64 next = p + 8 + (i64)size;
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        u32 word2 = rd32(p + 4);
        int smallSize = (int)((t >> 8) & 0xFF);
        if (type >= 1 && type <= 13 && (t & 0xFF00) != 0 && (t & 0xFF0000) == 0 &&
            (t & 0xFF000000) == 0 && smallSize != 0) {
            i64 next = p + 4 + smallSize;    // small element, no padding
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        if (type >= 1 && type <= 13) {       // 8-byte tag (size at +4)
            i64 next = p + 8 + (i64)word2;
            if (next <= p || next > max) break;
            p = next;
            els++;
            continue;
        }
        break;   // unknown element type: the top-level chain ends here
    }
    if (els < 1) return -1;
    return p - 0;   // p counts from off already
}

// --- PICKLE: opcode walk. Modern pickles are length-prefixed end to end,
// -- so the walk terminates exactly at the real STOP, never inside garbage.
// -- An opcode outside the covered set rejects the candidate outright: a
// -- genuine pickle produced by CPython 2.7+ never emits one (the walk then
// -- cannot be trusted to delimit the file, so we refuse rather than guess).
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
}

void registerDatabases(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("SQLite", "sqlite", "database", S("SQLite format 3\0"), 8*GB,
                  SizeMode::Header, vSqlite); c.min_size = 512; add(c); }
    add(mk("SQLite_WAL", "sqlite-wal", "database", B({0x37,0x7F,0x06,0x82}), 2*GB));
    add(mk("MDB", "mdb", "database", B({0x00,0x01,0x00,0x00,'S','t','a','n','d','a','r','d',' ','J','e','t'}), 4*GB));
    add(mk("ACCDB", "accdb", "database", B({0x00,0x01,0x00,0x00,'S','t','a','n','d','a','r','d',' ','A','C','E'}), 4*GB));
    add(mk("BerkeleyDB", "db", "database", B({0x00,0x05,0x31,0x62}), 2*GB));
    add(mk("LevelDB", "ldb", "database", B({0x57,0xFB,0x80,0x8B,0x24,0x75,0x47,0xDB}), 2*GB));
    add(mk("Firebird", "fdb", "database", B({0x01,0x00,0x39,0x30}), 4*GB));
    add(mk("MSSQL_MDF", "mdf", "database", B({0x01,0x0F,0x00,0x00}), 16*GB));
    add(mk("Parquet", "parquet", "database", S("PAR1"), 8*GB));
    add(mk("ORC", "orc", "database", S("ORC"), 8*GB));
    add(mk("Avro", "avro", "database", B({'O','b','j',0x01}), 8*GB));
    add(mk("HDF5", "h5", "database", B({0x89,'H','D','F',0x0D,0x0A,0x1A,0x0A}), 8*GB));
    add(mk("NetCDF", "nc", "database", S("CDF"), 8*GB));
    add(mk("Feather", "arrow", "database", S("ARROW1"), 8*GB));
    add(mk("NPY", "npy", "database", B({0x93,'N','U','M','P','Y'}), 8*GB, SizeMode::Header, vNpy));
    add(mk("MAT", "mat", "database", S("MATLAB 5.0 MAT-file"), 8*GB, SizeMode::Header, vMat));
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
