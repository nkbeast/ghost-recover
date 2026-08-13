// GHOST RECOVER — shared carver plumbing (definitions).
#include "sig_common.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <utility>

namespace ghost {

i64 vRiff(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    u32 sz = s.le32(off + 4);
    i64 total = (i64)sz + 8;
    if (total < 12 || total > max) return -1;
    return total;
}

i64 vMp4(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int atoms = 0;
    bool sawFtyp = false, sawMdatOrMoov = false;
    while (p + 8 <= off + max && atoms < 100000) {
        u32 sz32 = s.be32(p);
        auto type = s.read(p + 4, 4);
        if (type.size() < 4) break;
        for (u8 c : type)
            if (!(c == ' ' || c == '-' || (c >= '0' && c <= '9') ||
                  (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || c >= 0xA9)) {
                return atoms ? lastEnd - off : -1;
            }
        i64 size = sz32;
        if (sz32 == 1) {
            auto ext = s.read(p + 8, 8);
            if (ext.size() < 8) break;
            // Accumulate in u64: an 8-byte extended size can reach 2^64-1 and
            // shifting it into a signed i64 is undefined behaviour.
            u64 esz = 0;
            for (int i = 0; i < 8; i++) esz = (esz << 8) | ext[i];
            if (esz > 0x7FFFFFFFFFFFFFFFull) break;
            size = (i64)esz;
        } else if (sz32 == 0) {
            // "extends to end of file" — in a carving context we cannot know
            // where that is, so stop at the last complete atom.
            break;
        }
        if (size < 8 || p + size > off + max) break;
        if (std::memcmp(type.data(), "ftyp", 4) == 0) sawFtyp = true;
        if (std::memcmp(type.data(), "mdat", 4) == 0 ||
            std::memcmp(type.data(), "moov", 4) == 0) sawMdatOrMoov = true;
        lastEnd = p + size;
        p = lastEnd;
        atoms++;
    }
    if (atoms < 2 || !(sawFtyp || sawMdatOrMoov)) return -1;
    return lastEnd - off;
}

i64 vOgg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int pages = 0;
    while (p + 27 <= off + max && pages < 4000000) {
        auto h = s.read(p, 27);
        if (h.size() < 27) break;
        if (h[0] != 'O' || h[1] != 'g' || h[2] != 'g' || h[3] != 'S' || h[4] != 0) break;
        u8 segs = h[26];
        auto seg = s.read(p + 27, segs);
        if ((int)seg.size() < segs) break;
        i64 dataSize = 0;
        for (u8 x : seg) dataSize += x;
        i64 pageSize = 27 + segs + dataSize;
        if (p + pageSize > off + max) break;
        lastEnd = p + pageSize;
        p = lastEnd;
        pages++;
    }
    if (pages < 1) return -1;
    return lastEnd - off;
}

i64 vZip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // Accept only the End Of Central Directory whose central-directory pointer
    // and size add up to its own position — that identifies the EOCD belonging
    // to *this* archive rather than one from a neighbouring file.
    const i64 kStep = 1 * MB;
    const i64 kOverlap = 21;
    i64 base = 0;
    while (base < max) {
        i64 want = std::min(kStep, max - base);
        auto buf = s.read(off + base, want);
        if (buf.size() < 22) break;
        for (size_t i = 0; i + 22 <= buf.size(); i++) {
            if (!(buf[i] == 'P' && buf[i+1] == 'K' && buf[i+2] == 0x05 && buf[i+3] == 0x06))
                continue;
            u32 cdSize = (u32)buf[i+12] | (u32)buf[i+13] << 8 | (u32)buf[i+14] << 16 | (u32)buf[i+15] << 24;
            u32 cdOff  = (u32)buf[i+16] | (u32)buf[i+17] << 8 | (u32)buf[i+18] << 16 | (u32)buf[i+19] << 24;
            u16 comment = (u16)((u16)buf[i+20] | (u16)buf[i+21] << 8);
            i64 eocdPos = base + (i64)i;
            if ((i64)cdOff + (i64)cdSize != eocdPos) continue;
            i64 total = eocdPos + 22 + comment;
            return (total <= max) ? total : -1;
        }
        if ((i64)buf.size() < want) break;
        if (want <= kOverlap) break;
        base += want - kOverlap;
    }
    return -1;
}

i64 vTar(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The "ustar" magic sits at +257 inside the first header block.
    i64 p = off;
    int members = 0;
    while (p + 512 <= off + max && members < 1000000) {
        auto h = s.read(p, 512);
        if (h.size() < 512) break;
        bool allZero = true;
        for (u8 c : h) if (c) { allZero = false; break; }
        if (allZero) break;                       // end-of-archive terminator
        if (std::memcmp(h.data() + 257, "ustar", 5) != 0) break;
        // size is an octal string at +124, 12 bytes
        u64 size = 0;
        for (int i = 124; i < 135; i++) {
            u8 c = h[i];
            if (c < '0' || c > '7') break;
            size = size * 8 + (u64)(c - '0');
        }
        p += 512 + (i64)((size + 511) / 512) * 512;
        members++;
    }
    if (members < 1) return -1;
    // Writers pad the archive to a record size (GNU tar and Python's
    // tarfile both default to 10 KiB). The file ends on that boundary —
    // everything beyond it (usually the next file's area) is foreign, so
    // never walk the zero run looking for it.
    i64 end = p;
    i64 rel = end - off;
    if (rel % 10240 != 0) {
        i64 rounded = off + ((rel / 10240) + 1) * 10240;
        if (rounded <= off + max && rounded > end) {
            // Only extend when the rounding really is archive padding.
            bool zeroOk = true;
            for (i64 q = end; q < rounded && zeroOk; q++)
                if (s.byte(q)) zeroOk = false;
            if (zeroOk) end = rounded;
        }
    }
    return end - off;
}

i64 vOle2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 sectorShift = s.le16(off + 30);
    if (sectorShift < 7 || sectorShift > 12) return -1;
    i64 sectorSize = (i64)1 << sectorShift;
    u32 numFat = s.le32(off + 44);
    if (numFat == 0 || numFat > 100000) return -1;
    // The highest sector referenced by the FAT bounds the file.
    i64 highest = 0;
    int fatSectorsRead = 0;
    for (int i = 0; i < 109 && fatSectorsRead < 512; i++) {
        u32 fatSect = s.le32(off + 76 + (i64)i * 4);
        if (fatSect == 0xFFFFFFFF || fatSect == 0xFFFFFFFE) break;
        i64 fatOff = (i64)(fatSect + 1) * sectorSize;
        if (fatOff + sectorSize > max) break;
        auto fat = s.read(off + fatOff, sectorSize);
        for (size_t k = 0; k + 4 <= fat.size(); k += 4) {
            u32 v = (u32)fat[k] | (u32)fat[k+1] << 8 | (u32)fat[k+2] << 16 | (u32)fat[k+3] << 24;
            if (v == 0xFFFFFFFF) continue;                   // free
            i64 idx = (i64)(fatSectorsRead * (sectorSize / 4)) + (i64)(k / 4);
            highest = std::max(highest, idx);
        }
        fatSectorsRead++;
    }
    if (highest <= 0) return -1;
    i64 total = (highest + 2) * sectorSize;
    if (total > max) return -1;
    return total;
}

i64 vText(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
    i64 p = 0;
    const i64 kStep = 64 * KB;
    i64 limit = std::min(max, spec.max_size);
    while (p < limit) {
        auto buf = s.read(off + p, std::min(kStep, limit - p));
        if (buf.empty()) break;
        for (size_t i = 0; i < buf.size(); i++) {
            u8 c = buf[i];
            bool ok = (c >= 0x20 && c < 0x7F) || c == '\t' || c == '\n' || c == '\r' || c >= 0x80;
            if (!ok) return (p + (i64)i >= spec.min_size) ? p + (i64)i : -1;
        }
        p += (i64)buf.size();
    }
    return p >= spec.min_size ? p : -1;
}

i64 vDer(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
    struct El { i64 pos; i64 contentEnd; };
    std::vector<El> stack;
    i64 pos = off;
    i64 lastEnd = -1;
    i64 total = 0;
    const i64 kLimit = (i64)1 << 28;
    while (pos < off + max && total < kLimit) {
        u8 tag = s.byte(pos);
        // Top-level element: tag byte must be 0x30/0x31 (SEQUENCE/SET) for the
        // common .der/.p12 containers; a raw OCTET STRING wrapper is rare
        // (PKCS#12 is a sequence, so accept 0x30/0x31).
        if (tag != 0x30 && tag != 0x31) break;
        bool constructed = (tag & 0x20) != 0;
        i64 p = pos + 1;
        i64 len = 0;
        u8 lb = s.byte(p++);
        if (lb & 0x80) {
            int n = lb & 0x7F;
            if (n < 1 || n > 4 || p + n > off + max) return -1;
            for (int k = 0; k < n; k++) len = (len << 8) | s.byte(p++);
        } else len = lb;
        i64 contentEnd = p + len;
        if (contentEnd > off + max) return -1;
        if (!constructed) return -1;   // must be a constructed container
        // Walk down the constructed chain.
        stack.push_back({p, contentEnd});
        while (!stack.empty()) {
            El& top = stack.back();
            if (top.pos >= top.contentEnd) {
                lastEnd = top.contentEnd;
                stack.pop_back();
                continue;
            }
            u8 t = s.byte(top.pos);
            i64 q = top.pos + 1;
            i64 l = 0;
            u8 lbb = s.byte(q++);
            if (lbb & 0x80) {
                int n = lbb & 0x7F;
                if (n < 1 || n > 4 || q + n > top.contentEnd) return -1;
                for (int k = 0; k < n; k++) l = (l << 8) | s.byte(q++);
            } else l = lbb;
            if (q + l > top.contentEnd) return -1;
            bool c = (t & 0x20) != 0;
            if (c) {
                top.pos = q + l;                 // consume after descent
                stack.push_back({q, q + l});
                if (stack.size() > 64) return -1;
            } else {
                top.pos = q + l;
                lastEnd = q + l;
            }
        }
        if (lastEnd > pos) pos = lastEnd;
        else break;
    }
    if (lastEnd < 0) return -1;
    if (lastEnd - off > max) return -1;
    if (spec.min_size > 0 && lastEnd - off < spec.min_size) return -1;
    return lastEnd - off;
}

bool walksWholeFile(SizeFn fn) {
    static const SizeFn kWhole[] = {
        vJpeg, vPng, vGif, vZip, vTar, vAr, vMp4, vEbml, vOgg, vFlac,
        vMidi, vWasm, vPcap, vPcapng, nullptr};
    for (int i = 0; kWhole[i]; i++) if (fn == kWhole[i]) return true;
    return false;
}

// Stream formats whose validator chain-walk has no hard end marker. The walk
// is honest for what it proves, but the file's real length is only settled by
// the next signature on the device, so the engine clamps the result to it.
bool walksToBoundary(SizeFn fn) {
    static const SizeFn kBounded[] = {
        vGpg, vMat, vPickle, vDer, vPlistBin, vQcow, vVhd, vVhdx, vVdi, vSwf, nullptr};
    for (int i = 0; kBounded[i]; i++) if (fn == kBounded[i]) return true;
    return false;
}
CarveSpec mk(const char* name, const char* ext, const char* cat, std::vector<u8> magic,
             i64 maxSize, SizeMode mode, SizeFn fn) {
    CarveSpec c;
    c.name = name;
    c.ext = ext;
    c.category = cat;
    c.magic = std::move(magic);
    c.max_size = maxSize;
    c.mode = mode;
    c.validator = fn;
    c.whole_file = walksWholeFile(fn);
    c.bound_to_next = walksToBoundary(fn);
    return c;
}

CarveSpec& withConfirm(CarveSpec& c, std::vector<u8> confirm, int atOffset, int window) {
    c.confirm = std::move(confirm);
    c.confirm_offset = atOffset;
    c.confirm_window = window;
    return c;
}

}  // namespace ghost
