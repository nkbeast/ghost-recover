// GHOST RECOVER — carver signature specs and validators for Archives.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef GHOST_HAVE_BZIP2
#include <bzlib.h>
#endif

namespace ghost {


// --- cpio (newc / crc / odc / binary) ---------------------------------------
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
            ns = s.le16(p + 20);
            fs = (i64)s.le16(p + 22) | ((i64)s.le16(p + 24) << 16);
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
}

// --- .lzma (alone) header screen. -------------------------------------------
// No decoder is invoked, but the 13-byte header is largely self-describing:
// props must encode lc/lp/pb in range, the dict size must be a plausible
// power-of-two-ish value, and the uncompressed size must be 0xFFFF... (unknown)
// or sane. That leaves few false positives for the 5D 00 00 magic, and any
// survivor is bounded to the next signature and never masks other files.
i64 vLzmaAlone(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (max < 29) return -1;
    u8 props = s.byte(off);
    u32 dict = s.le32(off + 1);
    u64 usize = 0;
    for (int k = 0; k < 8; k++) usize |= (u64)s.byte(off + 5 + k) << (8 * k);
    i64 lc = props % 9, lp = (props / 9) % 5, pb = props / 45;
    if (lc + lp > 4 || pb > 4) return -1;         // LZMA SDK/xz parameter range
    if (dict < 4096 || dict > (u32)(1 << 30)) return -1;
    if (usize == 0) return -1;                    // empty stream: pointless
    if (usize != 0xFFFFFFFFFFFFFFFFull && usize > (4ull << 30)) return -1;
    return 0;   // valid header: length unknown, clamp to the next signature
}

// --- gzip: walk the deflate member chain with inflate. ---------------------
// The compressed stream has no length field, but inflate can verify the
// member end exactly: with windowBits | 16 zlib checks the CRC32 and ISIZE
// trailer itself, so a candidate that passes is a real gzip member of the
// reported length. Random data that merely starts with 1F 8B fails the
// deflate decoding within a few hundred bytes.
i64 vGzip(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
#ifdef GHOST_HAVE_ZLIB
    const i64 kInBudget = 1 * 1024LL * 1024 * 1024;    // compressed bytes per member
    const i64 kOutBudget = 32 * 1024LL * 1024 * 1024;  // decompressed cap
    i64 pos = off;
    i64 outTotal = 0;
    std::vector<u8> buf;
    for (int member = 0; member < 64; member++) {
        z_stream zs;
        std::memset(&zs, 0, sizeof(zs));
        if (inflateInit2(&zs, 15 + 16) != Z_OK) return -1;
        int rc = Z_OK;
        u8 out[64 * 1024];
        while (rc != Z_STREAM_END) {
            if (zs.avail_in == 0) {
                if (pos - off >= max || (i64)zs.total_in >= kInBudget) {
                    rc = Z_BUF_ERROR;
                    break;
                }
                i64 want = std::min<i64>(
                    64 * 1024,
                    std::min(max - (pos - off), kInBudget - (i64)zs.total_in));
                buf = s.read(pos, want);
                if (buf.empty()) {
                    // Input exhausted: one last inflate call lets zlib report
                    // a stream that ended flush against the read boundary.
                    zs.next_in = nullptr;
                    zs.avail_in = 0;
                    zs.next_out = out;
                    zs.avail_out = sizeof(out);
                    rc = inflate(&zs, Z_NO_FLUSH);
                    break;
                }
                zs.next_in = buf.data();
                zs.avail_in = (uInt)buf.size();
            }
            zs.next_out = out;
            zs.avail_out = sizeof(out);
            rc = inflate(&zs, Z_NO_FLUSH);
            outTotal += (i64)(sizeof(out) - zs.avail_out);
            if (outTotal > kOutBudget) { rc = Z_BUF_ERROR; break; }
            if (rc == Z_STREAM_ERROR || rc == Z_MEM_ERROR || rc == Z_DATA_ERROR) break;
        }
        i64 consumed = (i64)zs.total_in;
        bool ok = (rc == Z_STREAM_END);
        inflateEnd(&zs);
        if (!ok) return -1;
        pos += consumed;                               // trailer included
        if (pos - off > max) return -1;
        auto nx = s.read(pos, 2);                      // concatenated member?
        if (nx.size() < 2 || nx[0] != 0x1F || nx[1] != 0x8B) return pos - off;
    }
    return pos - off;
#else
    (void)s; (void)off; (void)max;
    return 0;
#endif
}

// --- bzip2 -----------------------------------------------------------------
// The stream is bit-packed, so the end-of-stream magic is not byte-aligned
// and cannot be located by scanning; decompression finds the exact end.
i64 vBzip2(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
#ifdef GHOST_HAVE_BZIP2
    const i64 kInBudget = 1 * 1024LL * 1024 * 1024;
    const i64 kOutBudget = 32 * 1024LL * 1024 * 1024;
    auto h = s.read(off, 4);
    if (h.size() < 4 || h[0] != 'B' || h[1] != 'Z' || h[2] != 'h'
        || h[3] < '1' || h[3] > '9') return -1;
    bz_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (BZ2_bzDecompressInit(&zs, 0, 0) != BZ_OK) return -1;
    auto bzIn = [](bz_stream* z) { return (i64)z->total_in_hi32 << 32 | (u32)z->total_in_lo32; };
    i64 fed = 0;                 // bytes handed to the decompressor so far
    i64 outTotal = 0;
    int rc = BZ_OK;
    u8 out[64 * 1024];
    std::vector<u8> buf;
    while (rc != BZ_STREAM_END) {
        if (zs.avail_in == 0) {
            if (fed >= max || bzIn(&zs) >= kInBudget) {
                rc = BZ_UNEXPECTED_EOF;
                break;
            }
            i64 want = std::min<i64>(
                64 * 1024,
                std::min(max - fed, kInBudget - bzIn(&zs)));
            buf = s.read(off + fed, want);
            if (buf.empty()) {
                zs.next_in = nullptr;
                zs.avail_in = 0;
                zs.next_out = reinterpret_cast<char*>(out);
                zs.avail_out = sizeof(out);
                rc = BZ2_bzDecompress(&zs);
                break;
            }
            zs.next_in = reinterpret_cast<char*>(buf.data());
            zs.avail_in = (unsigned)buf.size();
            fed += (i64)buf.size();
        }
        zs.next_out = reinterpret_cast<char*>(out);
        zs.avail_out = sizeof(out);
        rc = BZ2_bzDecompress(&zs);
        outTotal += (i64)(sizeof(out) - zs.avail_out);
        if (outTotal > kOutBudget) { rc = BZ_UNEXPECTED_EOF; break; }
        if (rc != BZ_OK && rc != BZ_STREAM_END) break;
    }
    i64 consumed = bzIn(&zs);
    bool ok = (rc == BZ_STREAM_END);
    BZ2_bzDecompressEnd(&zs);
    if (!ok || consumed <= 0) return -1;
    return consumed;                             // EOS + CRC included
#else
    (void)s; (void)off; (void)max;
    return 0;
#endif
}

// --- xz --------------------------------------------------------------------
i64 vXz(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 12);
    if (h.size() < 12) return -1;
    static const u8 kFooter[2] = {'Y', 'Z'};
    const i64 kStep = 1 * MB;
    for (i64 base = 0; base < max; base += kStep - 16) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 12) break;
        for (size_t i = 0; i + 2 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, kFooter, 2) == 0 && base + (i64)i >= 12)
                return base + (i64)i + 2;
        }
        if ((i64)buf.size() < std::min(kStep, max - base)) break;
    }
    return 0;
}

// --- 7-Zip -----------------------------------------------------------------
i64 v7z(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    u64 nextHeaderOffset = 0, nextHeaderSize = 0;
    for (int i = 0; i < 8; i++) nextHeaderOffset |= (u64)h[12 + i] << (i * 8);
    for (int i = 0; i < 8; i++) nextHeaderSize |= (u64)h[20 + i] << (i * 8);
    i64 total = 32 + (i64)nextHeaderOffset + (i64)nextHeaderSize;
    if (total < 32 || total > max) return -1;
    return total;
}

// --- RAR -------------------------------------------------------------------
// RAR4 blocks carry a 16-bit size at +5. RAR5 headers are vint-coded:
// CRC32(4) + Header size (vint) + Header type (vint) + flags (vint) +
// [extra area size (vint)] + [data area size (vint)] + header data + data.
static i64 rar5Vint(ByteSource& s, i64 at, i64 base, i64 hi, int& width) {
    width = 0;
    u64 v = 0;
    for (int i = 0; i < 10; i++) {
        u8 b = s.byte(base + at + i);
        v |= (u64)(b & 0x7F) << (7 * i);
        width = i + 1;
        if (!(b & 0x80)) return (v <= (u64)hi) ? (i64)v : -1;
    }
    return -1;
}
i64 vRar(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto h = s.read(off, 8);
    if (h.size() < 8) return -1;
    bool v5 = (h[6] == 0x01 && h[7] == 0x00);
    if (!v5) {
        i64 p = off + 7;
        int blocks = 0;
        while (p + 7 <= off + max && blocks < 100000) {
            u16 size = s.le16(p + 5);
            u8 type = s.byte(p + 2);
            if (size < 7) break;
            i64 add = 0;
            if (type == 0x74 || (s.le16(p + 3) & 0x8000)) add = s.le32(p + 7);
            p += size + add;
            blocks++;
            if (type == 0x7B) break;                // end-of-archive
        }
        if (blocks < 1) return -1;
        return p - off;
    }
    // RAR 5.0: walk header blocks to the End-of-archive header (type 5).
    // RAR reads nothing after it, so its end is the archive's end. Only the
    // size-bearing fields are consumed; block-specific fields are covered by
    // the Header size vint itself.
    i64 p = off + 8;
    int blocks = 0;
    while (p + 6 <= off + max && blocks < 1000000) {
        i64 hp = p - off;
        int w = 0;
        i64 hdrSize = rar5Vint(s, hp + 4, off, 2 * MB, w);
        if (hdrSize < 0 || w == 0) return -1;
        i64 q = hp + 4 + w;
        int tw = 0;
        i64 type = rar5Vint(s, q, off, 5, tw);
        if (type < 0 || tw == 0) return -1;
        q += tw;
        int fw = 0;
        i64 flags = rar5Vint(s, q, off, 0xFFFF, fw);
        if (flags < 0 || fw == 0) return -1;
        q += fw;
        if (flags & 0x0001) {                       // extra area: skip its size field
            int ew = 0;
            i64 extraSize = rar5Vint(s, q, off, 2 * MB, ew);
            if (extraSize < 0 || ew == 0) return -1;
            q += ew;
        }
        i64 dataSize = 0;
        if (flags & 0x0002) {                       // data area present
            int dw = 0;
            dataSize = rar5Vint(s, q, off, 64 * GB, dw);
            if (dataSize < 0 || dw == 0) return -1;
        }
        i64 end = hp + 4 + w + hdrSize + dataSize;
        if (end <= hp || end > max) return -1;
        p = off + end;
        blocks++;
        if (getenv("GHOST_DEBUG_RAR"))
            fprintf(stderr, "vRar5 @%lld size=%lld type=%lld flags=%lld data=%lld end=%lld\n",
                    (long long)hp, (long long)hdrSize, (long long)type,
                    (long long)flags, (long long)dataSize, (long long)end);
        if (type == 5) return end;                  // end-of-archive header
    }
    return -1;
}

// --- CAB -------------------------------------------------------------------
i64 vCab(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 size = s.le32(off + 8);
    if (size < 36 || (i64)size > max) return -1;
    return size;
}

// --- ar / deb --------------------------------------------------------------
i64 vAr(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 8;
    int members = 0;
    while (p + 60 <= off + max && members < 100000) {
        auto h = s.read(p, 60);
        if (h.size() < 60 || h[58] != 0x60 || h[59] != 0x0A) break;
        u64 size = 0;
        for (int i = 48; i < 58; i++) {
            u8 c = h[i];
            if (c < '0' || c > '9') break;
            size = size * 10 + (u64)(c - '0');
        }
        p += 60 + (i64)size + ((size & 1) ? 1 : 0);
        members++;
    }
    if (members < 1) return -1;
    return p - off;
}

// --- ISO9660: PVD at sector 16; file size = volume space * block size ------
i64 vIso(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto b = s.read(off + 32768, 2048);
    if (b.size() < 134) return -1;
    if (std::memcmp(b.data() + 1, "CD001", 5) != 0) return -1;
    if (b[6] != 1) return -1;                       // PVD (type 1, not terminator)
    u16 block = (u16)b[128] | (u16)b[129] << 8;
    if (block != 512 && block != 1024 && block != 2048 && block != 4096) return -1;
    u64 vol = (u64)b[80] | (u64)b[81] << 8 | (u64)b[82] << 16 | (u64)b[83] << 24;
    if (vol < 16) return -1;
    u64 size = vol * block;
    if (size > (u64)max) size = (u64)max;
    if (size < 2048) return -1;
    return (i64)size;
}

void registerArchives(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ZIP", "zip", "archive", B({'P','K',0x03,0x04}), 8*GB, SizeMode::Header, vZip);
      c.min_size = 100; add(c); }
    { auto c = mk("JAR", "jar", "archive", B({'P','K',0x03,0x04}), 2*GB, SizeMode::Header, vZip);
      withConfirm(c, S("META-INF/MANIFEST"), -1, 8192); c.priority = 25; add(c); }
    { auto c = mk("APK", "apk", "archive", B({'P','K',0x03,0x04}), 4*GB, SizeMode::Header, vZip);
      withConfirm(c, S("AndroidManifest"), -1, 16384); c.priority = 28; add(c); }
    { auto c = mk("GZIP", "gz", "archive", B({0x1F,0x8B,0x08}), 8*GB, SizeMode::Heuristic, vGzip);
      c.min_size = 20; add(c); }
    { auto c = mk("BZIP2", "bz2", "archive", S("BZh"), 8*GB, SizeMode::Heuristic, vBzip2);
      c.min_size = 20; add(c); }
    { auto c = mk("XZ", "xz", "archive", B({0xFD,'7','z','X','Z',0x00}), 8*GB,
                  SizeMode::Heuristic, vXz); c.min_size = 32; add(c); }
    { auto c = mk("7Z", "7z", "archive", B({'7','z',0xBC,0xAF,0x27,0x1C}), 8*GB,
                  SizeMode::Header, v7z); c.min_size = 32; add(c); }
    { auto c = mk("RAR4", "rar", "archive", B({'R','a','r','!',0x1A,0x07,0x00}), 8*GB,
                  SizeMode::Header, vRar); c.min_size = 32; add(c); }
    { auto c = mk("RAR5", "rar", "archive", B({'R','a','r','!',0x1A,0x07,0x01,0x00}), 8*GB,
                  SizeMode::Header, vRar); c.min_size = 32; add(c); }
    { auto c = mk("TAR", "tar", "archive", S("ustar"), 8*GB, SizeMode::Container, vTar);
      c.magic_offset = 257; c.min_size = 1024; add(c); }
    { auto c = mk("DEB", "deb", "archive", S("!<arch>\n"), 2*GB, SizeMode::Container, vAr);
      withConfirm(c, S("debian-binary"), -1, 128); c.priority = 20; add(c); }
    { auto c = mk("AR", "a", "archive", S("!<arch>\n"), 2*GB, SizeMode::Container, vAr);
      c.min_size = 68; add(c); }
    { auto c = mk("CAB", "cab", "archive", S("MSCF"), 2*GB, SizeMode::Header, vCab);
      c.min_size = 36; add(c); }
    add(mk("ZSTD", "zst", "archive", B({0x28,0xB5,0x2F,0xFD}), 8*GB));
    add(mk("LZ4", "lz4", "archive", B({0x04,0x22,0x4D,0x18}), 8*GB));
    add(mk("LZIP", "lz", "archive", S("LZIP"), 8*GB));
    { auto c = mk("LZMA_ALONE", "lzma", "archive", B({0x5D,0x00,0x00}), 8*GB, SizeMode::Heuristic, vLzmaAlone);
      c.min_size = 29; add(c); }
    add(mk("RPM", "rpm", "archive", B({0xED,0xAB,0xEE,0xDB}), 2*GB));
    add(mk("CPIO_ASCII", "cpio", "archive", S("070701"), 2*GB, SizeMode::Container, vCpio));
    add(mk("CPIO_ODC", "cpio", "archive", S("070707"), 2*GB, SizeMode::Container, vCpio));
    add(mk("CPIO_BIN", "cpio", "archive", B({0xC7,0x71}), 2*GB, SizeMode::Container, vCpio));
    add(mk("LZH", "lzh", "archive", S("-lh"), 512*MB));
    add(mk("ACE", "ace", "archive", S("**ACE**"), 512*MB));
    add(mk("SIT", "sit", "archive", S("StuffIt"), 512*MB));
    add(mk("WIM", "wim", "archive", S("MSWIM"), 8*GB));
    add(mk("DMG_KOLY", "dmg", "archive", S("koly"), 16*GB));
    { auto c = mk("ISO9660", "iso", "archive", S("CD001"), 16*GB,
                  SizeMode::Header, vIso);
      c.magic_offset = 32769; add(c); }
    add(mk("SQUASHFS", "squashfs", "archive", S("hsqs"), 8*GB));
    add(mk("CRAMFS", "cramfs", "archive", B({0x45,0x3D,0xCD,0x28}), 2*GB));
}

}  // namespace ghost
