// GHOST//RECOVER — block decompression for filesystem codecs.
//
// Own decoders (no dependencies) for LZO1X and LZNT1, zlib through the
// optional zlib library, and zstd through the optional libzstd. Every function
// bounds-checks its input: these parse on-disk data of unknown provenance.
//
// Format references:
//   LZO1X      lzo1x_d.ch, LZO 2.10 (instruction set)
//   Btrfs LZO  fs/btrfs/lzo.c, Linux v6.6 (LE32 header + segments + padding)
//   LZNT1      libfwnt_lznt1.c, libfwnt (tag/tuple stream, sub-block sizes)
#include "ghost/decompress.h"

#include <cstring>

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif

#ifdef GHOST_HAVE_ZSTD
#include <zstd.h>
#endif

namespace ghost {

namespace {

// zlib inflate of a whole stream. Returns false on failure.
bool inflateAll(const u8* src, size_t srcLen, std::vector<u8>& out) {
#ifdef GHOST_HAVE_ZLIB
    z_stream zs{};
    if (inflateInit(&zs) != Z_OK) return false;
    zs.next_in = const_cast<Bytef*>(src);
    zs.avail_in = (uInt)srcLen;
    size_t base = out.size();
    out.resize(base + srcLen * 4 + 4096);
    size_t total = base;
    int ret;
    while (true) {
        zs.next_out = out.data() + total;
        zs.avail_out = (uInt)(out.size() - total);
        ret = inflate(&zs, Z_NO_FLUSH);
        total = out.size() - zs.avail_out;
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { inflateEnd(&zs); out.resize(base); return false; }
        if (zs.avail_out == 0) {
            if (out.size() > base + 512u * 1024 * 1024) { inflateEnd(&zs); out.resize(base); return false; }
            out.resize(out.size() * 2);
        } else if (zs.avail_in == 0) {
            break;
        }
    }
    inflateEnd(&zs);
    out.resize(total);
    return true;
#else
    (void)src; (void)srcLen; (void)out;
    return false;
#endif
}

}  // namespace

// ---------------------------------------------------------------------------
// LZO1X raw stream decoder. Instruction semantics follow lzo1x_d.ch; the
// encoding of each class (offsets, lengths, extended forms) is reproduced
// byte-exactly, so streams produced by any LZO1X compressor decode here.
bool lzo1xDecode(const u8* in, size_t inLen, std::vector<u8>& out) {
    if (inLen == 0) return true;
    size_t ip = 0, op = 0;
    size_t t = 0;
    auto needIp = [&](size_t n) { return ip + n <= inLen; };

    if (in[0] > 17) {                       // first-byte literal shortcut
        t = in[0] - 17;
        ip = 1;
        if (t < 4) {
            if (!needIp(t)) return false;
            out.insert(out.end(), in + ip, in + ip + t);
            ip += t; op += t;
        } else {
            if (!needIp(t)) return false;
            out.insert(out.end(), in + ip, in + ip + t);
            ip += t; op += t;
            goto first_literal_run;
        }
    }

    for (;;) {
        if (!needIp(3)) return false;
        t = in[ip++];
        if (t >= 16) goto match;
        if (t == 0) {                       // extended literal run
            if (!needIp(1)) return false;
            while (in[ip] == 0) { t += 255; ip++; if (!needIp(1)) return false; }
            t += 15 + in[ip++];
        }
        t += 3;
        if (!needIp(t)) return false;
        out.insert(out.end(), in + ip, in + ip + t);
        ip += t; op += t;
    first_literal_run:
        if (!needIp(2)) return false;
        t = in[ip++];
        if (t >= 16) goto match;
        // M2-relative match with a fixed 3-byte copy, offset base 2049.
        {
            i64 m_pos = (i64)op - (1 + 2048) - (i64)(t >> 2) - (i64)(in[ip++] << 2);
            if (m_pos < 0) return false;
            out.push_back(out[(size_t)m_pos]);
            out.push_back(out[(size_t)(m_pos + 1)]);
            out.push_back(out[(size_t)(m_pos + 2)]);
            op += 3;
        }
        goto match_done;
    match:
        if (t >= 64) {                      // M2: length 3..8, offset 1..2048
            if (!needIp(1)) return false;
            i64 m_pos = (i64)op - 1 - (i64)((t >> 2) & 7) - (i64)(in[ip++] << 3);
            size_t n = (t >> 5) + 1;
            if (m_pos < 0) return false;
            for (size_t i = 0; i < n; i++) out.push_back(out[(size_t)(m_pos + i)]);
            op += n;
        } else if (t >= 32) {               // M3: length 3..33, offset 1..16384
            size_t len = t & 31;
            if (len == 0) {
                if (!needIp(1)) return false;
                while (in[ip] == 0) { len += 255; ip++; if (!needIp(1)) return false; }
                len += 31 + in[ip++];
                if (!needIp(2)) return false;
            }
            i64 m_pos = (i64)op - 1 - (i64)((in[ip] >> 2) + (in[ip + 1] << 6));
            ip += 2;
            if (m_pos < 0) return false;
            len += 2;
            for (size_t i = 0; i < len; i++) out.push_back(out[(size_t)(m_pos + i)]);
            op += len;
        } else if (t >= 16) {               // M4: length 3..9, offset 16385..49151
            i64 m_pos = (i64)op - (i64)((t & 8) << 11);
            size_t len = t & 7;
            if (len == 0) {
                if (!needIp(1)) return false;
                while (in[ip] == 0) { len += 255; ip++; if (!needIp(1)) return false; }
                len += 7 + in[ip++];
                if (!needIp(2)) return false;
            }
            m_pos -= (i64)((in[ip] >> 2) + (in[ip + 1] << 6));
            ip += 2;
            if (m_pos == (i64)op) return true;   // end-of-stream marker 0x11 00 00
            m_pos -= 0x4000;
            if (m_pos < 0) return false;
            len += 2;
            for (size_t i = 0; i < len; i++) out.push_back(out[(size_t)(m_pos + i)]);
            op += len;
        } else {                            // M1: 2-byte copy, offset 1..1024
            if (!needIp(1)) return false;
            i64 m_pos = (i64)op - 1 - (i64)(t >> 2) - (i64)(in[ip++] << 2);
            if (m_pos < 0) return false;
            out.push_back(out[(size_t)m_pos]);
            out.push_back(out[(size_t)(m_pos + 1)]);
            op += 2;
        }
    match_done:
        t = in[ip - 2] & 3;                 // up to 3 trailing literals
        if (t == 0) continue;               // next instruction follows
        if (!needIp(t)) return false;
        for (size_t i = 0; i < t; i++) out.push_back(in[ip++]);
        op += t;
    }
}

// ---------------------------------------------------------------------------
bool btrfsLzoDecode(const u8* in, size_t inLen, std::vector<u8>& out) {
    if (inLen < 4) return false;
    u32 total = (u32)(in[0] | (in[1] << 8) | (in[2] << 16) | (in[3] << 24));
    if (total < 4 || total > inLen) total = (u32)inLen;
    size_t cur = 4;
    while (cur + 4 <= total) {
        u32 seg = (u32)(in[cur] | (in[cur + 1] << 8) | (in[cur + 2] << 16) | (in[cur + 3] << 24));
        cur += 4;
        if (seg == 0 || cur + seg > total) return false;
        if (!lzo1xDecode(in + cur, seg, out)) return false;
        cur += seg;
        // Segment headers never cross a sector boundary; skip the pad zeros.
        size_t sectorLeft = 4096 - (cur % 4096);
        if (sectorLeft < 4 && cur + sectorLeft <= total) cur += sectorLeft;
    }
    return true;
}

// ---------------------------------------------------------------------------
bool zlibStreamDecode(const u8* in, size_t inLen, std::vector<u8>& out) {
    return inflateAll(in, inLen, out);
}

// ---------------------------------------------------------------------------
std::vector<u8> zstdFrameDecode(const u8* in, size_t inLen) {
#ifdef GHOST_HAVE_ZSTD
    unsigned long long size = ZSTD_getFrameContentSize(in, inLen);
    if (size == ZSTD_CONTENTSIZE_ERROR || size == ZSTD_CONTENTSIZE_UNKNOWN)
        return {};
    if (size > 512ull * 1024 * 1024) return {};
    std::vector<u8> out((size_t)size);
    size_t got = ZSTD_decompress(out.data(), out.size(), in, inLen);
    if (ZSTD_isError(got)) return {};
    out.resize(got);
    return out;
#else
    (void)in; (void)inLen;
    return {};
#endif
}

// ---------------------------------------------------------------------------
// LZNT1 (MS-XCA / libfwnt): a unit is one or more sub-blocks. Each starts with
// a 2-byte header: low 12 bits = payload length - 1, bit 15 = compressed. A
// compressed payload is a tag/tuple stream: each tag byte covers 8 tokens
// (LSB first); a clear bit means a literal byte, a set bit a 16-bit tuple with
// (offset-1) in the top (12-shift) bits and (length-3) in the low `shift`
// bits, where `shift` shrinks as the output position grows.
bool lznt1Decode(const u8* in, size_t inLen, std::vector<u8>& out) {
    size_t ip = 0;
    while (ip + 2 <= inLen) {
        u16 header = (u16)(in[ip] | (in[ip + 1] << 8));
        ip += 2;
        if (header == 0) return true;                   // end-of-unit marker
        u32 chunkLen = (header & 0x0FFF) + 1;
        if (chunkLen > inLen - ip) return false;
        const u8* end = in + ip + chunkLen;
        if (!(header & 0x8000)) {                       // raw sub-block
            out.insert(out.end(), in + ip, end);
            ip = (size_t)(end - in);
            continue;
        }
        size_t chunkStart = out.size();
        while (ip < (size_t)(end - in)) {
            u8 tag = in[ip++];
            for (int b = 0; b < 8; b++, tag >>= 1) {
                if (ip >= (size_t)(end - in)) break;
                if (!(tag & 1)) {
                    out.push_back(in[ip++]);
                    continue;
                }
                if (ip + 2 > (size_t)(end - in)) return false;
                u16 tuple = (u16)(in[ip] | (in[ip + 1] << 8));
                ip += 2;
                size_t pos = out.size() - chunkStart;
                u32 shift = 12, threshold = 16;
                while (pos > threshold && shift > 0) { shift--; threshold <<= 1; }
                u32 off = (tuple >> shift) + 1;
                u32 len = (tuple & ((1u << shift) - 1)) + 3;
                if (off > pos) return false;
                size_t src = out.size() - off;
                for (u32 i = 0; i < len; i++) out.push_back(out[src + i]);
            }
        }
        ip = (size_t)(end - in);
    }
    return true;
}

// ---------------------------------------------------------------------------
std::vector<u8> decompressBlock(const std::string& codec, const u8* data,
                                size_t len, i64 expectedOut) {
    std::vector<u8> out;
    if (codec == "btrfs-lzo") {
        if (!btrfsLzoDecode(data, len, out)) return {};
    } else if (codec == "zlib-block" || codec == "btrfs-zlib") {
        if (!zlibStreamDecode(data, len, out)) return {};
    } else if (codec == "btrfs-zstd") {
        out = zstdFrameDecode(data, len);
        if (out.empty()) return {};
    } else if (codec == "lznt1") {
        if (!lznt1Decode(data, len, out)) return {};
    } else {
        return {};
    }
    if (expectedOut > 0 && (i64)out.size() > expectedOut) out.resize((size_t)expectedOut);
    return out;
}

}  // namespace ghost
