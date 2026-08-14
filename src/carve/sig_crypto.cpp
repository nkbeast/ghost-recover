// GHOST RECOVER — carver signature specs and validators for Crypto and secrets.
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


// --- PGP keyring: walk the packet chain (RFC 4880 old and new format). ------
i64 vGpg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int packets = 0;
    bool havePub = false, haveSec = false;
    while (p < off + max && packets < 1000000) {
        auto h = s.read(p, 6);
        if (h.size() < 1) break;
        u8 b0 = h[0];
        if (b0 < 0x80 || b0 == 0xFF) break;      // not a packet header
        int tag = (b0 & 0x40) ? (b0 & 0x3F) : ((b0 >> 2) & 0x0F);
        // keyring structure: the first packet is a key (tag 6 pub / 7
        // secret); uids (13) and sigs (2) follow anything; a key may follow
        // a key of the same type (multi-key exports); subkeys (14 pub /
        // 17 secret) must match the preceding key type, and a keyring never
        // mixes public and secret keys
        if (packets == 0) {
            if (tag != 6 && tag != 7) break;
            havePub = (tag == 6);
            haveSec = (tag == 7);
        } else {
            bool ok;
            switch (tag) {
            case 2: case 13: ok = true; break;
            case 6: ok = !haveSec; havePub = true; break;
            case 7: ok = !havePub; haveSec = true; break;
            case 14: ok = havePub && !haveSec; break;
            case 17: ok = haveSec && !havePub; break;
            default: ok = false; break;
            }
            if (!ok) break;
        }
        i64 len = -1, hdrLen = 1;
        if ((b0 & 0x40) == 0) {                  // old format
            int lt = b0 & 0x03;
            if (lt == 3) break;                  // indeterminate: no end marker
            int need = lt == 0 ? 1 : (lt == 1 ? 2 : 4);
            if (h.size() < (size_t)(1 + need)) break;
            len = 0;
            for (int k = 0; k < need; k++) len = (len << 8) | h[1 + k];
            hdrLen = 1 + need;
        } else {                                 // new format
            if (h.size() < 2) break;
            u8 l1 = h[1];
            if (l1 < 0x80) { len = l1; hdrLen = 2; }
            else if (l1 == 0xFF) {
                if (h.size() < 6) break;
                len = ((i64)h[2] << 24) | ((i64)h[3] << 16) | ((i64)h[4] << 8) | h[5];
                hdrLen = 6;
            } else {
                if (h.size() < 3) break;
                len = ((i64)(l1 & 0x7F) << 8) | h[2];
                hdrLen = 3;
            }
        }
        if (len < 0 || p + hdrLen + len > off + max) break;
        lastEnd = p + hdrLen + len;
        p = lastEnd;
        packets++;
    }
    if (packets == 0) return -1;
    return lastEnd - off;
}

// --- KeePass 1 (KDB): 116-byte header; LE32 payload length at 116. ----------
i64 vKdb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.le32(off + 8) != 3) return -1;                       // version
    u32 len = s.le32(off + 116);
    if (len < 1 || len > (u32)max) return -1;
    i64 total = 120 + (i64)len;
    return (total <= max) ? total : -1;
}

// --- KeePass 2 (KDBX): magic + version + typed header fields until END,
// then the payload length. ----------------------------------------------------
i64 vKdbx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.le32(off + 8);
    if ((ver & 0xFFFF0000) != 0x00030000 && (ver & 0xFFFF0000) != 0x00040000) return -1;
    i64 p = off + 12;
    for (int guard = 0; guard < 256; guard++) {
        if (p + 5 > off + max) return -1;
        u8 type = s.byte(p);
        if (type == 0) break;                                  // END
        if (type > 7) return -1;
        u32 size = s.le32(p + 1);
        if (size > (1 << 20)) return -1;
        p += 5 + size;
    }
    u32 len = s.le32(p);
    if (len < 1 || len > (u32)max) return -1;
    i64 total = p + 4 + (i64)len;
    return (total <= off + max) ? total - off : -1;
}

// --- Java keystore (JKS): count entries, each alias + ts + key + certs. -----
i64 vJks(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 ver = s.be32(off + 4);
    u32 count = s.be32(off + 8);
    if (ver != 1 && ver != 2) return -1;
    if (count < 1 || count > 1024) return -1;
    i64 p = off + 12;
    for (u32 i = 0; i < count; i++) {
        if (p + 2 > off + max) return -1;
        u32 aliasLen = s.be16(p);
        if (aliasLen > 65535 || p + 2 + aliasLen + 8 > off + max) return -1;
        p += 2 + aliasLen + 8;                                 // alias + ts
        if (p + 4 > off + max) return -1;
        u32 keyLen = s.be32(p);
        if (p + 4 + keyLen > off + max) return -1;
        p += 4 + keyLen;
        if (p + 4 > off + max) return -1;
        u32 chain = s.be32(p);
        if (chain > 1024) return -1;
        p += 4;
        for (u32 c = 0; c < chain; c++) {
            if (p + 4 > off + max) return -1;
            u32 certLen = s.be32(p);
            if (p + 4 + certLen > off + max) return -1;
            p += 4 + certLen;
        }
    }
    return p - off;
}

// --- Berkeley DB / Bitcoin wallet.dat: meta page; file = pages x pageSize. -
i64 vBdb(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 8) != 0x00053162) return -1;              // DB magic
    u32 pageSize = s.le32(off + 16);
    if (pageSize < 512 || pageSize > 65536 || (pageSize & (pageSize - 1)) != 0) return -1;
    if (s.byte(off + 20) != 1) return -1;                      // meta page
    u32 lastPgno = s.le32(off + 26);
    if (lastPgno > 1000000) return -1;
    i64 total = ((i64)lastPgno + 1) * pageSize;
    return (total <= max) ? total : -1;
}

void registerCrypto(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PEM_CERT", "pem", "crypto", S("-----BEGIN CERTIFICATE-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END CERTIFICATE-----");
      c.footer_extra = 1; c.min_size = 64; add(c); }
    { auto c = mk("PEM_RSA", "pem", "crypto", S("-----BEGIN RSA PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END RSA PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_EC", "pem", "crypto", S("-----BEGIN EC PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END EC PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_DSA", "pem", "crypto", S("-----BEGIN DSA PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END DSA PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_OPENSSH", "pem", "crypto", S("-----BEGIN OPENSSH PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END OPENSSH PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PEM_PRIVATE", "pem", "crypto", S("-----BEGIN PRIVATE KEY-----"), 4*MB,
                  SizeMode::Footer); c.footer = S("-----END PRIVATE KEY-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PGP_PRIVATE", "asc", "crypto", S("-----BEGIN PGP PRIVATE KEY BLOCK-----"), 8*MB,
                  SizeMode::Footer); c.footer = S("-----END PGP PRIVATE KEY BLOCK-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("PGP_MESSAGE", "asc", "crypto", S("-----BEGIN PGP MESSAGE-----"), 64*MB,
                  SizeMode::Footer); c.footer = S("-----END PGP MESSAGE-----");
      c.footer_extra = 1; add(c); }
    { auto c = mk("SSH_RSA_PUB", "pub", "crypto", S("ssh-rsa AAAA"), 64*KB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("SSH_ED25519_PUB", "pub", "crypto", S("ssh-ed25519 AAAA"), 64*KB,
                  SizeMode::Text, vText); c.min_size = 64; add(c); }
    add(mk("PKCS12", "p12", "crypto", B({0x30,0x82}), 4*MB, SizeMode::Header, vDer));
    add(mk("JKS", "jks", "crypto", B({0xFE,0xED,0xFE,0xED}), 16*MB, SizeMode::Header, vJks));
    add(mk("KDBX", "kdbx", "crypto", B({0x03,0xD9,0xA2,0x9A,0x67,0xFB,0x4B,0xB5}), 256*MB, SizeMode::Header, vKdbx));
    add(mk("KDB", "kdb", "crypto", B({0x03,0xD9,0xA2,0x9A,0x65,0xFB,0x4B,0xB5}), 256*MB, SizeMode::Header, vKdb));
    add(mk("GPG_KEYRING", "gpg", "crypto", B({0x99,0x01}), 16*MB, SizeMode::FrameStream, vGpg));
    add(mk("BITCOIN_WALLET", "dat", "crypto", B({0x00,0x05,0x31,0x62,0x00,0x09,0x00,0x00}), 512*MB, SizeMode::Header, vBdb));
}

}  // namespace ghost
