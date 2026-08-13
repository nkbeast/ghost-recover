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


// --- PGP keyring: walk the old-format public-key packet chain. --------------
i64 vGpg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int keys = 0;
    while (p + 3 <= off + max && keys < 1000000) {
        auto h = s.read(p, 3);
        if (h.size() < 3) break;
        if (h[0] != 0x99 && h[0] != 0x98) break;   // pubkey / seckey packet
        int len = ((int)h[1] << 8) | h[2];
        if (len < 269 || len > 8192) break;        // key body length is bounded
        auto b = s.read(p + 3, 1);
        if (b.empty() || (b[0] != 0x01 && b[0] != 0x02)) break;
        lastEnd = p + 3 + len;
        p = lastEnd;
        keys++;
    }
    if (keys == 0) return -1;
    return lastEnd - off;
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
    add(mk("JKS", "jks", "crypto", B({0xFE,0xED,0xFE,0xED}), 16*MB));
    add(mk("KDBX", "kdbx", "crypto", B({0x03,0xD9,0xA2,0x9A,0x67,0xFB,0x4B,0xB5}), 256*MB));
    add(mk("KDB", "kdb", "crypto", B({0x03,0xD9,0xA2,0x9A,0x65,0xFB,0x4B,0xB5}), 256*MB));
    add(mk("GPG_KEYRING", "gpg", "crypto", B({0x99,0x01}), 16*MB, SizeMode::FrameStream, vGpg));
    add(mk("BITCOIN_WALLET", "dat", "crypto", B({0x00,0x05,0x31,0x62,0x00,0x09,0x00,0x00}), 512*MB));
}

}  // namespace ghost
