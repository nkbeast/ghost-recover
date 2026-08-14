// GHOST RECOVER — pem signature family (one file per format).
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

void registerFmt_pem(Registry& r) {
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
}

}  // namespace ghost
