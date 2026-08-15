// GHOST RECOVER — eml signature family (one file per format).
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

void registerFmt_eml(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("EML", "eml", "email", S("Received: from"), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_MSGID", "eml", "email", S("Message-ID: <"), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    // RFC 5322 headers: a mailbox that opens the file directly with the
    // sender block never has a Received: trace (it was not relayed).
    { auto c = mk("EML_FROM", "eml", "email", S("From: "), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_TO", "eml", "email", S("To: "), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_SUBJECT", "eml", "email", S("Subject: "), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_DATE", "eml", "email", S("Date: "), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_MIME", "eml", "email", S("MIME-Version: "), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
}

}  // namespace ghost
