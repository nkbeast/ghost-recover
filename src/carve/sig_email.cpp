// GHOST RECOVER — carver signature specs and validators for Email.
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



// --- Outlook PST: ANSI header; next-free-page x 512 is the file size. -------
i64 vPst(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 ver = s.le16(off + 0x0A);
    if (ver != 23) return -1;                                  // ANSI only
    u32 nextFree = s.le32(off + 0x14);
    if (nextFree < 2) return -1;
    i64 total = (i64)nextFree * 512;
    return (total <= max) ? total : -1;
}

// --- Outlook Express DBX: index start + index size bound the file. ----------
i64 vDbx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 indexStart = s.le32(off + 0x10);
    u32 indexSize = s.le32(off + 0x14);
    if (indexStart < 0x18 || indexSize == 0) return -1;
    i64 total = (i64)indexStart + indexSize;
    return (total <= max) ? total : -1;
}

void registerEmail(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("MSG", "msg", "email", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("__nameid"), -1, 16384); c.priority = 30; add(c); }
    add(mk("PST", "pst", "email", B({0x21,0x42,0x44,0x4E}), 32*GB, SizeMode::Header, vPst));
    { auto c = mk("MBOX", "mbox", "email", S("From "), 2*GB, SizeMode::Text, vText);
      c.min_size = 256; add(c); }
    { auto c = mk("EML", "eml", "email", S("Received: from"), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    { auto c = mk("EML_MSGID", "eml", "email", S("Message-ID: <"), 128*MB, SizeMode::Text, vText);
      c.min_size = 128; add(c); }
    add(mk("DBX", "dbx", "email", B({0xCF,0xAD,0x12,0xFE}), 2*GB, SizeMode::Header, vDbx));
}

}  // namespace ghost
