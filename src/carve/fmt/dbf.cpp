// GHOST RECOVER — DBF database signatures; DBF_DBASE4 database signatures; DBF_FOXPRO database signatures.
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

i64 vDbf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 32 > off + max) return -1;
    auto h = s.read(off, 32);
    if (h.size() < 32) return -1;
    u8 ver = h[0];
    if (ver != 0x03 && ver != 0x04 && ver != 0x83 && ver != 0x8B) return -1;
    if (h[2] > 12 || h[3] > 31) return -1;               // month / day sanity
    u32 nRecords = 0;
    u16 headerSize = 0, recordSize = 0;
    for (int i = 0; i < 4; i++) nRecords |= (u32)h[4 + i] << (i * 8);
    headerSize = (u16)h[8] | ((u16)h[9] << 8);
    recordSize = (u16)h[10] | ((u16)h[11] << 8);
    if (nRecords == 0 || nRecords > 0xFFFFFFF) return -1;
    if (headerSize < 33 || recordSize < 2) return -1;
    i64 total = (i64)headerSize + (i64)nRecords * recordSize;
    if (total > max) return -1;
    return total;
}

// The dBase signature is a single version byte, so it collides with plain
// data everywhere. Admit only hits whose next 11 bytes look like a dBase
// header: a plausible last-update date, a nonzero record count, a real
// header size and a record size of at least 2 bytes. This kills the
// candidate flood (millions of hits on a dense disk) before it reaches the
// capped candidate list; vDbf still re-checks everything at validate time.
bool dbfScanFilter(const u8* p, i64 n) {
    if (n < 11) return true;               // cannot decide — let vDbf handle it
    if (p[2] < 1 || p[2] > 12) return false;
    if (p[3] < 1 || p[3] > 31) return false;
    u32 nRecords = (u32)p[4] | ((u32)p[5] << 8) | ((u32)p[6] << 16) | ((u32)p[7] << 24);
    if (nRecords == 0 || nRecords > 0xFFFFFFF) return false;
    u16 headerSize = (u16)p[8] | ((u16)p[9] << 8);
    u16 recordSize = (u16)p[10] | ((u16)p[11] << 8);
    if (headerSize < 33 || recordSize < 2) return false;
    return true;
}

void registerFmt_dbf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("DBF", "dbf", "database", B({0x03}), 1*GB, SizeMode::Container, vDbf); c.min_size = 33; c.scan_filter = dbfScanFilter; add(c); }
    { auto c = mk("DBF_DBASE4", "dbf", "database", B({0x04}), 1*GB, SizeMode::Container, vDbf); c.min_size = 33; c.scan_filter = dbfScanFilter; add(c); }
    { auto c = mk("DBF_DBASE3_MEMO", "dbf", "database", B({0x83}), 1*GB, SizeMode::Container, vDbf); c.min_size = 33; c.scan_filter = dbfScanFilter; add(c); }
    { auto c = mk("DBF_DBASE4_MEMO", "dbf", "database", B({0x8B}), 1*GB, SizeMode::Container, vDbf); c.min_size = 33; c.scan_filter = dbfScanFilter; add(c); }
}

}  // namespace ghost
