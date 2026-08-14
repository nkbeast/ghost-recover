// GHOST RECOVER — hdf5 signature family (one file per format).
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

i64 vHdf5(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.byte(off + 8) != 0) return -1;                     // superblock v0
    u8 sizeOfOffsets = s.byte(off + 13);
    u8 sizeOfLengths = s.byte(off + 14);
    if (sizeOfOffsets != 4 && sizeOfOffsets != 8) return -1;
    if (sizeOfLengths != 4 && sizeOfLengths != 8) return -1;
    if (s.byte(off + 15) != 0) return -1;
    u64 symtabAddr = (sizeOfOffsets == 8) ? s.le64(off + 40) : (u64)s.le32(off + 40);
    if (symtabAddr < 56) return -1;
    i64 node = off + (i64)symtabAddr;
    if (node + 8 > off + max) return -1;
    if (s.be32(node) != 0x534E4F44) return -1;               // SNOD
    if (s.byte(node + 4) != 1) return -1;                    // version
    u16 nentries = s.be16(node + 6);
    if (nentries > 1024) return -1;
    i64 total = (i64)symtabAddr + 8 + 24 * (i64)nentries;
    return (total <= max) ? total : -1;
}void registerFmt_hdf5(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("HDF5", "h5", "database", B({0x89,'H','D','F',0x0D,0x0A,0x1A,0x0A}), 8*GB, SizeMode::Header, vHdf5));
}

}  // namespace ghost
