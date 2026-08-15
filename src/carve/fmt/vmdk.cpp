// GHOST RECOVER — vmdk signature family (one file per format).
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

i64 vVmdk(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 version = s.le32(off + 4);
    u32 flags = s.le32(off + 8);
    if (version != 1 && version != 2) return -1;
    u64 grainSize = s.le64(off + 20);
    u64 descSize = s.le64(off + 36);
    u32 numGT = s.le32(off + 44);
    u32 numGTE = s.le32(off + 48);
    if (grainSize > (1u << 21)) return -1;
    if (numGTE > 0 && grainSize == 0) return -1;
    if (descSize == 0 || descSize > 1024 * 1024) return -1;
    if (numGT > (1u << 23) || numGTE > (1u << 23)) return -1;
    i64 total = 512 + (i64)descSize * 512 + (i64)numGT * 4 + (i64)numGTE * 4 +
                (i64)numGTE * (i64)grainSize * 512;
    if (flags & 0x10000) total += 512;                        // embedded backup
    return (total <= max) ? total : -1;
}void registerFmt_vmdk(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("VMDK_SPARSE", "vmdk", "vm", B({'K','D','M','V'}), 64*GB, SizeMode::Header, vVmdk));
    add(mk("VMDK_DESC", "vmdk", "vm", S("# Disk DescriptorFile"), 1*MB));
}

}  // namespace ghost
