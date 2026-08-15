// GHOST RECOVER — netcdf signature family (one file per format).
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

// Validates a netCDF classic header structure (magic + numrecs + dims +
// vars + global attrs). Returns 0 on a well-formed header: the data section
// has no length field, so the engine takes the bounded/trim path instead of
// pretending to know an exact end. Garbage returns -1 and is rejected.
i64 vNetcdf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto readU32 = [&](i64 p, u32* v) -> bool {
        auto b = s.read(p, 4);
        if (b.size() < 4) return false;
        *v = ((u32)b[0] << 24) | ((u32)b[1] << 16) | ((u32)b[2] << 8) | b[3];
        return true;
    };
    auto skipName = [&](i64* p) -> bool {
        u32 n = 0;
        if (!readU32(*p, &n)) return false;
        if (n == 0 || n > 4096) return false;
        *p += 4;
        if (*p + (i64)n > off + max) return false;
        for (u32 i = 0; i < n; i++) {
            u8 c = s.byte(*p + i);
            if (c == 0 || c == '/' || c < 0x20) return false;
        }
        *p += n;
        return true;
    };
    // netCDF attribute values are aligned to 4-byte boundaries; per-type
    // sizes are 1,1,2,4,4,8 for NC_BYTE..NC_DOUBLE.
    static const i64 kTypeSize[7] = {0, 1, 1, 2, 4, 4, 8};
    auto skipAttr = [&](i64* p) -> bool {
        if (!skipName(p)) return false;
        u32 t = 0, l = 0;
        if (!readU32(*p, &t) || t < 1 || t > 6) return false;
        *p += 4;
        if (!readU32(*p, &l) || l > (1u << 28)) return false;
        *p += 4;
        i64 bytes = kTypeSize[t] * (i64)l;
        i64 padded = (bytes + 3) & ~3LL;
        if (*p + padded > off + max) return false;
        *p += padded;
        return true;
    };
    i64 p = off + 4;
    u32 numrecs = 0, ndims = 0;
    if (!readU32(p, &numrecs) || numrecs > (1u << 28)) return -1;
    p += 4;
    if (!readU32(p, &ndims) || ndims > (1u << 16)) return -1;
    p += 4;
    for (u32 d = 0; d < ndims; d++) {
        if (!skipName(&p)) return -1;
        u32 dimSize = 0;
        if (!readU32(p, &dimSize)) return -1;
        p += 4;
    }
    u32 nvars = 0;
    if (!readU32(p, &nvars) || nvars > (1u << 16)) return -1;
    p += 4;
    for (u32 v = 0; v < nvars; v++) {
        if (!skipName(&p)) return -1;
        u32 vdims = 0;
        if (!readU32(p, &vdims) || vdims > 1024) return -1;
        p += 4 + (i64)vdims * 4;
        if (p + 8 > off + max) return -1;
        u32 natt = 0, nvs = 0;
        if (!readU32(p, &natt) || natt > (1u << 16)) return -1;
        p += 4;
        if (!readU32(p, &nvs) || nvs > (1u << 30)) return -1;
        p += 4;
        for (u32 a = 0; a < natt; a++) {
            if (!skipAttr(&p)) return -1;
        }
    }
    u32 ngatt = 0;
    if (!readU32(p, &ngatt) || ngatt > (1u << 16)) return -1;
    p += 4;
    for (u32 a = 0; a < ngatt; a++) {
        if (!skipAttr(&p)) return -1;
    }
    return 0;    // structure sound: guessed-end path trims trailing zeros
}

void registerFmt_netcdf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("NetCDF", "nc", "database", B({0x43,0x44,0x46,0x01}), 8*GB,
                  SizeMode::Header, vNetcdf); c.min_size = 24; add(c); }
    { auto c = mk("NetCDF_CDF2", "nc", "database", B({0x43,0x44,0x46,0x02}), 8*GB,
                  SizeMode::Header, vNetcdf); c.min_size = 24; add(c); }
}

}  // namespace ghost
