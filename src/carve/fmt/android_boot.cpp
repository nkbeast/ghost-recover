// GHOST RECOVER — ANDROID_BOOT vm signatures.
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

i64 vAndroidBoot(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (off + 2048 > off + max) return -1;
    auto h = s.read(off, 2048);
    if (h.size() < 2048) return -1;
    u32 kernel = 0, ramdisk = 0, second = 0, pageSize = 0;
    for (int i = 0; i < 4; i++) {
        kernel   |= (u32)h[ 8 + i] << (i * 8);
        ramdisk  |= (u32)h[16 + i] << (i * 8);
        second   |= (u32)h[24 + i] << (i * 8);
        pageSize |= (u32)h[36 + i] << (i * 8);
    }
    if (pageSize < 512 || pageSize > 0x10000) return -1;
    if (kernel == 0 && ramdisk == 0 && second == 0) return -1;
    auto align = [&](i64 x) { return ((x + pageSize - 1) / pageSize) * pageSize; };
    i64 end = 2048 + align(kernel) + align(ramdisk) + align(second);
    if (end > max) return -1;
    return end;
}

void registerFmt_android_boot(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("ANDROID_BOOT", "img", "vm", S("ANDROID!"), 512*MB, SizeMode::Container, vAndroidBoot); c.min_size = 2048; add(c); }
}

}  // namespace ghost
