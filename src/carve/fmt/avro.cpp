// GHOST RECOVER — avro signature family (one file per format).
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

i64 vAvro(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    auto sync0 = s.read(off + 4, 16);
    if (sync0.size() < 16) return -1;
    auto varint = [&](i64& at) -> i64 {
        i64 v = 0, shift = 0;
        for (int i = 0; i < 10; i++) {
            if (at >= off + max) return -1;
            u8 b = s.byte(at++);
            v |= (i64)(b & 0x7F) << shift;
            if (!(b & 0x80)) return v;
            shift += 7;
        }
        return -1;
    };
    i64 p = off + 20, end = -1;
    for (int blocks = 0; p < off + max && blocks < 1000000; blocks++) {
        i64 q = p;
        i64 count = varint(q);
        i64 size = varint(q);
        if (count < 0 || size < 0 || size > off + max - q) break;
        q += size;
        auto sync = s.read(q, 16);
        if (sync.size() < 16 || std::memcmp(sync.data(), sync0.data(), 16) != 0) break;
        q += 16;
        end = q;
        p = q;
    }
    return (end > off) ? end - off : -1;
}void registerFmt_avro(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("Avro", "avro", "database", B({'O','b','j',0x01}), 8*GB, SizeMode::Header, vAvro));
}

}  // namespace ghost
