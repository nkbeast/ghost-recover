// GHOST RECOVER — der signature family (one file per format).
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

i64 vDer(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
    struct El { i64 pos; i64 contentEnd; };
    std::vector<El> stack;
    i64 pos = off;
    i64 lastEnd = -1;
    i64 total = 0;
    const i64 kLimit = (i64)1 << 28;
    while (pos < off + max && total < kLimit) {
        u8 tag = s.byte(pos);
        // Top-level element: tag byte must be 0x30/0x31 (SEQUENCE/SET) for the
        // common .der/.p12 containers; a raw OCTET STRING wrapper is rare
        // (PKCS#12 is a sequence, so accept 0x30/0x31).
        if (tag != 0x30 && tag != 0x31) break;
        bool constructed = (tag & 0x20) != 0;
        i64 p = pos + 1;
        i64 len = 0;
        u8 lb = s.byte(p++);
        if (lb & 0x80) {
            int n = lb & 0x7F;
            if (n < 1 || n > 4 || p + n > off + max) return -1;
            for (int k = 0; k < n; k++) len = (len << 8) | s.byte(p++);
        } else len = lb;
        i64 contentEnd = p + len;
        if (contentEnd > off + max) return -1;
        if (!constructed) return -1;   // must be a constructed container
        // Walk down the constructed chain.
        stack.push_back({p, contentEnd});
        while (!stack.empty()) {
            El& top = stack.back();
            if (top.pos >= top.contentEnd) {
                lastEnd = top.contentEnd;
                stack.pop_back();
                continue;
            }
            u8 t = s.byte(top.pos);
            i64 q = top.pos + 1;
            i64 l = 0;
            u8 lbb = s.byte(q++);
            if (lbb & 0x80) {
                int n = lbb & 0x7F;
                if (n < 1 || n > 4 || q + n > top.contentEnd) return -1;
                for (int k = 0; k < n; k++) l = (l << 8) | s.byte(q++);
            } else l = lbb;
            if (q + l > top.contentEnd) return -1;
            bool c = (t & 0x20) != 0;
            if (c) {
                top.pos = q + l;                 // consume after descent
                stack.push_back({q, q + l});
                if (stack.size() > 64) return -1;
            } else {
                top.pos = q + l;
                lastEnd = q + l;
            }
        }
        if (lastEnd > pos) pos = lastEnd;
        else break;
    }
    if (lastEnd < 0) return -1;
    if (lastEnd - off > max) return -1;
    if (spec.min_size > 0 && lastEnd - off < spec.min_size) return -1;
    return lastEnd - off;
}void registerFmt_der(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("PKCS12", "p12", "crypto", B({0x30,0x82}), 4*MB, SizeMode::Header, vDer));
    add(mk("DER", "der", "misc", B({0x30,0x82}), 64*MB, SizeMode::Header, vDer));
    { auto c = mk("DER_SMALL", "der", "misc", B({0x30,0x81}), 64*MB, SizeMode::Header, vDer);
      c.priority = 10; c.min_size = 32; add(c); }
}

}  // namespace ghost
