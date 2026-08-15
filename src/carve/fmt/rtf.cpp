// GHOST RECOVER — rtf signature family (one file per format).
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

// RTF brace-balance walker: counts groups, honours backslash escapes and
// \binN binary data (which may contain braces), ends at depth 0.
i64 vRtf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The magic already consumed the opening '{' of "{\rtf".
    i64 p = off + 5;
    int depth = 1;
    while (p < off + max) {
        u8 c = s.byte(p);
        if (c == '\\') {
            if (p + 1 >= off + max) return -1;
            u8 n = s.byte(p + 1);
            if (n == 'b' && p + 4 <= off + max && s.byte(p + 2) == 'i' &&
                s.byte(p + 3) == 'n') {
                i64 j = p + 4;
                i64 nbin = 0;
                while (j < off + max && s.byte(j) >= '0' && s.byte(j) <= '9') {
                    nbin = nbin * 10 + (s.byte(j) - '0');
                    if (nbin > (1 << 30)) return -1;
                    j++;
                }
                if (j < off + max && s.byte(j) == ' ') j++;   // delimiter space
                if (nbin > 0) {
                    if (j + nbin > off + max) return -1;
                    p = j + nbin;
                    continue;
                }
            }
            p += 2;                  // escape: \X or \{ \} \\ — skip the pair
            continue;
        }
        if (c == '{') { depth++; p++; continue; }
        if (c == '}') {
            depth--;
            if (depth == 0) return p - off + 1;
            p++;
            continue;
        }
        p++;
    }
    return -1;
}

void registerFmt_rtf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("RTF", "rtf", "document", S("{\\rtf"), 128*MB, SizeMode::Text, vRtf);
      c.min_size = 64; add(c); }
}

}  // namespace ghost
