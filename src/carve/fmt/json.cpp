// GHOST RECOVER — json signature family (one file per format).
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

// Strict JSON walker: tracks string/escape state and brace depth and only
// allows JSON structural characters outside strings. Ends at the closing
// brace of the top-level object; any non-JSON byte before that rejects.
// A 41-byte printable `{"...` blob can no longer walk to the end of a disk
// region or mask neighbouring formats.
i64 vJson(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off + 1;                       // magic already consumed "{\"
    int depth = 1;
    bool inStr = false, esc = false;
    bool sawColon = false;
    for (; p < off + max; p++) {
        u8 c = s.byte(p);
        if (inStr) {
            if (esc) { esc = false; continue; }
            if (c == '\\') { esc = true; continue; }
            if (c == '"') { inStr = false; continue; }
            if (c < 0x20) return -1;               // no raw control chars
            continue;
        }
        if (c == '"') { inStr = true; continue; }
        if (c == '{') { depth++; continue; }
        if (c == '[' || c == ']') continue;
        if (c == ':') { sawColon = true; continue; }
        if (c == ',') continue;
        if (c == ' ') continue;
        if (c == '\t' || c == '\n' || c == '\r') continue;
        if (c == '-') continue;
        if (c >= '0' && c <= '9') continue;
        if (c == '.' || c == 'e' || c == 'E' || c == '+') continue;
        if (c == 't' && p + 4 <= off + max && s.byte(p + 1) == 'r' &&
            s.byte(p + 2) == 'u' && s.byte(p + 3) == 'e') { p += 3; continue; }
        if (c == 'f' && p + 5 <= off + max && s.byte(p + 1) == 'a' &&
            s.byte(p + 2) == 'l' && s.byte(p + 3) == 's' && s.byte(p + 4) == 'e') { p += 4; continue; }
        if (c == 'n' && p + 4 <= off + max && s.byte(p + 1) == 'u' &&
            s.byte(p + 2) == 'l' && s.byte(p + 3) == 'l') { p += 3; continue; }
        if (c == '}' ) {
            if (--depth == 0) {
                if (!sawColon) return -1;
                return p - off + 1;
            }
            continue;
        }
        return -1;
    }
    return -1;
}

void registerFmt_json(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("JSON", "json", "code", S("{\""), 64*MB, SizeMode::Text, vJson);
      c.min_size = 32; add(c); }
}

}  // namespace ghost
