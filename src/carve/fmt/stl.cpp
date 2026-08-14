// GHOST RECOVER — stl signature family (one file per format).
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

i64 vStlAscii(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    static const char* kLineTokens[] = {
        "facet normal", "solid ", "endsolid", "outer loop", "inner loop",
        "vertex", "endloop", "endfacet", "color", "sourcestatcode", "aoutstatcode"};
    i64 p = off;
    int facets = 0;
    while (p < off + max) {
        i64 q = p;
        while (q < off + max && (s.byte(q) == ' ' || s.byte(q) == '\t')) q++;
        auto tok = s.read(q, 13);
        // endsolid closes the file; its line end is the last byte.
        if (tok.size() >= 8 && std::memcmp(tok.data(), "endsolid", 8) == 0) {
            i64 e = q + 8;
            while (e < off + max && s.byte(e) != '\n') e++;
            return std::min<i64>(e + 1, off + max) - off;
        }
        bool known = false;
        for (const char* t : kLineTokens) {
            size_t n = strlen(t);
            if (tok.size() >= n && std::memcmp(tok.data(), t, n) == 0) { known = true; break; }
        }
        if (std::memcmp(tok.data(), "facet normal", 12) == 0) facets++;
        if (!known) break;                             // foreign line: not ours
        while (q < off + max && s.byte(q) != '\n') q++;
        if (q >= off + max) break;
        p = q + 1;
    }
    return (facets >= 1) ? p - off : -1;
}void registerFmt_stl(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("STL_ASCII", "stl", "misc", S("solid "), 512*MB, SizeMode::Container, vStlAscii));
}

}  // namespace ghost
