// GHOST RECOVER — pdf signature family (one file per format).
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

i64 vPdf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    const i64 kStep = 1 * MB;
    auto skipEol = [&](i64 rel) {
        if (rel <= 0 || rel >= max) return rel;
        auto tail = s.read(off + rel, 2);
        if (!tail.empty() && (tail[0] == '\r' || tail[0] == '\n')) rel++;
        if (tail.size() > 1 && tail[0] == '\r' && tail[1] == '\n') rel++;
        return rel;
    };
    i64 startxref = -1;
    for (i64 base = 0; base < max; base += kStep - 9) {
        auto buf = s.read(off + base, std::min(kStep, max - base));
        if (buf.size() < 9) break;
        for (size_t i = 0; i + 9 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, "startxref", 9) == 0) {
                startxref = base + (i64)i + 9;
                break;
            }
        }
        if (startxref >= 0 || (i64)buf.size() < std::min(kStep, max - base)) break;
    }
    if (startxref < 0) {
        // Minimal or truncated producers emit no xref table at all; their only
        // reliable end marker is the first %%EOF, which closes the trailer.
        for (i64 base = 0; base < max; base += kStep - 5) {
            auto buf = s.read(off + base, std::min(kStep, max - base));
            if (buf.size() < 5) break;
            for (size_t i = 0; i + 5 <= buf.size(); i++) {
                if (std::memcmp(buf.data() + i, "%%EOF", 5) == 0)
                    return skipEol(base + (i64)i + 5);
            }
            if ((i64)buf.size() < std::min(kStep, max - base)) break;
        }
        return -1;
    }
    const i64 scanEnd = std::min(max, startxref + 1 * MB);
    i64 lastEof = -1;
    for (i64 base = startxref; base >= 0 && base < scanEnd; base += kStep - 8) {
        auto buf = s.read(off + base, std::min(kStep, scanEnd - base));
        if (buf.size() < 5) break;
        for (size_t i = 0; i + 5 <= buf.size(); i++) {
            if (std::memcmp(buf.data() + i, "%%EOF", 5) == 0) lastEof = base + (i64)i + 5;
        }
        if ((i64)buf.size() < std::min(kStep, scanEnd - base)) break;
    }
    if (lastEof < 0) return -1;
    return skipEol(lastEof);
}void registerFmt_pdf(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PDF", "pdf", "document", S("%PDF-"), 2*GB, SizeMode::Footer, vPdf);
      c.footer = S("%%EOF"); c.min_size = 100; add(c); }
}

}  // namespace ghost
