// GHOST RECOVER — svg signature family (one file per format).
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

i64 vSvgXml(ByteSource& s, i64 off, i64 max, const CarveSpec& spec) {
    auto head = s.read(off, std::min<i64>(max, 8192));
    if (head.size() < 16) return -1;
    bool found = false;
    for (size_t i = 0; i + 4 <= head.size(); i++) {
        if (std::memcmp(head.data() + i, "<svg", 4) == 0) { found = true; break; }
    }
    if (!found) return -1;
    i64 size = vText(s, off, max, spec);
    if (size <= 0) return -1;
    // Text carving runs into whatever printable bytes follow the file (a
    // random ASCII byte in the slack region pads the recovered copy). An SVG
    // is a document: it ends with a closing root tag, so trim the run back to
    // the end of the last </svg> plus its trailing newline.
    const i64 kProbe = std::min<i64>(size, 64 * KB);
    auto run = s.read(off, kProbe);
    i64 lastClose = -1;
    for (i64 i = 0; i + 6 <= (i64)run.size(); i++) {
        if (std::memcmp(run.data() + (size_t)i, "</svg", 5) == 0) lastClose = i + 5;
    }
    if (lastClose >= 0) {
        i64 trimmed = lastClose;
        if (trimmed < (i64)run.size() && run[(size_t)trimmed] == '>') trimmed++;
        if (trimmed < (i64)run.size() && run[(size_t)trimmed] == '\r') trimmed++;
        if (trimmed < (i64)run.size() && run[(size_t)trimmed] == '\n') trimmed++;
        if (trimmed > 0 && trimmed < size) size = trimmed;
    }
    return size;
}void registerFmt_svg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("SVG", "svg", "image", S("<svg"), 32*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("SVG_XML", "svg", "image", S("<?xml"), 32*MB, SizeMode::Text, vSvgXml);
      c.min_size = 64; c.priority = 15; add(c); }
}

}  // namespace ghost
