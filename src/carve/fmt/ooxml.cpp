// GHOST RECOVER — ooxml signature family (one file per format).
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

void registerFmt_ooxml(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("DOCX", "docx", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("word/"), -1, 8192); c.priority = 30; c.min_size = 256; add(c); }
    { auto c = mk("XLSX", "xlsx", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("xl/"), -1, 8192); c.priority = 30; c.min_size = 256; add(c); }
    { auto c = mk("PPTX", "pptx", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("ppt/"), -1, 8192); c.priority = 30; c.min_size = 256; add(c); }
    { auto c = mk("ODT", "odt", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("opendocument.text"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("ODS", "ods", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("opendocument.spreadsheet"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("ODP", "odp", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("opendocument.presentation"), -1, 8192); c.priority = 30; add(c); }
    { auto c = mk("EPUB", "epub", "document", B({'P','K',0x03,0x04}), 512*MB, SizeMode::Header, vZip);
      withConfirm(c, S("application/epub"), -1, 8192); c.priority = 30; add(c); }
}

}  // namespace ghost
