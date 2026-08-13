// GHOST RECOVER — carver signature specs and validators for Documents.
//
// Part of the per-category split of the former monolithic signatures.cpp.
// Shared plumbing (mk, withConfirm, cross-category validators) lives in
// sig_common.h / sig_common.cpp; the registry aggregator is signatures.cpp.
#include "ghost/carve.h"
#include "ghost/util.h"
#include "sig_common.h"

#include <algorithm>
#include <cstring>

namespace ghost {


// --- PDF: find %%EOF, but only within 1 MB after the ``startxref`` line -----
// -- (a ``startxref`` that byte-ranges back to %%EOF is part of an old
// -- incremental update; the PDF proper never continues past its final EOF,
// -- so bounding the scan here avoids eating arbitrary trailing data).
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
}

void registerDocuments(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PDF", "pdf", "document", S("%PDF-"), 2*GB, SizeMode::Footer, vPdf);
      c.footer = S("%%EOF"); c.min_size = 100; add(c); }
    { auto c = mk("PS", "ps", "document", S("%!PS"), 256*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
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
    { auto c = mk("XLS", "xls", "document", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("Workbook"), -1, 16384); c.priority = 30; add(c); }
    { auto c = mk("PPT", "ppt", "document", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2);
      withConfirm(c, U16("PowerPoint"), -1, 16384); c.priority = 30; add(c); }
    { auto c = mk("DOC", "doc", "document", B({0xD0,0xCF,0x11,0xE0,0xA1,0xB1,0x1A,0xE1}), 512*MB,
                  SizeMode::Header, vOle2); c.min_size = 512; add(c); }
    { auto c = mk("RTF", "rtf", "document", S("{\\rtf"), 128*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    add(mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB));
    add(mk("DJVU", "djvu", "document", S("AT&TFORM"), 512*MB));
    add(mk("CHM", "chm", "document", S("ITSF"), 512*MB));
    add(mk("ONE", "one", "document", B({0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D}), 512*MB));
    add(mk("WPD", "wpd", "document", B({0xFF,'W','P','C'}), 128*MB));
    { auto c = mk("HTML", "html", "document", S("<!DOCTYPE html"), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("HTML_TAG", "html", "document", S("<html"), 64*MB, SizeMode::Text, vText);
      c.min_size = 64; add(c); }
    { auto c = mk("XML", "xml", "document", S("<?xml"), 64*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
    { auto c = mk("LATEX", "tex", "document", S("\\documentclass"), 32*MB, SizeMode::Text, vText);
      c.min_size = 32; add(c); }
}

}  // namespace ghost
