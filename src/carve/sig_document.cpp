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

// --- DjVu: IFF-style chunk chain; BE32 length at 8 sets the file size. ------
i64 vDjvu(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = 12 + s.be32(off + 8);
    if (total < 12 || total > max) return -1;
    i64 p = off + 12;
    while (p < off + total) {
        if (p + 8 > off + total) return -1;
        u32 size = s.be32(p + 4);
        if (size > (u32)(off + total - p - 8)) return -1;
        p += 8 + size;
    }
    return (p == off + total) ? total : -1;
}

// --- MOBI: PalmDB container (magic at 60); record table sizes the file. -----
i64 vMobi(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 60) != 0x424F4F4B) return -1;             // "BOOK"
    if (s.be32(off + 64) != 0x4D4F4249) return -1;             // "MOBI"
    u32 num = s.be16(off + 76);
    if (num < 1 || num > 100000) return -1;
    i64 table = off + 78;
    if (table + 8 * (i64)num > off + max) return -1;
    u32 lastOff = s.be32(table + 8 * (num - 1));
    u16 lastSize = s.be16(table + 8 * (i64)num);
    if (lastSize == 0) return -1;
    i64 total = (i64)lastOff + lastSize;
    if (total < 78 + 8 * (i64)num || total > max) return -1;
    u32 prev = 0;
    for (u32 i = 0; i < num; i++) {
        u32 o = s.be32(table + 8 * (i64)i);
        if (o < prev || o > (u32)total) return -1;
        prev = o;
    }
    return total;
}

// --- CHM: ITSF header then 0x800-byte PMGL pages chained by "next". ---------
i64 vChm(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (s.be32(off + 8) != 0x60) return -1;                    // header length
    u32 ver = s.be32(off + 4);
    if (ver != 2 && ver != 3) return -1;
    i64 p = off + 0x60;
    for (int guard = 0; guard < (1 << 16); guard++) {
        if (p + 0x800 > off + max) return -1;
        if (s.be32(p) != 0x504D474C) return -1;                // PMGL
        i64 next = s.le32(p + 8);
        if (next == 0) return (p + 0x800) - off;               // last page
        if (next != (p - off) / 0x800 + 1 || next > (1 << 16)) return -1;
        p += 0x800;
    }
    return -1;
}

// --- OneNote: 72-byte header; LE32 fragment length at 72. -------------------
i64 vOne(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 cb = s.le32(off + 72);
    if (cb < 8) return -1;
    i64 total = 72 + (i64)cb;
    return (total <= max) ? total : -1;
}

// --- WordPerfect: LE32 file size at 0x10. -----------------------------------
i64 vWpd(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 total = s.le32(off + 0x10);
    if (total < 512 || total > max) return -1;
    return total;
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
    { auto c = mk("MOBI", "mobi", "document", S("BOOKMOBI"), 256*MB, SizeMode::Header, vMobi);
      c.magic_offset = 60; add(c); }
    add(mk("DJVU", "djvu", "document", S("AT&TFORM"), 512*MB, SizeMode::Header, vDjvu));
    add(mk("CHM", "chm", "document", S("ITSF"), 512*MB, SizeMode::Header, vChm));
    add(mk("ONE", "one", "document", B({0xE4,0x52,0x5C,0x7B,0x8C,0xD8,0xA7,0x4D}), 512*MB, SizeMode::Header, vOne));
    add(mk("WPD", "wpd", "document", B({0xFF,'W','P','C'}), 128*MB, SizeMode::Header, vWpd));
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
