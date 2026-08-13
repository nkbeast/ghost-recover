// GHOST RECOVER — carver signature specs and validators for Forensic artefacts.
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


// --- pcap ------------------------------------------------------------------
i64 vPcap(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 magic = s.le32(off);
    bool swapped = (magic == 0xD4C3B2A1 || magic == 0x4D3CB2A1);
    bool nano = (magic == 0xA1B23C4D || magic == 0x4D3CB2A1);
    (void)nano;
    auto rd32 = [&](i64 o) { return swapped ? s.be32(off + o) : s.le32(off + o); };
    u32 snaplen = rd32(16);
    if (snaplen == 0 || snaplen > 1 << 22) return -1;
    i64 p = 24;
    int packets = 0;
    while (p + 16 <= max && packets < 10000000) {
        u32 inclLen = rd32(p + 8);
        u32 origLen = rd32(p + 12);
        if (inclLen == 0 || inclLen > snaplen || origLen < inclLen) break;
        p += 16 + (i64)inclLen;
        packets++;
    }
    if (packets < 1) return -1;
    return p;
}

// --- pcapng ----------------------------------------------------------------
i64 vPcapng(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 bom = s.le32(off + 8);
    bool swapped = (bom == 0x4D3C2B1A);
    auto rd32 = [&](i64 o) { return swapped ? s.be32(off + o) : s.le32(off + o); };
    if (bom != 0x1A2B3C4D && bom != 0x4D3C2B1A) return -1;
    i64 p = 0;
    int blocks = 0;
    while (p + 12 <= max && blocks < 10000000) {
        u32 total = rd32(p + 4);
        if (total < 12 || (total & 3) || p + (i64)total > max) break;
        p += total;
        blocks++;
    }
    if (blocks < 1) return -1;
    return p;
}

// --- Windows event log (EVTX) ---------------------------------------------
i64 vEvtx(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u16 hdrSize = s.le16(off + 0x28);
    if (hdrSize < 4096) return -1;
    u16 chunkCount = s.le16(off + 0x2A);
    if (chunkCount == 0) return -1;
    i64 total = (i64)hdrSize + (i64)chunkCount * 65536;
    if (total > max) return -1;
    auto c0 = s.read(off + hdrSize, 8);
    if (c0.size() < 8 || c0[0] != 'E' || c0[1] != 'l' || c0[2] != 'f'
        || c0[3] != 'C' || c0[4] != 'h' || c0[5] != 'n' || c0[6] != 'k') return -1;
    return total;
}

// --- Windows registry hive -------------------------------------------------
i64 vRegf(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    u32 hbinsSize = s.le32(off + 0x28);
    if (hbinsSize == 0 || (i64)hbinsSize + 4096 > max) return -1;
    return 4096 + (i64)hbinsSize;
}

void registerForensic(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PCAP_LE", "pcap", "forensic", B({0xD4,0xC3,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_BE", "pcap", "forensic", B({0xA1,0xB2,0xC3,0xD4}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS", "pcap", "forensic", B({0xA1,0xB2,0x3C,0x4D}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS_LE", "pcap", "forensic", B({0x4D,0x3C,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAPNG", "pcapng", "forensic", B({0x0A,0x0D,0x0D,0x0A}), 8*GB,
                  SizeMode::Container, vPcapng); c.min_size = 28; add(c); }
    { auto c = mk("EVTX", "evtx", "forensic", S("ElfFile\0"), 4*GB, SizeMode::Header, vEvtx);
      c.min_size = 4096; add(c); }
    add(mk("EVT", "evt", "forensic", B({0x30,0x00,0x00,0x00,'L','f','L','e'}), 512*MB));
    { auto c = mk("REGF", "hiv", "forensic", S("regf"), 4*GB, SizeMode::Header, vRegf);
      c.min_size = 4096; add(c); }
    add(mk("LNK", "lnk", "forensic", B({0x4C,0x00,0x00,0x00,0x01,0x14,0x02,0x00}), 16*MB));
    add(mk("PREFETCH", "pf", "forensic", S("SCCA"), 16*MB));
    add(mk("PREFETCH_C", "pf", "forensic", B({0x4D,0x41,0x4D,0x04}), 16*MB));
    add(mk("JOB", "job", "forensic", B({0x01,0x05,0x01,0x00}), 4*MB));
}

}  // namespace ghost
