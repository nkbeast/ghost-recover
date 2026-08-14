// GHOST RECOVER — pcap signature family (one file per format).
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
}void registerFmt_pcap(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    { auto c = mk("PCAP_LE", "pcap", "forensic", B({0xD4,0xC3,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_BE", "pcap", "forensic", B({0xA1,0xB2,0xC3,0xD4}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS", "pcap", "forensic", B({0xA1,0xB2,0x3C,0x4D}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
    { auto c = mk("PCAP_NS_LE", "pcap", "forensic", B({0x4D,0x3C,0xB2,0xA1}), 8*GB,
                  SizeMode::Container, vPcap); c.min_size = 24; add(c); }
}

}  // namespace ghost
