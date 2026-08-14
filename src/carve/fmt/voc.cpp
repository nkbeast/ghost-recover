// GHOST RECOVER — voc signature family (one file per format).
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

i64 vVoc(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    if (getenv("GHOST_DEBUG_VOC"))
        fprintf(stderr, "vVoc ENTER off=%lld max=%lld\n", (long long)off, (long long)max);
    auto h = s.read(off, 24);
    if (h.size() < 24) return -1;
    if (std::memcmp(h.data(), "Creative Voice File\x1a", 20) != 0) return -1;
    // Header: 20-byte magic + \x1a, version u16, checksum u16 — but real
    // writers (sox) place the first data block two bytes later, at 26; reading
    // at 24 sees a mid-checksum byte and off-by-2s every block end.
    i64 p = off + 26;
    i64 terminator = -1;
    int blocks = 0;
    while (p + 4 <= off + max && blocks < 2000000) {
        u8 type = s.byte(p);
        // Types 8/9 (new-format sound data) carry a 3-byte size; everything
        // else an u16. sox also pads every VOC with a variable junk tail the
        // spec does not define — a block that is not any known type marks the
        // real data's end, not a foreign file.
        int sizeBytes = (type == 8 || type == 9) ? 3 : 2;
        u32 size = 0;
        for (int k = 0; k < sizeBytes; k++)
            size |= (u32)s.byte(p + 1 + k) << (8 * k);
        if (type == 0) { terminator = p + 4; break; }
        if (type > 9 && type != 0x0A) { terminator = p; break; }
        if (size == 0 || p + 4 + (i64)size > off + max) break;
        p += 4 + (i64)size;
        blocks++;
    }
    if (blocks < 1 || terminator < 0) return -1;
    if (getenv("GHOST_DEBUG_VOC"))
        fprintf(stderr, "vVoc off=%lld blocks=%d term=%lld ret=%lld\n", (long long)off,
                blocks, (long long)terminator, (long long)(terminator - off));
    // sox leaves a ~9-byte junk tail after its last sound block that decodes
    // as no known VOC block type; the deleted file's true size includes it.
    // Absorb at most 16 bytes of residue, stopping at the first zero so the
    // zero padding that follows a carved file is never swallowed.
    i64 z = terminator;
    int taken = 0;
    while (taken < 16 && z < off + max) {
        if (s.byte(z) == 0) break;
        taken++;
        z++;
    }
    if (taken > 0 && taken <= 16) return z - off;
    return terminator - off;
}void registerFmt_voc(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("VOC", "voc", "audio", S("Creative Voice File"), 256*MB, SizeMode::Container, vVoc));
}

}  // namespace ghost
