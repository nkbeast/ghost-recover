// GHOST RECOVER — gpg signature family (one file per format).
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

i64 vGpg(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    i64 p = off, lastEnd = off;
    int packets = 0;
    bool havePub = false, haveSec = false;
    while (p < off + max && packets < 1000000) {
        auto h = s.read(p, 6);
        if (h.size() < 1) break;
        u8 b0 = h[0];
        if (b0 < 0x80 || b0 == 0xFF) break;      // not a packet header
        int tag = (b0 & 0x40) ? (b0 & 0x3F) : ((b0 >> 2) & 0x0F);
        // keyring structure: the first packet is a key (tag 6 pub / 7
        // secret); uids (13) and sigs (2) follow anything; a key may follow
        // a key of the same type (multi-key exports); subkeys (14 pub /
        // 17 secret) must match the preceding key type, and a keyring never
        // mixes public and secret keys
        if (packets == 0) {
            if (tag != 6 && tag != 7) break;
            havePub = (tag == 6);
            haveSec = (tag == 7);
        } else {
            bool ok;
            switch (tag) {
            case 2: case 13: ok = true; break;
            case 6: ok = !haveSec; havePub = true; break;
            case 7: ok = !havePub; haveSec = true; break;
            case 14: ok = havePub && !haveSec; break;
            case 17: ok = haveSec && !havePub; break;
            default: ok = false; break;
            }
            if (!ok) break;
        }
        i64 len = -1, hdrLen = 1;
        if ((b0 & 0x40) == 0) {                  // old format
            int lt = b0 & 0x03;
            if (lt == 3) break;                  // indeterminate: no end marker
            int need = lt == 0 ? 1 : (lt == 1 ? 2 : 4);
            if (h.size() < (size_t)(1 + need)) break;
            len = 0;
            for (int k = 0; k < need; k++) len = (len << 8) | h[1 + k];
            hdrLen = 1 + need;
        } else {                                 // new format
            if (h.size() < 2) break;
            u8 l1 = h[1];
            if (l1 < 0x80) { len = l1; hdrLen = 2; }
            else if (l1 == 0xFF) {
                if (h.size() < 6) break;
                len = ((i64)h[2] << 24) | ((i64)h[3] << 16) | ((i64)h[4] << 8) | h[5];
                hdrLen = 6;
            } else {
                if (h.size() < 3) break;
                len = ((i64)(l1 & 0x7F) << 8) | h[2];
                hdrLen = 3;
            }
        }
        if (len < 0 || p + hdrLen + len > off + max) break;
        lastEnd = p + hdrLen + len;
        p = lastEnd;
        packets++;
    }
    if (packets == 0) return -1;
    return lastEnd - off;
}void registerFmt_gpg(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("GPG_KEYRING", "gpg", "crypto", B({0x99,0x01}), 16*MB, SizeMode::FrameStream, vGpg));
}

}  // namespace ghost
