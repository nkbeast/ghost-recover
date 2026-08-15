// GHOST RECOVER — job signature family (one file per format).
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

i64 vJob(ByteSource& s, i64 off, i64 max, const CarveSpec&) {
    // The signature itself encodes the product version (1.5) and the file
    // format version (1.0); the header then continues with a job UUID and
    // comment sections, none of which carries a reliable file length.
    return 0;
}void registerFmt_job(Registry& r) {
    auto add = [&](CarveSpec c) { r.push_back(std::move(c)); };

    add(mk("JOB", "job", "forensic", B({0x01,0x05,0x01,0x00}), 4*MB, SizeMode::Header, vJob));
}

}  // namespace ghost
