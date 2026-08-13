// GHOST RECOVER — Aho-Corasick multi-pattern matcher.
//
// The old carver called std::search once per signature per chunk: with ~180
// signatures that is 180 full passes over every byte of the device, and the
// cost grew linearly with each new format added. This walks each byte exactly
// once and reports every signature ending at it, so adding signatures is free.
#include "ghost/carve.h"

#include <queue>

namespace ghost {

void MultiMatcher::add(const std::vector<u8>& pattern, int id) {
    if (pattern.empty() || built_) return;
    int node = 0;
    for (u8 c : pattern) {
        auto it = edges_[node].find(c);
        if (it == edges_[node].end()) {
            edges_.push_back({});
            int next = (int)edges_.size() - 1;
            edges_[node][c] = next;
            node = next;
        } else {
            node = it->second;
        }
    }
    if (out_.size() < edges_.size()) out_.resize(edges_.size());
    if ((int)pat_len_.size() <= id) pat_len_.resize((size_t)id + 1, 0);
    pat_len_[id] = (int)pattern.size();
    out_[node].push_back(id);
    patterns_++;
    if (pattern.size() > max_len_) max_len_ = pattern.size();
}

void MultiMatcher::build() {
    if (built_) return;
    const size_t n = edges_.size();
    out_.resize(n);
    fail_.assign(n, 0);
    out_link_.assign(n, -1);
    goto_.assign(n * 256, 0);

    std::queue<int> q;
    for (int c = 0; c < 256; c++) {
        auto it = edges_[0].find((u8)c);
        if (it == edges_[0].end()) {
            goto_[(size_t)0 * 256 + c] = 0;
        } else {
            int child = it->second;
            goto_[(size_t)0 * 256 + c] = child;
            fail_[child] = 0;
            q.push(child);
        }
    }

    while (!q.empty()) {
        int u = q.front();
        q.pop();
        // Chain outputs through the failure link so overlapping matches (e.g. a
        // 4-byte signature that is a suffix of an 8-byte one) all fire.
        out_link_[u] = !out_[fail_[u]].empty() ? fail_[u] : out_link_[fail_[u]];
        for (int c = 0; c < 256; c++) {
            auto it = edges_[u].find((u8)c);
            if (it == edges_[u].end()) {
                goto_[(size_t)u * 256 + c] = goto_[(size_t)fail_[u] * 256 + c];
            } else {
                int v = it->second;
                goto_[(size_t)u * 256 + c] = v;
                fail_[v] = goto_[(size_t)fail_[u] * 256 + c];
                q.push(v);
            }
        }
    }

    // The trie edges are no longer needed once the DFA table exists.
    std::vector<std::map<u8, int>>().swap(edges_);
    built_ = true;
}

void MultiMatcher::scan(const u8* data, size_t len, i64 base, int& state,
                        const std::function<void(i64, int)>& cb) const {
    if (!built_ || goto_.empty() || !data) return;
    int s = state;
    const int* g = goto_.data();
    for (size_t i = 0; i < len; i++) {
        s = g[(size_t)s * 256 + data[i]];
        for (int id : out_[s]) cb(base + (i64)i - pat_len_[id] + 1, id);
        for (int link = out_link_[s]; link >= 0; link = out_link_[link])
            for (int id : out_[link]) cb(base + (i64)i - pat_len_[id] + 1, id);
    }
    state = s;
}

// ---------------------------------------------------------------------------
// ByteSource
// ---------------------------------------------------------------------------
bool ByteSource::fill(i64 off, i64 len) {
    if (win_len_ > 0 && off >= win_start_ && off - win_start_ + len <= win_len_) return true;
    if (off < 0 || len <= 0) return false;
    const i64 aligned = off & ~(kWin - 1);
    auto v = d_.readBlock((u64)aligned, kWin);
    if (v.empty()) return false;
    win_ = std::move(v);
    win_start_ = aligned;
    win_len_ = (i64)win_.size();
    return off >= win_start_ && off - win_start_ + len <= win_len_;
}

std::vector<u8> ByteSource::read(i64 off, i64 len) {
    if (off < 0 || len <= 0) return {};
    if (off >= limit_) return {};
    if (off + len > limit_) len = limit_ - off;
    // Requests as large as the window can never fit inside an aligned window
    // when the offset is unaligned (vText reads 64 KiB steps), so serve them
    // directly. Small reads are where the win is — validators issue millions.
    if (len >= kWin) return d_.readBlock((u64)off, len);
    if (!fill(off, len)) {
        // Tail of the device (or an unaligned request straddling the window
        // edge): read what actually exists rather than failing the candidate.
        return d_.readBlock((u64)off, len);
    }
    return std::vector<u8>(win_.begin() + (off - win_start_),
                           win_.begin() + (off - win_start_) + len);
}

u8 ByteSource::byte(i64 off) {
    if (off < 0 || off >= limit_) return 0;
    if (!fill(off, 1)) return 0;
    return win_[(size_t)(off - win_start_)];
}

u32 ByteSource::be32(i64 off) {
    auto v = read(off, 4);
    if (v.size() < 4) return 0;
    return (u32)v[0] << 24 | (u32)v[1] << 16 | (u32)v[2] << 8 | v[3];
}
u32 ByteSource::le32(i64 off) {
    auto v = read(off, 4);
    if (v.size() < 4) return 0;
    return (u32)v[3] << 24 | (u32)v[2] << 16 | (u32)v[1] << 8 | v[0];
}
u16 ByteSource::be16(i64 off) {
    auto v = read(off, 2);
    if (v.size() < 2) return 0;
    return (u16)((u16)v[0] << 8 | v[1]);
}
u16 ByteSource::le16(i64 off) {
    auto v = read(off, 2);
    if (v.size() < 2) return 0;
    return (u16)((u16)v[1] << 8 | v[0]);
}

}  // namespace ghost
