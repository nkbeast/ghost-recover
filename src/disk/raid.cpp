// GHOST RECOVER — RAID detection and reconstruction.
//
// The old raid.cpp was six lines of comments saying that reconstruction "would
// go here". This implements it:
//   * reads Linux md superblocks, both 1.x (all three placements) and 0.90
//   * brute-forces chunk size, member order and parity layout when the
//     superblocks are gone, validating each guess by looking for a real
//     filesystem at the start of the assembled array
//   * maps logical offsets for linear, RAID 0, 1, 5, 6 and 10 (near layout)
//   * rebuilds data from parity when one member is missing or unreadable
#include "ghost/disk.h"

#include "ghost/carve.h"
#include "ghost/fs.h"
#include "ghost/util.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <limits>
#include <numeric>

#include <fcntl.h>
#include <unistd.h>

namespace ghost {

const char* raidLevelName(RaidLevel l) {
    switch (l) {
        case RaidLevel::Linear: return "linear";
        case RaidLevel::Raid0:  return "raid0";
        case RaidLevel::Raid1:  return "raid1";
        case RaidLevel::Raid5:  return "raid5";
        case RaidLevel::Raid6:  return "raid6";
        case RaidLevel::Raid10: return "raid10";
        default:                return "unknown";
    }
}

RaidLevel raidLevelFromString(const std::string& s) {
    std::string v = toLower(trim(s));
    if (v == "linear" || v == "-1") return RaidLevel::Linear;
    if (v == "0" || v == "raid0")   return RaidLevel::Raid0;
    if (v == "1" || v == "raid1")   return RaidLevel::Raid1;
    if (v == "5" || v == "raid5")   return RaidLevel::Raid5;
    if (v == "6" || v == "raid6")   return RaidLevel::Raid6;
    if (v == "10" || v == "raid10") return RaidLevel::Raid10;
    return RaidLevel::Unknown;
}

namespace {

RaidLevel levelFromMd(int level) {
    switch (level) {
        case -1: case -4: return RaidLevel::Linear;
        case 0:  return RaidLevel::Raid0;
        case 1:  return RaidLevel::Raid1;
        case 4:  case 5: return RaidLevel::Raid5;
        case 6:  return RaidLevel::Raid6;
        case 10: return RaidLevel::Raid10;
        default: return RaidLevel::Unknown;
    }
}

const char* layoutName(u32 layout) {
    switch (layout & 0xFF) {
        case 0: return "left-asymmetric";
        case 1: return "right-asymmetric";
        case 2: return "left-symmetric";
        case 3: return "right-symmetric";
        default: return "left-symmetric";
    }
}

u32 layoutCode(const std::string& name) {
    if (name == "left-asymmetric")  return 0;
    if (name == "right-asymmetric") return 1;
    if (name == "right-symmetric")  return 3;
    return 2;   // left-symmetric — the md default
}

}  // namespace

// ---------------------------------------------------------------------------
bool probeMdSuperblock(const std::string& path, RaidMember& member, RaidLayout& layout,
                       std::string* err) {
    DiskReader d(path);
    if (!d.open(err)) return false;
    const i64 size = d.deviceSize();
    if (size < 1 << 20) { if (err) *err = "member too small"; return false; }

    // Superblock 1.x can live at 4 KiB (1.2), at 0 (1.1) or near the end (1.0).
    i64 candidates[3];
    candidates[0] = 4096;
    candidates[1] = 0;
    candidates[2] = ((size - 8LL * 1024) & ~(i64)0xFFF);

    for (int i = 0; i < 3; i++) {
        i64 off = candidates[i];
        if (off < 0 || off + 512 > size) continue;
        auto raw = d.readBlock((u64)off, 512);
        Bytes b(raw);
        if (raw.size() < 512 || b.le32(0) != 0xA92B4EFCu) continue;
        if (b.le32(4) != 1) continue;                       // major version 1

        layout.level        = levelFromMd((int)(i32)b.le32(72));
        layout.chunk_size   = (i64)b.le32(88) * 512;
        layout.members      = (int)b.le32(92);
        layout.parity_layout = layoutName(b.le32(76));
        // RAID10 packs near/far copies and offset-ness into the layout field;
        // the near count (how many adjacent members hold each chunk) is the
        // low byte and is what the assembler needs.
        if (layout.level == RaidLevel::Raid10) {
            int near = (int)(b.le32(76) & 0xFF);
            if (near > 0 && near <= 27) layout.copies = near;
        }
        layout.detected_from = "mdraid-superblock";
        if (layout.chunk_size <= 0) layout.chunk_size = 65536;

        member.path        = path;
        member.data_offset = (i64)b.le64(128) * 512;
        member.size        = (i64)b.le64(136) * 512;
        if (member.size <= 0) member.size = size - member.data_offset;
        member.present     = true;
        member.uuid        = toHex(raw.data() + 16, 16);

        u32 devNumber = b.le32(160);
        // dev_roles[] starts at byte 256; the entry for this device gives its
        // position in the array (0xFFFE = spare, 0xFFFF = faulty).
        auto roles = d.readBlock((u64)off + 256, (i64)(layout.members + 8) * 2);
        Bytes rb(roles);
        u16 role = rb.le16((size_t)devNumber * 2);
        member.role = (role < 0xFFFE) ? (int)role : -1;

        // Array name is handy for the UI.
        std::string name = b.trimmed(32, 32);
        if (!name.empty()) layout.notes.push_back("array name: " + name);
        return true;
    }

    // Superblock 0.90 sits in the last 64 KiB-aligned block.
    i64 off090 = ((size / 65536) - 1) * 65536;
    if (off090 > 0 && off090 + 4096 <= size) {
        auto raw = d.readBlock((u64)off090, 4096);
        Bytes b(raw);
        if (raw.size() >= 4096 && b.le32(0) == 0xA92B4EFCu && b.le32(4) == 0) {
            layout.level        = levelFromMd((int)(i32)b.le32(28));
            layout.members      = (int)b.le32(40);
            // Layout is the personality word (md_p.h word 64); chunk_size there
            // is stored in bytes, unlike the 512-byte units of superblock 1.x.
            layout.parity_layout = layoutName(b.le32(256));
            layout.chunk_size   = (i64)b.le32(260);
            layout.detected_from = "mdraid-superblock-0.90";
            if (layout.chunk_size <= 0) layout.chunk_size = 65536;
            member.path = path;
            member.data_offset = 0;
            // MD_NEW_SIZE_SECTORS: the superblock sits in the last 64 KiB
            // aligned block, which is exactly the usable size of the member.
            member.size = off090;
            member.present = true;
            // this_disk.raid_disk lives in the per-disk area at word 992.
            member.role = (int)b.le32(3980);
            char u[64];
            snprintf(u, sizeof(u), "%08x:%08x:%08x:%08x",
                     b.le32(20), b.le32(52), b.le32(56), b.le32(60));
            member.uuid = u;
            return true;
        }
    }

    if (err) *err = "no Linux md superblock found on " + path;
    return false;
}

// ---------------------------------------------------------------------------
RaidReader::RaidReader(const RaidLayout& layout) : layout_(layout) {}
RaidReader::~RaidReader() = default;

bool RaidReader::open(std::string* err) {
    readers_.clear();
    const int n = (int)layout_.disks.size();
    if (n == 0) { if (err) *err = "no RAID members supplied"; return false; }

    const i64 C = layout_.chunk_size > 0 ? layout_.chunk_size : 65536;
    if (C <= 0 || C > 1LL * 1024 * 1024 * 1024) {
        if (err) *err = "invalid RAID chunk size";
        return false;
    }
    if (layout_.level == RaidLevel::Raid0 && n < 2) {
        if (err) *err = "RAID 0 requires at least two members";
        return false;
    }
    if (layout_.level == RaidLevel::Raid5 && n < 2) {
        if (err) *err = "RAID 5 requires at least two members";
        return false;
    }
    if (layout_.level == RaidLevel::Raid6 && n < 3) {
        if (err) *err = "RAID 6 requires at least three members";
        return false;
    }
    if (layout_.level == RaidLevel::Raid10 &&
        (layout_.copies < 1 || layout_.copies > n || n % layout_.copies != 0)) {
        if (err) *err = "invalid RAID 10 mirror count";
        return false;
    }
    if (layout_.data_size < 0) {
        if (err) *err = "negative RAID data size";
        return false;
    }

    i64 smallest = 0;
    int present = 0;
    std::vector<i64> usable((size_t)n, 0);
    for (int i = 0; i < n; i++) {
        const auto& m = layout_.disks[(size_t)i];
        if (!m.present || m.path.empty()) {
            readers_.push_back(nullptr);
            continue;
        }
        auto r = std::make_unique<DiskReader>(m.path);
        std::string e;
        if (!r->open(&e)) {
            readers_.push_back(nullptr);
            layout_.notes.push_back("member " + m.path + " could not be opened: " + e);
            continue;
        }
        const i64 deviceSize = r->deviceSize();
        if (m.data_offset < 0 || m.data_offset > deviceSize) {
            if (err) *err = "member data offset is outside the device";
            return false;
        }
        const i64 available = deviceSize - m.data_offset;
        const i64 avail = m.size > 0 ? std::min(m.size, available) : available;
        if (avail <= 0) {
            if (err) *err = "RAID member has no usable data";
            return false;
        }
        r->setWindow((u64)m.data_offset, avail);
        layout_.disks[(size_t)i].size = avail;
        usable[(size_t)i] = avail;
        if (smallest == 0 || avail < smallest) smallest = avail;
        readers_.push_back(std::move(r));
        present++;
    }
    if (present == 0) { if (err) *err = "none of the RAID members could be opened"; return false; }
    if (smallest <= 0) { if (err) *err = "RAID members report zero usable size"; return false; }
    if ((layout_.level == RaidLevel::Raid5 && present < n - 1) ||
        (layout_.level == RaidLevel::Raid6 && present < n - 2)) {
        if (err) *err = "too many RAID members are unavailable";
        return false;
    }

    auto checkedProduct = [](i64 a, i64 b, i64& out) {
        if (a < 0 || b < 0 || (b != 0 && a > INT64_MAX / b)) return false;
        out = a * b;
        return true;
    };
    switch (layout_.level) {
        case RaidLevel::Raid0:
            if (!checkedProduct(smallest, n, size_)) { if (err) *err = "RAID size overflows"; return false; }
            break;
        case RaidLevel::Raid1: size_ = smallest; break;
        case RaidLevel::Raid5:
            if (!checkedProduct(smallest, n - 1, size_)) { if (err) *err = "RAID size overflows"; return false; }
            break;
        case RaidLevel::Raid6:
            if (!checkedProduct(smallest, n - 2, size_)) { if (err) *err = "RAID size overflows"; return false; }
            break;
        case RaidLevel::Raid10:
            if (!checkedProduct(smallest, n, size_)) { if (err) *err = "RAID size overflows"; return false; }
            size_ /= layout_.copies;
            break;
        case RaidLevel::Linear: {
            size_ = 0;
            for (i64 memberSize : usable) {
                if (memberSize > INT64_MAX - size_) { if (err) *err = "RAID size overflows"; return false; }
                size_ += memberSize;
            }
            break;
        }
        default: if (err) *err = "unsupported RAID level"; return false;
    }
    if (layout_.data_size > 0) size_ = std::min(size_, layout_.data_size);
    if (size_ <= 0) { if (err) *err = "computed array size is zero"; return false; }
    return true;
}

i64 RaidReader::readStripeUnit(int diskIdx, i64 unitOffset, u8* buf, i64 count) {
    if (diskIdx < 0 || diskIdx >= (int)readers_.size() || unitOffset < 0) return 0;
    DiskReader* r = readers_[(size_t)diskIdx].get();
    if (!r) return 0;
    return r->read((u64)unitOffset, buf, count);
}

i64 RaidReader::read(u64 offset, u8* buf, i64 count) {
    if (count <= 0 || offset >= (u64)size_) return 0;
    const u64 remaining = (u64)size_ - offset;
    if ((u64)count > remaining) count = (i64)remaining;
    const int n = (int)readers_.size();
    const i64 C = layout_.chunk_size > 0 ? layout_.chunk_size : 65536;
    i64 done = 0;

    while (done < count) {
        const i64 logical = (i64)offset + done;
        i64 got = 0;

        switch (layout_.level) {
            case RaidLevel::Linear: {
                i64 pos = logical;
                int idx = 0;
                for (; idx < n; idx++) {
                    i64 sz = layout_.disks[(size_t)idx].size;
                    if (pos < sz) break;
                    pos -= sz;
                }
                if (idx >= n) return done;
                i64 want = std::min(count - done, layout_.disks[(size_t)idx].size - pos);
                got = readStripeUnit(idx, pos, buf + done, want);
                break;
            }
            case RaidLevel::Raid1: {
                i64 want = count - done;
                for (int d = 0; d < n && got <= 0; d++) got = readStripeUnit(d, logical, buf + done, want);
                if (got <= 0) { std::memset(buf + done, 0, (size_t)want); got = want; degraded_++; }
                break;
            }
            case RaidLevel::Raid0: {
                i64 chunkIdx = logical / C;
                i64 inChunk  = logical % C;
                int disk = (int)(chunkIdx % n);
                i64 stripe = chunkIdx / n;
                i64 want = std::min(count - done, C - inChunk);
                got = readStripeUnit(disk, stripe * C + inChunk, buf + done, want);
                if (got <= 0) { std::memset(buf + done, 0, (size_t)want); got = want; degraded_++; }
                break;
            }
            case RaidLevel::Raid10: {
                // Near layout: each chunk exists on `copies` adjacent members.
                // The count comes from the superblock layout field when the
                // array was detected; far/offset geometries are not supported.
                const int copies = std::max(1, layout_.copies);
                i64 chunkIdx = logical / C;
                i64 inChunk  = logical % C;
                int groups = n / copies;
                if (groups <= 0) return done;
                int firstDev = (int)((chunkIdx % groups) * copies);
                i64 stripe = chunkIdx / groups;
                i64 want = std::min(count - done, C - inChunk);
                for (int c = 0; c < copies && got <= 0; c++)
                    got = readStripeUnit((firstDev + c) % n, stripe * C + inChunk, buf + done, want);
                if (got <= 0) { std::memset(buf + done, 0, (size_t)want); got = want; degraded_++; }
                break;
            }
            case RaidLevel::Raid5:
            case RaidLevel::Raid6: {
                const int parityCount = (layout_.level == RaidLevel::Raid6) ? 2 : 1;
                const int dataDisks = n - parityCount;
                if (dataDisks <= 0) return done;
                i64 chunkIdx = logical / C;
                i64 inChunk  = logical % C;
                i64 stripe = chunkIdx / dataDisks;
                int idxInStripe = (int)(chunkIdx % dataDisks);
                u32 lay = layoutCode(layout_.parity_layout);

                int pd;
                if (lay == 1 || lay == 3) pd = (int)(stripe % n);              // right-*
                else                      pd = (int)(n - 1 - (stripe % n));    // left-*

                int disk;
                if (lay == 2 || lay == 3) {                                    // symmetric
                    // Data starts after P and Q; the kernel's raid5.c maps
                    // dd = (pd + 1 + dd) for RAID5 but (pd + 2 + dd) for RAID6
                    // (Q sits at pd + 1), see ALGORITHM_*_SYMMETRIC.
                    disk = (pd + parityCount + idxInStripe) % n;
                } else {                                                       // asymmetric
                    disk = idxInStripe;
                    if (disk >= pd) disk++;
                    if (layout_.level == RaidLevel::Raid6) {
                        int qd = (pd + 1) % n;
                        if (disk >= qd) disk++;
                        disk %= n;
                    }
                }

                i64 want = std::min(count - done, C - inChunk);
                got = readStripeUnit(disk, stripe * C + inChunk, buf + done, want);
                if (got <= 0) {
                    // Rebuild the missing chunk from parity: XOR every other
                    // member in the stripe. Works for a single failure.
                    std::vector<u8> acc((size_t)want, 0);
                    std::vector<u8> tmp((size_t)want);
                    bool ok = true;
                    for (int d = 0; d < n; d++) {
                        if (d == disk) continue;
                        if (layout_.level == RaidLevel::Raid6 && d == (pd + 1) % n) continue;
                        i64 r = readStripeUnit(d, stripe * C + inChunk, tmp.data(), want);
                        if (r != want) { ok = false; break; }
                        for (i64 k = 0; k < want; k++) acc[(size_t)k] ^= tmp[(size_t)k];
                    }
                    if (ok) {
                        std::memcpy(buf + done, acc.data(), (size_t)want);
                        degraded_++;
                    } else {
                        std::memset(buf + done, 0, (size_t)want);
                    }
                    got = want;
                }
                break;
            }
            default:
                return done;
        }

        if (got <= 0) break;
        done += got;
    }
    return done;
}

// ---------------------------------------------------------------------------
namespace {

// Follows one directory entry from the root directory through to that
// subdirectory's own data block, checking its "." and ".." entries. This second
// chain lands far away from the first, which is what separates the true chunk
// size from the aliases that map the start of the array identically.
bool verifySubdirectory(RaidReader& rr, const Bytes& rootDir, i64 bs, u64 itbl,
                        u16 isize, u16 descSize, u32 fdb, u32 incompat) {
    (void)descSize; (void)fdb; (void)incompat;
    size_t p = 0;
    int examined = 0;
    while (p + 8 < rootDir.size() && examined < 32) {
        u32 ino = rootDir.le32(p);
        u16 recLen = rootDir.le16(p + 4);
        u8  nameLen = rootDir.u8at(p + 6);
        u8  fileType = rootDir.u8at(p + 7);
        if (recLen < 8 || (recLen & 3)) break;
        std::string name = rootDir.str(p + 8, nameLen);
        p += recLen;
        if (ino <= 11 || name == "." || name == "..") continue;
        if (fileType != 2) continue;                     // EXT4_FT_DIR
        examined++;

        // The inode table is contiguous within a block group, so inode N sits
        // at (N-1) * isize from its start.
        i64 inodeOff = (i64)(itbl * (u64)bs) + (i64)(ino - 1) * isize;
        std::vector<u8> in((size_t)isize);
        if (rr.read((u64)inodeOff, in.data(), isize) != isize) continue;
        Bytes ib(in.data(), in.size());
        if ((ib.le16(0) & 0xF000) != 0x4000) continue;
        u64 blk = 0;
        if (ib.le16(0x28) == 0xF30A && ib.le16(0x2A) >= 1 && ib.le16(0x2E) == 0)
            blk = ib.le32(0x28 + 12 + 8) | ((u64)ib.le16(0x28 + 12 + 6) << 32);
        else
            blk = ib.le32(0x28);
        if (!blk) continue;

        std::vector<u8> sub(64);
        if (rr.read(blk * (u64)bs, sub.data(), 64) != 64) continue;
        Bytes sb2(sub.data(), sub.size());
        u16 r0 = sb2.le16(4);
        bool dot = sb2.le32(0) == ino && sb2.u8at(6) == 1 && sb2.u8at(8) == '.';
        bool dotdot = r0 >= 12 && r0 < 64 && sb2.le32(r0) == 2 &&
                      sb2.u8at(r0 + 6) == 2 && sb2.u8at(r0 + 8) == '.' &&
                      sb2.u8at(r0 + 9) == '.';
        if (dot && dotdot) return true;
    }
    // A filesystem with no subdirectories cannot be checked this way; accept
    // the single chain rather than rejecting a valid geometry outright.
    return examined == 0;
}

}  // namespace

namespace {

// Assembles a prefix of the array and measures how much *structurally valid*
// file content it yields. A wrong chunk size splices data from the wrong
// member, which breaks the internal chains that formats like PNG, ZIP and MP4
// carry, so the correct geometry recovers far more intact files. This is what
// separates geometries that the metadata alone cannot tell apart.
i64 scoreByContent(const RaidLayout& layout, Progress& prog) {
    RaidReader rr(layout);
    std::string err;
    if (!rr.open(&err)) return -1;

    const i64 prefix = std::min<i64>(rr.size(), 24LL * 1024 * 1024);
    if (prefix <= 0) return -1;

    char tmpl[] = "/tmp/ghost-raid-probe-XXXXXX";
    int fd = ::mkstemp(tmpl);
    if (fd < 0) return -1;
    std::string tmpPath = tmpl;

    {
        const i64 kChunk = 4LL * 1024 * 1024;
        std::vector<u8> buf((size_t)kChunk);
        i64 done = 0;
        while (done < prefix) {
            i64 want = std::min(kChunk, prefix - done);
            i64 got = rr.read((u64)done, buf.data(), want);
            if (got <= 0) break;
            if (::write(fd, buf.data(), (size_t)got) != got) break;
            done += got;
        }
    }
    ::close(fd);

    i64 score = 0;
    {
        std::string e2;
        auto probe = openTarget(tmpPath, 0, 0, &e2);
        if (probe) {
            CarveOptions co;
            co.write_files = false;
            co.compute_hashes = false;
            co.validate = true;
            co.dedup = true;
            co.max_files = 400;
            co.threads = 1;
            Progress quiet;
            CarveResult cr = carveDevice(*probe, co, quiet);
            for (const auto& f : cr.files)
                if (f.whole_file && !f.truncated) score += f.size;
        }
    }
    ::unlink(tmpPath.c_str());
    (void)prog;
    return score;
}

}  // namespace

RaidLayout detectRaidLayout(const std::vector<std::string>& memberPaths, Progress& prog) {
    RaidLayout layout;
    layout.members = (int)memberPaths.size();

    // ---- superblocks first -----------------------------------------------
    prog.setPhase("reading RAID superblocks");
    std::vector<RaidMember> members;
    int withSuper = 0;
    for (const auto& p : memberPaths) {
        RaidMember m;
        m.path = p;
        RaidLayout probe;
        std::string err;
        if (probeMdSuperblock(p, m, probe, &err)) {
            withSuper++;
            if (layout.level == RaidLevel::Unknown) {
                layout.level = probe.level;
                layout.chunk_size = probe.chunk_size;
                layout.parity_layout = probe.parity_layout;
                layout.copies = probe.copies;
                layout.detected_from = probe.detected_from;
                if (probe.members > 0) layout.members = probe.members;
                for (const auto& n : probe.notes) layout.notes.push_back(n);
            }
        } else {
            m.present = fileExists(p);
            layout.notes.push_back(err);
        }
        members.push_back(std::move(m));
    }

    if (withSuper == (int)memberPaths.size() && layout.level != RaidLevel::Unknown) {
        // Order members by the role recorded in their superblocks.
        std::sort(members.begin(), members.end(),
                  [](const RaidMember& a, const RaidMember& b) {
                      if (a.role != b.role) return a.role < b.role;
                      return a.path < b.path;
                  });
        layout.disks = std::move(members);
        layout.confidence = 1.0;
        return layout;
    }
    if (withSuper > 0) {
        layout.notes.push_back(std::to_string(withSuper) + " of " +
                               std::to_string(memberPaths.size()) +
                               " members had a readable superblock");
    }

    // ---- brute force ------------------------------------------------------
    prog.setPhase("brute-forcing RAID parameters");
    const int n = (int)memberPaths.size();
    if (n < 2) {
        layout.notes.push_back("at least two members are needed to detect a layout");
        layout.disks = std::move(members);
        return layout;
    }
    if (n > 6) {
        layout.notes.push_back(
            "member order cannot be brute-forced for more than six disks without superblocks — "
            "supply the order, chunk size and level manually");
        layout.disks = std::move(members);
        return layout;
    }

    static const i64 kChunks[] = {4096, 8192, 16384, 32768, 65536, 131072, 262144, 524288, 1048576};
    static const RaidLevel kLevels[] = {RaidLevel::Raid5, RaidLevel::Raid0, RaidLevel::Raid6,
                                        RaidLevel::Raid10};
    static const char* kLayouts[] = {"left-symmetric", "left-asymmetric",
                                     "right-symmetric", "right-asymmetric"};

    std::vector<int> order(n);
    std::iota(order.begin(), order.end(), 0);
    std::vector<int>& order_ = order;
    double bestScore = 0;

    RaidLayout best;
    std::vector<RaidLayout> candidates;

    do {
        if (prog.cancelled()) break;
        for (RaidLevel level : kLevels) {
            if (level == RaidLevel::Raid5 && n < 3) continue;
            if (level == RaidLevel::Raid6 && n < 4) continue;
            if (level == RaidLevel::Raid10 && (n % 2)) continue;
            for (i64 chunk : kChunks) {
                for (const char* lay : kLayouts) {
                    if (level != RaidLevel::Raid5 && level != RaidLevel::Raid6 &&
                        std::string(lay) != "left-symmetric")
                        continue;

                    RaidLayout trial;
                    trial.level = level;
                    trial.chunk_size = chunk;
                    trial.members = n;
                    trial.parity_layout = lay;
                    for (int idx : order) {
                        RaidMember m;
                        m.path = memberPaths[(size_t)idx];
                        m.data_offset = members[(size_t)idx].data_offset;
                        m.size = members[(size_t)idx].size;
                        m.present = true;
                        trial.disks.push_back(m);
                    }

                    RaidReader rr(trial);
                    std::string err;
                    if (!rr.open(&err)) continue;
                    // Assemble the first megabyte and see whether a filesystem
                    // or a partition table appears at offset 0.
                    std::vector<u8> head(1 << 20);
                    i64 got = rr.read(0, head.data(), (i64)head.size());
                    if (got < 4096) continue;
                    Bytes b(head.data(), (size_t)got);

                    double score = 0;
                    bool deepOk = false;      // metadata followed deep into the array
                    if (b.u8at(510) == 0x55 && b.u8at(511) == 0xAA) score += 0.5;
                    if (b.eq(512, "EFI PART", 8)) score += 1.0;
                    if (b.le16(1024 + 0x38) == 0xEF53) score += 1.0;
                    if (b.eq(3, "NTFS    ", 8)) score += 1.0;
                    if (b.eq(3, "EXFAT   ", 8)) score += 1.0;
                    if (b.eq(0, "XFSB", 4)) score += 1.0;
                    if (b.eq(0, "LABELONE", 8) || b.eq(512, "LABELONE", 8)) score += 0.8;

                    // A signature at offset 0 looks identical for every chunk
                    // size, because the first chunk always comes from member 0.
                    // Follow a pointer that reaches deep into the array instead:
                    // only the correct geometry puts the target where the
                    // metadata says it is.
                    if (b.le16(1024 + 0x38) == 0xEF53) {
                        u32 logBs  = b.le32(1024 + 0x18);
                        u32 bpg    = b.le32(1024 + 0x20);
                        u32 fdb    = b.le32(1024 + 0x14);
                        u16 isize  = b.le16(1024 + 0x58);
                        u32 incompat = b.le32(1024 + 0x60);
                        if (logBs <= 6 && isize >= 128) {
                            i64 bs = 1024LL << logBs;
                            u16 descSize = (incompat & 0x80) ? 64 : 32;
                            // Follow the group descriptor to the inode table,
                            // then the root inode to its first data block, and
                            // require the "." and ".." entries to be there
                            // pointing back at inode 2. Merely checking that
                            // root "looks like a directory" matches roughly one
                            // random block in a thousand, and across thousands
                            // of trial geometries that produced confident wrong
                            // answers; this chain does not happen by accident.
                            std::vector<u8> gd(descSize);
                            i64 gdOff = (i64)(fdb + 1) * bs;
                            if (rr.read((u64)gdOff, gd.data(), descSize) == descSize) {
                                Bytes gb(gd.data(), gd.size());
                                u64 itbl = gb.le32(0x08);
                                if (descSize >= 64) itbl |= ((u64)gb.le32(0x28)) << 32;
                                if (itbl > 0) {
                                    std::vector<u8> rootIn(isize);
                                    i64 rootOff = (i64)(itbl * (u64)bs) + (i64)isize;
                                    if (rr.read((u64)rootOff, rootIn.data(), isize) == isize) {
                                        Bytes rb(rootIn.data(), rootIn.size());
                                        if ((rb.le16(0) & 0xF000) == 0x4000 && rb.le16(0x1A) >= 2) {
                                            u64 firstBlock = 0;
                                            if (rb.le16(0x28) == 0xF30A && rb.le16(0x2A) >= 1 &&
                                                rb.le16(0x2E) == 0) {
                                                firstBlock = rb.le32(0x28 + 12 + 8) |
                                                             ((u64)rb.le16(0x28 + 12 + 6) << 32);
                                            } else {
                                                firstBlock = rb.le32(0x28);      // ext2 direct
                                            }
                                            if (firstBlock > 0) {
                                                std::vector<u8> dir((size_t)bs);
                                                if (rr.read(firstBlock * (u64)bs, dir.data(), bs) == bs) {
                                                    Bytes db(dir.data(), dir.size());
                                                    u16 rec0 = db.le16(4);
                                                    bool dot = db.le32(0) == 2 && db.u8at(6) == 1 &&
                                                               db.u8at(8) == '.';
                                                    bool dotdot = rec0 >= 12 && rec0 < 64 &&
                                                                  db.u8at(rec0 + 6) == 2 &&
                                                                  db.u8at(rec0 + 8) == '.' &&
                                                                  db.u8at(rec0 + 9) == '.';
                                                    // One chain is not enough: a wrong chunk size
                                                    // often maps the first few kilobytes
                                                    // identically to the right one, so several
                                                    // geometries pass a single probe. Walk on to
                                                    // a subdirectory and verify its own "." and
                                                    // ".." at a completely different offset.
                                                    if (dot && dotdot) {
                                                        deepOk = verifySubdirectory(rr, db, bs,
                                                                                    itbl, isize,
                                                                                    descSize, fdb,
                                                                                    incompat);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            // Larger volumes also carry a backup superblock.
                            if (bpg) {
                                i64 backup = (i64)bpg * bs + (bs == 1024 ? 1024 : 0);
                                std::vector<u8> probe(1024);
                                if (rr.read((u64)backup, probe.data(), 1024) == 1024) {
                                    Bytes pb(probe);
                                    if (pb.le16(0x38) == 0xEF53 && pb.le16(0x5A) == 1) deepOk = true;
                                }
                            }
                        }
                    } else if (b.eq(3, "NTFS    ", 8)) {
                        u16 bps = b.le16(0x0B);
                        u8 spcRaw = b.u8at(0x0D);
                        // Corrupt counts would shift by up to 127 on a u32.
                        u32 spc = (spcRaw > 0x80) ? (1u << std::min<unsigned>(31, 0x100u - spcRaw))
                                                  : spcRaw;
                        u64 mftLcn = b.le64(0x30);
                        if (bps && spc && mftLcn) {
                            std::vector<u8> probe(512);
                            if (rr.read(mftLcn * bps * spc, probe.data(), 512) == 512 &&
                                std::memcmp(probe.data(), "FILE", 4) == 0)
                                deepOk = true;
                        }
                    } else if (b.eq(0, "XFSB", 4)) {
                        u32 blocksize = b.be32(0x04);
                        u32 agblocks  = b.be32(0x54);
                        if (blocksize >= 512 && agblocks) {
                            std::vector<u8> probe(4);
                            // Every allocation group repeats the superblock.
                            if (rr.read((u64)agblocks * blocksize, probe.data(), 4) == 4 &&
                                std::memcmp(probe.data(), "XFSB", 4) == 0)
                                deepOk = true;
                        }
                    }
                    if (deepOk && ::getenv("GHOST_RAID_DEBUG")) {
                        std::string ord;
                        for (int idx : order_) ord += std::to_string(idx);
                        fprintf(stderr, "  [raid] passes: level=%s chunk=%lld layout=%s order=%s\n",
                                raidLevelName(level), (long long)chunk, lay, ord.c_str());
                    }
                    // Several geometries can satisfy the metadata chains: a
                    // wrong chunk size often maps the start of the array
                    // identically to the right one. Collect every candidate and
                    // settle it afterwards on reconstructed file content.
                    if (deepOk) {
                        if (candidates.size() < 64) candidates.push_back(trial);

                    } else if (score > bestScore) {
                        bestScore = score;
                        best = trial;
                        best.detected_from = "heuristic";
                        best.confidence = std::min(0.6, score / 2.5);
                    }
                }
            }
        }
    } while (std::next_permutation(order.begin(), order.end()));

    if (!candidates.empty()) {
        prog.setPhase("ranking candidate geometries by reconstructed content");
        // When the content evidence cannot separate two geometries, fall back
        // on what arrays are actually built like: mdadm's default parity layout
        // is left-symmetric, and the order the user listed the members in is
        // usually the real order. Sorting by those priors first means an exact
        // tie keeps the more plausible candidate.
        std::vector<std::string> memberOrder;
        for (const auto& m : memberPaths) memberOrder.push_back(m);
        std::stable_sort(candidates.begin(), candidates.end(),
            [&](const RaidLayout& a, const RaidLayout& b) {
                auto identity = [&](const RaidLayout& l) {
                    if (l.disks.size() != memberOrder.size()) return false;
                    for (size_t i = 0; i < l.disks.size(); i++)
                        if (l.disks[i].path != memberOrder[i]) return false;
                    return true;
                };
                bool ai = identity(a), bi = identity(b);
                if (ai != bi) return ai;
                bool ad = a.parity_layout == "left-symmetric";
                bool bd = b.parity_layout == "left-symmetric";
                if (ad != bd) return ad;
                return false;
            });

        RaidLayout chosen = candidates.front();
        i64 bestContent = -1, runnerUp = -1;
        if (candidates.size() == 1) {
            chosen.confidence = 1.0;
        } else {
            for (size_t i = 0; i < candidates.size() && !prog.cancelled(); i++) {
                i64 sc = scoreByContent(candidates[i], prog);
                if (::getenv("GHOST_RAID_DEBUG"))
                    fprintf(stderr, "  [raid] content score %lld for chunk=%lld layout=%s\n",
                            (long long)sc, (long long)candidates[i].chunk_size,
                            candidates[i].parity_layout.c_str());
                if (sc > bestContent) { runnerUp = bestContent; bestContent = sc; chosen = candidates[i]; }
                else if (sc > runnerUp) { runnerUp = sc; }
            }
            // Below this much end-to-end verified content the ranking is noise
            // rather than evidence, so the structural priors decide instead.
            const i64 kMeaningful = 256LL * 1024;
            if (bestContent < kMeaningful) {
                chosen = candidates.front();
                chosen.confidence = 0.35;
                chosen.ambiguous = true;
                for (const auto& c : candidates) {
                    if (c.chunk_size == chosen.chunk_size &&
                        c.parity_layout == chosen.parity_layout) continue;
                    chosen.alternatives.push_back(std::string(raidLevelName(c.level)) + ", " +
                                                  humanSize(c.chunk_size) + " chunks, " +
                                                  c.parity_layout);
                    if (chosen.alternatives.size() >= 8) break;
                }
                chosen.notes.push_back(
                    std::to_string(candidates.size()) + " different geometries fit this array's "
                    "metadata equally well, and it holds too little verifiable file content to "
                    "tell them apart. A chunk size of N and N/2 map the start of an array "
                    "identically, so this is not something more searching can resolve. The most "
                    "conventional layout was assumed (left-symmetric parity, members in the "
                    "order given) — CHECK the assembled image before trusting any file from it.");
            } else if (runnerUp <= 0 || bestContent >= runnerUp * 2) {
                chosen.confidence = 1.0;
            } else {
                chosen.confidence = 0.7;
                chosen.notes.push_back(
                    "another geometry reconstructed almost as much valid content; verify the "
                    "assembled image before trusting it");
            }
        }
        chosen.detected_from = "heuristic";
        for (const auto& note : layout.notes) chosen.notes.push_back(note);
        if (candidates.size() > 1)
            chosen.notes.push_back("chose between " + std::to_string(candidates.size()) +
                                   " candidate geometries using reconstructed file content");
        chosen.notes.push_back("parameters recovered by brute force — verify the assembled array "
                               "before trusting recovered files");
        return chosen;
    }
    if (bestScore > 0) {
        for (const auto& note : layout.notes) best.notes.push_back(note);
        best.notes.push_back("no geometry fully verified; this is the closest match and may be "
                             "wrong — verify the assembled array before trusting it");
        return best;
    }

    layout.disks = std::move(members);
    layout.notes.push_back("no chunk size / member order produced a recognisable filesystem; "
                           "the array may use an unsupported layout or a missing member");
    return layout;
}

// ---------------------------------------------------------------------------
RaidBuildResult assembleRaid(const RaidLayout& layout, const std::string& outPath, i64 maxBytes,
                             Progress& prog) {
    RaidBuildResult res;
    res.layout = layout;
    res.output_path = outPath;

    RaidReader rr(layout);
    std::string err;
    if (!rr.open(&err)) {
        res.error = err;
        return res;
    }
    // Never write the reconstruction over a member or onto the same disk a
    // member lives on — that would destroy the only copy of the array.
    for (const auto& m : layout.disks)
        if (writesBackOntoSource(outPath, m.path)) {
            res.error = "refusing to assemble over " + m.path +
                        ", a member of this array. Write the reconstruction to a different disk.";
            return res;
        }
    if (!makeDirs(dirName(outPath))) {
        res.error = "cannot create output directory for " + outPath;
        return res;
    }
    FILE* fp = fopen(outPath.c_str(), "wb");
    if (!fp) {
        res.error = "cannot open " + outPath + " for writing";
        return res;
    }

    i64 total = rr.size();
    if (maxBytes > 0) total = std::min(total, maxBytes);
    prog.setPhase("assembling RAID array");
    prog.set(0, total);

    const i64 kChunk = 8LL * 1024 * 1024;
    std::vector<u8> buf((size_t)kChunk);
    i64 written = 0;
    while (written < total && !prog.cancelled()) {
        i64 want = std::min(kChunk, total - written);
        i64 got = rr.read((u64)written, buf.data(), want);
        if (got <= 0) break;
        if (fwrite(buf.data(), 1, (size_t)got, fp) != (size_t)got) {
            res.error = "write failed (out of space?)";
            break;
        }
        written += got;
        prog.set(written, total);
    }
    fclose(fp);
    adoptOwnership(outPath);

    res.bytes_written = written;
    res.stripes_reconstructed = rr.degradedStripes();
    res.ok = written > 0 && res.error.empty();
    if (!res.ok && res.error.empty()) res.error = "no data could be assembled";
    return res;
}

}  // namespace ghost
