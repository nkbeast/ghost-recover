// GHOST//RECOVER — ext2 / ext3 / ext4 driver.
//
// The previous version read the block-group-0 descriptor, assumed a 1024-byte
// block size, walked inodes 12..200 and read only the first extent of the first
// leaf. It could not see a file past the first block group, never followed an
// indirect block, and reconstructed no paths.
//
// This implementation walks every block group, decodes full extent trees and
// ext2/3 indirect chains, reconstructs paths from the directory tree, and adds
// the three techniques that actually recover deleted data on ext4:
//   * jbd2 journal mining  — old copies of inode-table blocks still hold the
//     extent tree that unlink() cleared from the live inode
//   * directory slack      — unlinked names survive inside the previous entry's
//     rec_len padding
//   * orphan inode list    — inodes that were open at crash time
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>

namespace ghost {
namespace ext {

namespace {

constexpr u32 kMagic = 0xEF53;

// s_feature_incompat
constexpr u32 kIncompatFiletype  = 0x0002;
constexpr u32 kIncompat64Bit     = 0x0080;
constexpr u32 kIncompatExtents   = 0x0040;
constexpr u32 kIncompatMetaBg    = 0x0010;
// s_feature_compat
constexpr u32 kCompatHasJournal  = 0x0004;

// i_flags
constexpr u32 kFlagExtents    = 0x00080000;
constexpr u32 kFlagInlineData = 0x10000000;
constexpr u32 kFlagEncrypted  = 0x00000800;

constexpr u16 kExtentMagic = 0xF30A;

struct Inode {
    u16 mode = 0;
    u32 uid = 0, gid = 0;
    u64 size = 0;
    u32 atime = 0, ctime = 0, mtime = 0, dtime = 0, crtime = 0;
    u16 links = 0;
    u64 blocks512 = 0;
    u32 flags = 0;
    u8  iblock[60] = {0};
    bool valid = false;
};

FileKind kindFromMode(u16 mode) {
    switch (mode & 0xF000) {
        case 0x8000: return FileKind::Regular;
        case 0x4000: return FileKind::Directory;
        case 0xA000: return FileKind::Symlink;
        case 0x6000: case 0x2000: return FileKind::Device;
        case 0x1000: return FileKind::Fifo;
        case 0xC000: return FileKind::Socket;
        default:     return FileKind::Other;
    }
}

// -------------------------------------------------------------------------
struct ExtFs {
    DiskReader* d = nullptr;
    i64 volume = 0;

    u32 block_size = 1024;
    u64 blocks_count = 0;
    u32 inodes_count = 0;
    u32 inodes_per_group = 0;
    u32 blocks_per_group = 0;
    u16 inode_size = 128;
    u16 desc_size = 32;
    u32 first_data_block = 1;
    u32 first_ino = 11;
    u32 feature_compat = 0, feature_incompat = 0, feature_ro_compat = 0;
    u32 journal_inum = 0;
    u32 last_orphan = 0;
    u32 groups = 0;
    std::string label, uuid;
    std::string flavour = "ext4";
    u64 free_blocks = 0, free_inodes = 0;
    u64 sb_offset = 1024;

    std::vector<u64> inode_table;   // absolute byte offset of each group's inode table
    std::vector<u64> block_bitmap;

    bool has64()      const { return feature_incompat & kIncompat64Bit; }
    bool hasExtents() const { return feature_incompat & kIncompatExtents; }
    bool hasFiletype() const { return feature_incompat & kIncompatFiletype; }
    bool hasMetaBg()  const { return feature_incompat & kIncompatMetaBg; }

    u64 blockOffset(u64 blk) const { return blk * (u64)block_size; }

    // ---- superblock ------------------------------------------------------
    bool loadSuper(u64 offset, std::string* err) {
        auto raw = d->readBlock(offset, 1024);
        Bytes s(raw);
        if (raw.size() < 1024 || s.le16(0x38) != kMagic) {
            if (err) *err = "ext superblock magic not found";
            return false;
        }
        u32 log_bs = s.le32(0x18);
        if (log_bs > 6) { if (err) *err = "invalid s_log_block_size"; return false; }
        block_size = 1024u << log_bs;

        inodes_count     = s.le32(0x00);
        blocks_count     = s.le32(0x04);
        free_blocks      = s.le32(0x0C);
        free_inodes      = s.le32(0x10);
        first_data_block = s.le32(0x14);
        blocks_per_group = s.le32(0x20);
        inodes_per_group = s.le32(0x28);
        first_ino        = s.le32(0x54);
        inode_size       = s.le16(0x58);
        feature_compat    = s.le32(0x5C);
        feature_incompat  = s.le32(0x60);
        feature_ro_compat = s.le32(0x64);
        journal_inum     = s.le32(0xE0);
        last_orphan      = s.le32(0xE8);
        desc_size        = s.le16(0xFE);
        label            = s.trimmed(0x78, 16);

        if (raw.size() >= 0x68 + 16) {
            char buf[40];
            const u8* g = raw.data() + 0x68;
            snprintf(buf, sizeof(buf),
                     "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     g[0],g[1],g[2],g[3],g[4],g[5],g[6],g[7],g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
            uuid = buf;
        }

        if (has64()) {
            blocks_count |= ((u64)s.le32(0x150)) << 32;
            free_blocks  |= ((u64)s.le32(0x158)) << 32;
            if (desc_size < 64) desc_size = 64;
        } else {
            desc_size = 32;
        }
        if (inode_size == 0) inode_size = 128;
        if (first_ino == 0) first_ino = 11;

        if (inode_size < 128 || inode_size > 4096 || (inode_size & (inode_size - 1)))
            { if (err) *err = "implausible s_inode_size"; return false; }
        if (inodes_per_group == 0 || blocks_per_group == 0)
            { if (err) *err = "zero group geometry"; return false; }
        if (inodes_per_group > 1u << 24 || blocks_per_group > 1u << 24)
            { if (err) *err = "implausible group geometry"; return false; }
        if (blocks_count == 0) { if (err) *err = "zero block count"; return false; }

        // Do the group arithmetic in 64 bits: with bigalloc-style geometry the
        // u32 products overflow and the group count wraps.
        u64 gByBlocks = 1;
        if (blocks_count > first_data_block)
            gByBlocks = (blocks_count - (u64)first_data_block + (u64)blocks_per_group - 1) /
                        (u64)blocks_per_group;
        u64 gByInodes = ((u64)inodes_count + inodes_per_group - 1) / (u64)inodes_per_group;
        if (gByBlocks > (1u << 22) || gByInodes > (1u << 22))
            { if (err) *err = "implausible group count"; return false; }
        groups = (u32)gByBlocks;
        u32 byInode = (u32)gByInodes;
        if (byInode && byInode < groups) groups = byInode;
        if (groups == 0) groups = 1;
        if (groups > 1u << 22) { if (err) *err = "implausible group count"; return false; }

        if (feature_incompat & kIncompatExtents) flavour = "ext4";
        else if (feature_compat & kCompatHasJournal) flavour = "ext3";
        else flavour = "ext2";
        if (has64()) flavour = "ext4";

        sb_offset = offset;
        return true;
    }

    // Primary superblock damaged? ext keeps backups at the start of groups
    // 1, 3, 5, 7, 9, 25, 27, 49, 81 ... (powers of 3, 5 and 7).
    std::vector<u64> backupSuperblockOffsets(u32 bs, u32 bpg) const {
        std::vector<u64> out;
        auto pushGroup = [&](u64 g) {
            u64 blk = (u64)g * bpg + (bs == 1024 ? 1 : 0);
            out.push_back(blk * bs);
        };
        pushGroup(1);
        for (u64 p = 3; p < 1u << 20; p *= 3) pushGroup(p);
        for (u64 p = 5; p < 1u << 20; p *= 5) pushGroup(p);
        for (u64 p = 7; p < 1u << 20; p *= 7) pushGroup(p);
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
        return out;
    }

    // ---- group descriptors ----------------------------------------------
    bool loadGroups() {
        inode_table.assign(groups, 0);
        block_bitmap.assign(groups, 0);
        u64 gdBlock = first_data_block + 1;
        // With META_BG the descriptor table is scattered; without it, it is one
        // contiguous run right after the superblock.
        u64 gdOffset = blockOffset(gdBlock);
        auto raw = d->readBlock(gdOffset, (i64)groups * desc_size);
        Bytes g(raw);
        if (raw.size() < (size_t)desc_size) return false;
        for (u32 i = 0; i < groups; i++) {
            size_t o = (size_t)i * desc_size;
            if (!g.has(o, 12)) break;
            u64 itbl = g.le32(o + 0x08);
            u64 bbmp = g.le32(o + 0x00);
            if (has64() && desc_size >= 64) {
                itbl |= ((u64)g.le32(o + 0x28)) << 32;
                bbmp |= ((u64)g.le32(o + 0x20)) << 32;
            }
            inode_table[i]  = itbl;
            block_bitmap[i] = bbmp;
        }
        // Sanity: at least group 0 must point somewhere inside the volume.
        if (inode_table.empty() || inode_table[0] == 0) return false;
        if (blockOffset(inode_table[0]) >= (u64)volume) return false;
        return true;
    }

    u64 inodeOffset(u64 ino) const {
        if (ino == 0) return 0;
        u64 idx = ino - 1;
        u32 grp = (u32)(idx / inodes_per_group);
        u64 within = idx % inodes_per_group;
        if (grp >= inode_table.size() || inode_table[grp] == 0) return 0;
        return blockOffset(inode_table[grp]) + within * inode_size;
    }

    bool parseInode(const Bytes& b, size_t off, Inode& out) const {
        if (!b.has(off, 128)) return false;
        out.mode  = b.le16(off + 0x00);
        out.uid   = b.le16(off + 0x02);
        out.size  = b.le32(off + 0x04);
        out.atime = b.le32(off + 0x08);
        out.ctime = b.le32(off + 0x0C);
        out.mtime = b.le32(off + 0x10);
        out.dtime = b.le32(off + 0x14);
        out.gid   = b.le16(off + 0x18);
        out.links = b.le16(off + 0x1A);
        out.blocks512 = b.le32(off + 0x1C);
        out.flags = b.le32(off + 0x20);
        std::memcpy(out.iblock, b.p + off + 0x28, 60);
        // Only regular files use the high half of i_size; for directories the
        // same field is i_dir_acl, so applying it there yields absurd sizes.
        if ((out.mode & 0xF000) == 0x8000)
            out.size |= ((u64)b.le32(off + 0x6C)) << 32;
        out.uid |= ((u32)b.le16(off + 0x78)) << 16;   // i_osd2.linux2.l_i_uid_high
        out.gid |= ((u32)b.le16(off + 0x7A)) << 16;
        if (inode_size > 128) {
            u16 extra = b.le16(off + 0x80);
            if (extra >= 0x1C) out.crtime = b.le32(off + 0x90);
        }
        out.valid = true;
        return true;
    }

    bool readInode(u64 ino, Inode& out) const {
        u64 off = inodeOffset(ino);
        if (off == 0 || off + inode_size > (u64)volume) return false;
        auto raw = d->readBlock(off, inode_size);
        if (raw.size() < 128) return false;
        return parseInode(Bytes(raw), 0, out);
    }

    // ---- extent tree -----------------------------------------------------
    void walkExtents(const Bytes& node, size_t base, std::vector<Extent>& out,
                     u64& logicalEnd, int depth, std::set<u64>& seen) const {
        if (depth > 6) return;
        if (node.le16(base + 0) != kExtentMagic) return;
        u16 entries = node.le16(base + 2);
        u16 nodeDepth = node.le16(base + 6);
        if (entries > 1024) return;

        for (u16 i = 0; i < entries; i++) {
            size_t e = base + 12 + (size_t)i * 12;
            if (!node.has(e, 12)) break;
            if (nodeDepth == 0) {
                u32 ee_block = node.le32(e + 0);
                u16 ee_len   = node.le16(e + 4);
                u64 start    = node.le32(e + 8) | ((u64)node.le16(e + 6) << 32);
                bool uninit  = ee_len > 32768;
                u32 len      = uninit ? (u32)(ee_len - 32768) : ee_len;
                if (len == 0 || start == 0) continue;
                if (start + len > blocks_count) continue;
                // Fill any hole between the previous extent and this one.
                if ((u64)ee_block > logicalEnd)
                    out.push_back(Extent(0, (i64)((ee_block - logicalEnd) * (u64)block_size), true));
                out.push_back(Extent((i64)blockOffset(start), (i64)len * block_size));
                logicalEnd = (u64)ee_block + len;
            } else {
                u64 leaf = node.le32(e + 4) | ((u64)node.le16(e + 8) << 32);
                if (leaf == 0 || leaf >= blocks_count) continue;
                if (!seen.insert(leaf).second) continue;      // cycle guard
                auto blk = d->readBlock(blockOffset(leaf), block_size);
                if (blk.size() < 12) continue;
                walkExtents(Bytes(blk), 0, out, logicalEnd, depth + 1, seen);
            }
        }
    }

    // ---- ext2/3 indirect chain -------------------------------------------
    void walkIndirect(u64 blk, int level, std::vector<Extent>& out, u64& count,
                      u64 maxBlocks, std::set<u64>& seen) const {
        if (blk == 0 || blk >= blocks_count || count >= maxBlocks) return;
        if (!seen.insert(blk).second) return;
        auto raw = d->readBlock(blockOffset(blk), block_size);
        Bytes b(raw);
        u32 perBlock = block_size / 4;
        for (u32 i = 0; i < perBlock && count < maxBlocks; i++) {
            u64 ptr = b.le32((size_t)i * 4);
            if (level == 1) {
                if (ptr == 0) { out.push_back(Extent(0, block_size, true)); count++; continue; }
                if (ptr >= blocks_count) continue;
                out.push_back(Extent((i64)blockOffset(ptr), block_size));
                count++;
            } else {
                walkIndirect(ptr, level - 1, out, count, maxBlocks, seen);
            }
        }
    }

    std::vector<Extent> dataExtents(const Inode& in) const {
        std::vector<Extent> raw;
        if (in.flags & kFlagInlineData) return raw;

        if ((in.flags & kFlagExtents) || (hasExtents() &&
             (in.iblock[0] | (in.iblock[1] << 8)) == kExtentMagic)) {
            Bytes ib(in.iblock, 60);
            u64 logicalEnd = 0;
            std::set<u64> seen;
            walkExtents(ib, 0, raw, logicalEnd, 0, seen);
        } else {
            Bytes ib(in.iblock, 60);
            u64 maxBlocks = (in.size + block_size - 1) / block_size;
            if (maxBlocks == 0) maxBlocks = in.blocks512 / (block_size / 512 ? block_size / 512 : 1);
            if (maxBlocks > 1u << 24) maxBlocks = 1u << 24;
            u64 count = 0;
            std::set<u64> seen;
            for (int i = 0; i < 12 && count < maxBlocks; i++) {
                u64 b = ib.le32((size_t)i * 4);
                if (b == 0) { raw.push_back(Extent(0, block_size, true)); count++; continue; }
                if (b >= blocks_count) continue;
                raw.push_back(Extent((i64)blockOffset(b), block_size));
                count++;
            }
            walkIndirect(ib.le32(12 * 4), 1, raw, count, maxBlocks, seen);
            walkIndirect(ib.le32(13 * 4), 2, raw, count, maxBlocks, seen);
            walkIndirect(ib.le32(14 * 4), 3, raw, count, maxBlocks, seen);
        }

        // Merge adjacent runs so a 1 GB contiguous file is one extent instead
        // of 256 000 single-block ones.
        std::vector<Extent> merged;
        merged.reserve(raw.size());
        for (const auto& e : raw) {
            if (!merged.empty()) {
                Extent& last = merged.back();
                if (last.sparse == e.sparse &&
                    (e.sparse || last.offset + last.length == e.offset)) {
                    last.length += e.length;
                    continue;
                }
            }
            merged.push_back(e);
        }
        return merged;
    }

    std::vector<u8> inlineData(const Inode& in) const {
        std::vector<u8> out;
        if (!(in.flags & kFlagInlineData)) return out;
        size_t n = std::min<size_t>(60, (size_t)in.size);
        out.assign(in.iblock, in.iblock + n);
        return out;
    }
};

// -------------------------------------------------------------------------
// Directory entries
// -------------------------------------------------------------------------
struct DirEnt {
    u32 inode = 0;
    u8  type = 0;
    std::string name;
    bool from_slack = false;
};

bool plausibleName(const std::string& n) {
    if (n.empty() || n.size() > 255) return false;
    for (unsigned char c : n) {
        if (c == '/' || c == 0) return false;
        if (c < 0x20) return false;
    }
    return true;
}

// Parses one directory block. Live entries come from the rec_len chain; the
// padding inside each rec_len is then re-scanned for unlinked entries, which is
// how a deleted filename is recovered on ext3/ext4.
void parseDirBlock(const std::vector<u8>& blk, u32 inodesCount, bool filetype,
                   std::vector<DirEnt>& out, bool slack) {
    Bytes b(blk);
    size_t pos = 0;
    while (pos + 8 <= b.size()) {
        u32 ino     = b.le32(pos);
        u16 rec_len = b.le16(pos + 4);
        u8  name_len = b.u8at(pos + 6);
        u8  ftype    = b.u8at(pos + 7);
        if (!filetype) { name_len = (u8)b.le16(pos + 6); ftype = 0; }

        if (rec_len < 8 || (rec_len & 3) || pos + rec_len > b.size()) break;

        if (ino != 0 && ino <= inodesCount && name_len > 0 &&
            pos + 8 + name_len <= b.size()) {
            std::string nm = b.str(pos + 8, name_len);
            if (plausibleName(nm)) out.push_back({ino, ftype, nm, false});
        }

        if (slack) {
            // Everything between the end of this name and the end of the record
            // is dead space that may still hold an unlinked entry.
            size_t used = 8 + (size_t)name_len;
            used = (used + 3) & ~size_t(3);
            size_t slackStart = pos + used;
            size_t slackEnd   = pos + rec_len;
            for (size_t p = slackStart; p + 8 < slackEnd && p + 8 < b.size(); p += 4) {
                u32 sino = b.le32(p);
                u16 srec = b.le16(p + 4);
                u8  slen = b.u8at(p + 6);
                if (!filetype) slen = (u8)b.le16(p + 6);
                if (sino == 0 || sino > inodesCount) continue;
                if (slen == 0) continue;
                if (srec < 8 + slen) continue;
                if (p + 8 + slen > slackEnd) continue;
                std::string nm = b.str(p + 8, slen);
                if (!plausibleName(nm)) continue;
                out.push_back({sino, b.u8at(p + 7), nm, true});
            }
        }
        pos += rec_len;
    }
}

// -------------------------------------------------------------------------
// jbd2 journal mining
// -------------------------------------------------------------------------
struct JournalHit {
    u64 fs_block = 0;      // filesystem block this journal block is a copy of
    u64 journal_off = 0;   // byte offset of the copy inside the volume
};

// Maps each journal block back to the filesystem block it shadows, by walking
// descriptor blocks. Old inode-table copies found this way still contain the
// extent trees that unlink() zeroed in the live table.
std::vector<JournalHit> mapJournal(ExtFs& fs, const std::vector<Extent>& journalExtents,
                                   Progress& prog) {
    std::vector<JournalHit> hits;
    if (journalExtents.empty()) return hits;

    // Flatten the journal's extents into a linear block address space.
    auto journalByteAt = [&](u64 jblock) -> i64 {
        u64 want = jblock * (u64)fs.block_size;
        for (const auto& e : journalExtents) {
            if (e.sparse) { if (want < (u64)e.length) return -1; want -= e.length; continue; }
            if (want < (u64)e.length) return e.offset + (i64)want;
            want -= e.length;
        }
        return -1;
    };

    i64 sbOff = journalByteAt(0);
    if (sbOff < 0) return hits;
    auto jsbRaw = fs.d->readBlock(sbOff, fs.block_size);
    Bytes jsb(jsbRaw);
    if (jsb.be32(0) != 0xC03B3998u) return hits;

    u32 jBlockSize = jsb.be32(12);
    u32 jMaxLen    = jsb.be32(16);
    u32 jFeatures  = jsb.be32(40);          // s_feature_incompat
    const bool csum64 = (jFeatures & 0x00000010) != 0;   // JBD2_FEATURE_INCOMPAT_64BIT
    const bool csumV3 = (jFeatures & 0x00000020) != 0;   // JBD2_FEATURE_INCOMPAT_CSUM_V3
    if (jBlockSize != fs.block_size) return hits;
    if (jMaxLen == 0 || jMaxLen > (1u << 22)) return hits;

    const size_t tagSize = csumV3 ? 16u : (csum64 ? 12u : 8u);
    const u32 kTagLast   = 0x8;
    const u32 kTagSameUuid = 0x2;
    const u32 kTagEscape = 0x1;

    for (u32 jb = 1; jb < jMaxLen; jb++) {
        if (prog.cancelled()) break;
        i64 off = journalByteAt(jb);
        if (off < 0) break;
        auto raw = fs.d->readBlock(off, fs.block_size);
        Bytes h(raw);
        if (h.be32(0) != 0xC03B3998u) continue;
        u32 type = h.be32(4);
        if (type != 1) continue;              // only descriptor blocks carry tags

        size_t p = 12;
        u32 dataBlock = jb + 1;
        while (p + tagSize <= h.size()) {
            u64 blocknr;
            u32 flags;
            if (csumV3) {
                blocknr = h.be32(p + 0);
                flags   = h.be32(p + 4);
                blocknr |= ((u64)h.be32(p + 8)) << 32;
            } else {
                blocknr = h.be32(p + 0);
                flags   = h.be16(p + 6);
                if (csum64) blocknr |= ((u64)h.be32(p + 8)) << 32;
            }
            p += tagSize;
            if (!(flags & kTagSameUuid)) p += 16;
            (void)kTagEscape;

            if (blocknr != 0 && blocknr < fs.blocks_count && dataBlock < jMaxLen) {
                i64 dOff = journalByteAt(dataBlock);
                if (dOff >= 0) hits.push_back({blocknr, (u64)dOff});
            }
            dataBlock++;
            if (flags & kTagLast) break;
            if (hits.size() > 2000000) break;
        }
        jb = dataBlock - 1;
        if (hits.size() > 2000000) break;
    }
    return hits;
}

}  // namespace

// ---------------------------------------------------------------------------

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "ext4";

    ExtFs fs;
    fs.d = &disk;
    fs.volume = disk.size();

    std::string err;
    if (!fs.loadSuper(1024, &err)) {
        // Try the backups before giving up — a wiped primary superblock is one
        // of the most common "my disk is gone" situations.
        bool recovered = false;
        for (u32 bs : {1024u, 2048u, 4096u, 8192u, 16384u, 32768u, 65536u}) {
            for (u32 bpg : {bs * 8}) {
                ExtFs probe;
                probe.d = &disk;
                probe.volume = fs.volume;
                for (u64 off : probe.backupSuperblockOffsets(bs, bpg)) {
                    if ((i64)off + 1024 > fs.volume) break;
                    if (probe.loadSuper(off, nullptr) && probe.block_size == bs) {
                        fs = probe;
                        res.technique("backup_superblock_recovery");
                        res.bump("superblock_backups_used");
                        recovered = true;
                        break;
                    }
                }
                if (recovered) break;
            }
            if (recovered) break;
        }
        if (!recovered) {
            res.ok = false;
            res.error = err.empty() ? "not an ext2/3/4 filesystem" : err;
            return res;
        }
    }

    if (!fs.loadGroups()) {
        res.ok = false;
        res.error = "ext group descriptor table is unreadable";
        res.filesystem = fs.flavour;
        return res;
    }

    res.ok           = true;
    res.filesystem   = fs.flavour;
    res.label        = fs.label;
    res.uuid         = fs.uuid;
    res.block_size   = fs.block_size;
    res.total_blocks = (i64)fs.blocks_count;
    res.free_blocks  = (i64)fs.free_blocks;
    res.total_inodes = fs.inodes_count;
    res.free_inodes  = (i64)fs.free_inodes;
    res.volume_size  = fs.volume;
    res.bump("block_groups", fs.groups);
    res.bump("inode_size", fs.inode_size);

    // ---- pass 1: every inode in every group ------------------------------
    prog.setPhase("reading inode tables");
    prog.set(0, fs.groups);

    struct Entry {
        Inode in;
        bool  deleted = false;
        bool  from_journal = false;
    };
    std::unordered_map<u64, Entry> inodes;
    inodes.reserve(std::min<size_t>((size_t)fs.inodes_count, 400000));

    const u64 perRead = std::max<u64>(1, (256 * 1024) / fs.inode_size);
    for (u32 g = 0; g < fs.groups; g++) {
        if (prog.cancelled()) break;
        prog.set(g, fs.groups);
        if (fs.inode_table[g] == 0) continue;
        u64 tableOff = fs.blockOffset(fs.inode_table[g]);
        if (tableOff >= (u64)fs.volume) continue;

        for (u64 i = 0; i < fs.inodes_per_group; i += perRead) {
            u64 count = std::min<u64>(perRead, fs.inodes_per_group - i);
            auto raw = disk.readBlock(tableOff + i * fs.inode_size, (i64)(count * fs.inode_size));
            if (raw.empty()) break;
            Bytes b(raw);
            for (u64 k = 0; k < count; k++) {
                size_t o = (size_t)(k * fs.inode_size);
                if (!b.has(o, 128)) break;
                u64 ino = (u64)g * fs.inodes_per_group + i + k + 1;
                if (ino < fs.first_ino && ino != 2) continue;   // reserved, except root

                Inode in;
                if (!fs.parseInode(b, o, in)) continue;
                if (in.mode == 0 && in.size == 0 && in.dtime == 0 && in.links == 0) continue;

                bool deleted = (in.dtime != 0) || (in.links == 0 && in.mode != 0);
                if (deleted && in.mode == 0 && in.size == 0) continue;
                if (!deleted && !opt.include_live) continue;

                Entry e;
                e.in = in;
                e.deleted = deleted;
                inodes[ino] = e;
                if ((i64)inodes.size() >= opt.max_files * 2) break;
            }
            if ((i64)inodes.size() >= opt.max_files * 2) break;
        }
        if ((i64)inodes.size() >= opt.max_files * 2) break;
    }
    res.technique("inode_table_walk");
    res.bump("inodes_examined", (i64)inodes.size());

    // ---- pass 2: journal mining ------------------------------------------
    // Recovers extent trees that the live inode no longer has.
    if (opt.journal && fs.journal_inum && (fs.feature_compat & kCompatHasJournal) &&
        !prog.cancelled()) {
        prog.setPhase("mining jbd2 journal");
        Inode jin;
        if (fs.readInode(fs.journal_inum, jin)) {
            auto jext = fs.dataExtents(jin);
            auto hits = mapJournal(fs, jext, prog);
            res.bump("journal_blocks_mapped", (i64)hits.size());

            // Which filesystem blocks belong to an inode table?
            auto inodeForBlock = [&](u64 blk, u32& groupOut, u64& firstInoOut) -> bool {
                u64 tableBlocks = ((u64)fs.inodes_per_group * fs.inode_size + fs.block_size - 1) /
                                  fs.block_size;
                for (u32 g = 0; g < fs.groups; g++) {
                    u64 start = fs.inode_table[g];
                    if (start == 0) continue;
                    if (blk >= start && blk < start + tableBlocks) {
                        groupOut = g;
                        u64 blockIdx = blk - start;
                        firstInoOut = (u64)g * fs.inodes_per_group +
                                      (blockIdx * fs.block_size) / fs.inode_size + 1;
                        return true;
                    }
                }
                return false;
            };

            i64 revived = 0;
            for (const auto& hit : hits) {
                if (prog.cancelled()) break;
                u32 grp = 0;
                u64 firstIno = 0;
                if (!inodeForBlock(hit.fs_block, grp, firstIno)) continue;
                auto raw = disk.readBlock(hit.journal_off, fs.block_size);
                if (raw.empty()) continue;
                Bytes b(raw);
                u32 perBlock = fs.block_size / fs.inode_size;
                for (u32 k = 0; k < perBlock; k++) {
                    Inode in;
                    if (!fs.parseInode(b, (size_t)k * fs.inode_size, in)) continue;
                    if (in.mode == 0 || in.size == 0) continue;
                    u64 ino = firstIno + k;
                    if (ino == 0 || ino > fs.inodes_count) continue;

                    auto it = inodes.find(ino);
                    bool liveHasData = false;
                    if (it != inodes.end()) {
                        // Journal copy is only interesting when the live inode
                        // has lost its block pointers.
                        liveHasData = !fs.dataExtents(it->second.in).empty();
                        if (liveHasData && !it->second.deleted) continue;
                    }
                    auto jExtents = fs.dataExtents(in);
                    if (jExtents.empty()) continue;
                    if (it != inodes.end() && liveHasData) continue;

                    Entry e;
                    e.in = in;
                    e.deleted = true;
                    e.from_journal = true;
                    inodes[ino] = e;
                    revived++;
                }
            }
            if (revived > 0) {
                res.technique("jbd2_journal_inode_recovery");
                res.bump("journal_ghost_inodes", revived);
            }
        }
    }

    // ---- pass 3: directory tree ------------------------------------------
    prog.setPhase("reconstructing directory tree");
    std::unordered_map<u64, std::string> names;
    std::unordered_map<u64, u64>         parents;
    i64 slackEntries = 0;

    if (opt.resolve_paths && !prog.cancelled()) {
        std::vector<u64> dirs;
        for (const auto& [ino, e] : inodes)
            if ((e.in.mode & 0xF000) == 0x4000) dirs.push_back(ino);
        // Root is reserved and therefore skipped by the inode pass filter.
        Inode rootIn;
        if (fs.readInode(2, rootIn) && (rootIn.mode & 0xF000) == 0x4000) {
            Entry re; re.in = rootIn; re.deleted = false;
            inodes[2] = re;
            dirs.push_back(2);
        }
        std::sort(dirs.begin(), dirs.end());
        dirs.erase(std::unique(dirs.begin(), dirs.end()), dirs.end());

        prog.set(0, (i64)dirs.size());
        i64 processed = 0;
        for (u64 dino : dirs) {
            if (prog.cancelled()) break;
            prog.set(++processed, (i64)dirs.size());
            auto it = inodes.find(dino);
            if (it == inodes.end()) continue;
            const Inode& din = it->second.in;

            std::vector<DirEnt> ents;
            if (din.flags & kFlagInlineData) {
                std::vector<u8> inl(din.iblock, din.iblock + 60);
                parseDirBlock(inl, fs.inodes_count, fs.hasFiletype(), ents, false);
            } else {
                auto ex = fs.dataExtents(din);
                i64 budget = 0;
                for (const auto& e : ex) {
                    if (e.sparse) continue;
                    for (i64 o = 0; o < e.length; o += fs.block_size) {
                        if (budget > 64LL * 1024 * 1024) break;
                        auto blk = disk.readBlock((u64)(e.offset + o), fs.block_size);
                        if (blk.empty()) break;
                        budget += fs.block_size;
                        parseDirBlock(blk, fs.inodes_count, fs.hasFiletype(), ents, opt.slack);
                    }
                }
            }
            for (const auto& de : ents) {
                if (de.name == "." || de.name == "..") continue;
                if (de.from_slack) {
                    slackEntries++;
                    // Don't let a stale slack name overwrite a live one.
                    if (names.count(de.inode)) continue;
                }
                names[de.inode]   = de.name;
                parents[de.inode] = dino;
            }
        }
        res.technique("directory_tree_walk");
        if (slackEntries > 0) {
            res.technique("dentry_slack_carving");
            res.bump("slack_space_entries", slackEntries);
        }
    }

    // ---- orphan inode list ------------------------------------------------
    if (opt.orphans && fs.last_orphan && !prog.cancelled()) {
        i64 orphans = 0;
        u64 ino = fs.last_orphan;
        std::set<u64> seen;
        while (ino && ino <= fs.inodes_count && seen.insert(ino).second && orphans < 100000) {
            Inode in;
            if (!fs.readInode(ino, in)) break;
            auto it = inodes.find(ino);
            if (it == inodes.end()) {
                Entry e; e.in = in; e.deleted = true;
                inodes[ino] = e;
            } else {
                it->second.deleted = true;
            }
            orphans++;
            ino = in.dtime;   // i_dtime doubles as the next-orphan pointer
        }
        if (orphans) {
            res.technique("orphan_inode_list_scan");
            res.bump("orphan_inodes_found", orphans);
        }
    }

    // ---- build the result -------------------------------------------------
    prog.setPhase("resolving paths");
    auto resolvePath = [&](u64 ino) -> std::string {
        std::vector<std::string> parts;
        u64 cur = ino;
        int guard = 0;
        while (cur != 0 && cur != 2 && guard++ < 128) {
            auto n = names.find(cur);
            if (n == names.end()) break;
            parts.push_back(n->second);
            auto p = parents.find(cur);
            if (p == parents.end()) break;
            cur = p->second;
        }
        if (parts.empty()) return {};
        std::string out;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
            out += '/';
            out += *it;
        }
        return out;
    };

    res.files.reserve(std::min<size_t>(inodes.size(), (size_t)opt.max_files));
    i64 withExtents = 0, deletedRecoverable = 0;
    for (const auto& [ino, e] : inodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        const Inode& in = e.in;
        FileKind kind = kindFromMode(in.mode);
        if (kind == FileKind::Directory && !opt.include_live && !e.deleted) continue;

        RecoveredFile f;
        f.id        = ino;
        f.size      = (i64)in.size;
        f.alloc_size = (i64)in.blocks512 * 512;
        f.is_deleted = e.deleted;
        f.is_dir     = kind == FileKind::Directory;
        f.kind       = kind;
        f.mtime = in.mtime; f.atime = in.atime; f.ctime = in.ctime;
        f.crtime = in.crtime; f.dtime = in.dtime;
        f.uid = in.uid; f.gid = in.gid; f.mode = in.mode & 0x0FFF;
        f.nlink = in.links;
        f.is_encrypted = (in.flags & kFlagEncrypted) != 0;

        auto nit = names.find(ino);
        if (nit != names.end()) f.name = nit->second;
        else f.name = (e.deleted ? "deleted_" : "inode_") + std::to_string(ino);
        auto pit = parents.find(ino);
        if (pit != parents.end()) f.parent_id = pit->second;
        f.path = resolvePath(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;

        if (in.flags & kFlagInlineData) {
            f.resident = fs.inlineData(in);
            f.method = "inline_data";
        } else if (kind == FileKind::Symlink && in.size > 0 && in.size < 60) {
            f.resident.assign(in.iblock, in.iblock + in.size);
            f.method = "fast_symlink";
        } else {
            f.extents = fs.dataExtents(in);
            if (e.from_journal)         f.method = "jbd2_journal_inode_recovery";
            else if (e.deleted)         f.method = "i_dtime_deleted_inode";
            else if (fs.hasExtents())   f.method = "extent_tree_walk";
            else                        f.method = "indirect_block_walk";
        }

        finalizeFile(f, fs.volume);

        if (f.is_deleted) {
            // Confidence reflects how much of the file we can actually pull
            // back — a deleted inode with no surviving block pointers is a name
            // and a size, nothing more.
            if (f.recoverable <= 0)          f.confidence = 0.0;
            else if (f.size > 0)             f.confidence = std::min(1.0, (double)f.recoverable / (double)f.size);
            if (f.recoverable > 0) deletedRecoverable++;
        }
        if (!f.extents.empty()) withExtents++;

        res.files.push_back(std::move(f));
    }

    res.bump("files_with_data", withExtents);
    res.bump("deleted_with_recoverable_data", deletedRecoverable);
    if (fs.hasExtents()) res.technique("extent_tree_walk");
    else                 res.technique("indirect_block_walk");
    res.technique("i_dtime_deleted_inode");
    if (opt.resolve_paths) res.technique("path_reconstruction");

    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });

    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace ext
}  // namespace ghost
