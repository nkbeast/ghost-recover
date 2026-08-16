// GHOST RECOVER — XFS driver (v4 and v5 / CRC).
//
// Replaces a stub that returned three technique strings and no files.
// Implements: superblock parsing, per-AG inode B+tree (inobt/IAB3) traversal,
// v2 and v3 inode cores, packed extent-record decoding, short-form and
// block/leaf directory formats, path reconstruction, and a free-slot harvest
// that recovers inodes XFS has released but not yet overwritten.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace ghost {
namespace xfs {

namespace {

constexpr u16 kInodeMagic = 0x494E;   // "IN"

struct XfsSb {
    u32 blocksize = 4096;
    u64 dblocks = 0;
    u64 rootino = 0;
    u32 agblocks = 0;
    u32 agcount = 0;
    u16 versionnum = 0;
    u16 sectsize = 512;
    u16 inodesize = 256;
    u16 inopblock = 0;
    u8  blocklog = 12, sectlog = 9, inodelog = 8, inopblog = 4, agblklog = 0;
    u64 icount = 0, ifree = 0, fdblocks = 0;
    std::string label, uuid;
    bool crc = false;      // v5 layout
    bool ftype = false;    // directory entries carry a file-type byte
    bool bigtime = false;  // timestamps are ns since 1901 rather than sec/nsec
    bool nrext64 = false;  // 64-bit extent counter moves di_nextents to 0x18
};

struct XfsFs {
    DiskReader* d = nullptr;
    i64 volume = 0;
    XfsSb sb;

    i64 fsbToByte(u64 fsb) const {
        u64 agno  = fsb >> sb.agblklog;
        u64 agbno = fsb & (((u64)1 << sb.agblklog) - 1);
        return (i64)((agno * sb.agblocks + agbno) * sb.blocksize);
    }
    i64 inoToByte(u64 ino) const {
        u64 shift = (u64)sb.agblklog + sb.inopblog;
        u64 agno  = ino >> shift;
        u64 rest  = ino & (((u64)1 << shift) - 1);
        u64 agbno = rest >> sb.inopblog;
        u64 off   = rest & (((u64)1 << sb.inopblog) - 1);
        return (i64)((agno * sb.agblocks + agbno) * sb.blocksize + off * sb.inodesize);
    }

    bool load(std::string* err) {
        auto raw = d->readBlock(0, 512);
        Bytes b(raw);
        if (raw.size() < 512 || !b.eq(0, "XFSB", 4)) {
            if (err) *err = "XFS superblock magic not found";
            return false;
        }
        sb.blocksize = b.be32(0x04);
        sb.dblocks   = b.be64(0x08);
        sb.rootino   = b.be64(0x38);
        sb.agblocks  = b.be32(0x54);
        sb.agcount   = b.be32(0x58);
        sb.versionnum = b.be16(0x64);
        sb.sectsize  = b.be16(0x66);
        sb.inodesize = b.be16(0x68);
        sb.inopblock = b.be16(0x6A);
        sb.label     = b.trimmed(0x6C, 12);
        sb.blocklog  = b.u8at(0x78);
        sb.sectlog   = b.u8at(0x79);
        sb.inodelog  = b.u8at(0x7A);
        sb.inopblog  = b.u8at(0x7B);
        sb.agblklog  = b.u8at(0x7C);
        sb.icount    = b.be64(0x80);
        sb.ifree     = b.be64(0x88);
        sb.fdblocks  = b.be64(0x90);
        if (raw.size() >= 0x20 + 16) {
            const u8* g = raw.data() + 0x20;
            char buf[40];
            snprintf(buf, sizeof(buf),
                     "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     g[0],g[1],g[2],g[3],g[4],g[5],g[6],g[7],g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
            sb.uuid = buf;
        }

        u16 ver = sb.versionnum & 0x000F;
        sb.crc = (ver == 5);
        u32 features2 = b.be32(0xC8);       // sb_features2
        (void)features2;
        if (sb.crc) {
            // sb_features_incompat lives at 0xD8; 0xE0 is sb_crc, so reading
            // there gave a random ftype flag and shifted every directory entry.
            u32 incompat = b.be32(0xD8);
            sb.ftype   = (incompat & 0x01) != 0;   // XFS_SB_FEAT_INCOMPAT_FTYPE
            sb.bigtime = (incompat & 0x08) != 0;   // XFS_SB_FEAT_INCOMPAT_BIGTIME
            sb.nrext64 = (incompat & 0x20) != 0;   // XFS_SB_FEAT_INCOMPAT_NREXT64
        } else {
            sb.ftype = (b.be32(0xC8) & 0x200) != 0;   // XFS_SB_VERSION2_FTYPE
        }

        if (sb.blocksize < 512 || sb.blocksize > 65536 || (sb.blocksize & (sb.blocksize - 1)))
            { if (err) *err = "implausible XFS block size"; return false; }
        if (sb.inodesize < 256 || sb.inodesize > 2048 || (sb.inodesize & (sb.inodesize - 1)))
            { if (err) *err = "implausible XFS inode size"; return false; }
        if (sb.agcount == 0 || sb.agcount > 1000000 || sb.agblocks == 0 ||
            // A real AG never spans beyond the device (the trailing group is
            // truncated, never inflated); this also keeps the AG-offset math
            // from wrapping in the inode-B+tree walk.
            (u64)sb.agblocks * sb.blocksize > (u64)d->size() + sb.blocksize)
            { if (err) *err = "implausible XFS AG geometry"; return false; }
        // These are shift counts used as `1 << x` when converting between inode
        // numbers, AG blocks and bytes. A corrupt value above 63 is undefined
        // behavior; anything implausible is not a real XFS volume anyway.
        if (sb.agblklog == 0 || sb.agblklog > 32 || sb.inopblog == 0 || sb.inopblog > 10 ||
            sb.blocklog < 8 || sb.blocklog > 16 || sb.sectlog < 7 || sb.sectlog > 16)
            { if (err) *err = "implausible XFS log fields"; return false; }
        return true;
    }
};

struct XInode {
    bool valid = false;
    u16  mode = 0;
    u8   version = 2;
    u8   format = 0;          // 1 local, 2 extents, 3 btree
    u32  uid = 0, gid = 0, nlink = 0;
    i64  atime = 0, mtime = 0, ctime = 0, crtime = 0;
    u64  size = 0, nblocks = 0;
    u32  nextents = 0;
    u8   forkoff = 0;
    u16  flags = 0;
    size_t fork_offset = 100;
};

// With XFS_SB_FEAT_INCOMPAT_BIGTIME a timestamp is a 64-bit nanosecond count
// from 1901 instead of a {seconds, nanoseconds} pair.
i64 readTimestamp(const Bytes& b, size_t off, bool bigtime) {
    if (!bigtime) return (i64)(i32)b.be32(off);
    u64 ns = b.be64(off);
    return (i64)(ns / 1000000000ull) - 2147483648LL;
}

XInode parseInode(const Bytes& b, size_t off, bool bigtime, bool nrext64) {
    XInode in;
    if (b.be16(off) != kInodeMagic) return in;
    in.mode     = b.be16(off + 0x02);
    in.version  = b.u8at(off + 0x04);
    in.format   = b.u8at(off + 0x05);
    in.uid      = b.be32(off + 0x08);
    in.gid      = b.be32(off + 0x0C);
    in.nlink    = b.be32(off + 0x10);
    in.atime    = readTimestamp(b, off + 0x20, bigtime);
    in.mtime    = readTimestamp(b, off + 0x28, bigtime);
    in.ctime    = readTimestamp(b, off + 0x30, bigtime);
    in.size     = b.be64(off + 0x38);
    in.nblocks  = b.be64(off + 0x40);
    // NREXT64 moves the data-fork extent count into the 64-bit field at 0x18
    // that older layouts used for padding; 0x4C then reads as zero, which is
    // why every extent list came back empty on a modern mkfs.xfs volume.
    in.nextents = nrext64 ? (u32)b.be64(off + 0x18) : b.be32(off + 0x4C);
    in.forkoff  = b.u8at(off + 0x52);
    in.flags    = b.be16(off + 0x5A);
    if (in.version >= 3) {
        in.crtime = readTimestamp(b, off + 0x90, bigtime);   // 0x98 is di_ino
        in.fork_offset = 176;
    } else {
        in.fork_offset = 100;
    }
    in.valid = true;
    return in;
}

FileKind kindOf(u16 mode) {
    switch (mode & 0xF000) {
        case 0x8000: return FileKind::Regular;
        case 0x4000: return FileKind::Directory;
        case 0xA000: return FileKind::Symlink;
        default:     return FileKind::Other;
    }
}

// XFS packs an extent into 128 bits: flag | startoff:54 | startblock:52 |
// blockcount:21.
struct XExtent { u64 startoff, startblock, blockcount; bool unwritten; };

XExtent decodeExtent(u64 l0, u64 l1) {
    XExtent e;
    e.unwritten  = (l0 >> 63) != 0;
    e.startoff   = (l0 & 0x7FFFFFFFFFFFFFFFull) >> 9;
    e.startblock = ((l0 & 0x1FFull) << 43) | (l1 >> 21);
    e.blockcount = l1 & 0x1FFFFFull;
    return e;
}

}  // namespace

// ---------------------------------------------------------------------------

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "xfs";

    XfsFs fs;
    fs.d = &disk;
    fs.volume = disk.size();

    std::string err;
    if (!fs.load(&err)) {
        // Every allocation group starts with a superblock copy. Scan forward
        // for one and rebuild the geometry from it — this is what makes a
        // wiped primary superblock survivable.
        bool ok = false;
        const i64 kProbeLimit = std::min<i64>(fs.volume, 64LL * 1024 * 1024 * 1024);
        for (i64 off = 512; off < kProbeLimit && !ok; off = off ? off * 2 : 512) {
            auto probe = disk.readBlock((u64)off, 4);
            if (probe.size() == 4 && std::memcmp(probe.data(), "XFSB", 4) == 0) {
                auto raw = disk.readBlock((u64)off, 512);
                Bytes b(raw);
                XfsSb s;
                s.blocksize = b.be32(0x04);
                s.agblocks  = b.be32(0x54);
                s.agcount   = b.be32(0x58);
                s.inodesize = b.be16(0x68);
                s.agblklog  = b.u8at(0x7C);
                s.inopblog  = b.u8at(0x7B);
                s.sectsize  = b.be16(0x66);
                s.rootino   = b.be64(0x38);
                s.dblocks   = b.be64(0x08);
                s.versionnum = b.be16(0x64);
                s.crc = (s.versionnum & 0x0F) == 5;
                if (s.blocksize >= 512 && s.agblocks && s.agcount && s.inodesize >= 256 &&
                    s.agblklog >= 1 && s.agblklog <= 32 && s.inopblog >= 1 && s.inopblog <= 10) {
                    fs.sb = s;
                    res.technique("backup_superblock_recovery");
                    res.bump("superblock_recovered_at_offset", off);
                    ok = true;
                }
            }
        }
        if (!ok) { res.ok = false; res.error = err; return res; }
    }

    res.ok           = true;
    res.block_size   = fs.sb.blocksize;
    res.total_blocks = (i64)fs.sb.dblocks;
    res.free_blocks  = (i64)fs.sb.fdblocks;
    res.total_inodes = (i64)fs.sb.icount;
    res.free_inodes  = (i64)fs.sb.ifree;
    res.label        = fs.sb.label;
    res.uuid         = fs.sb.uuid;
    res.volume_size  = fs.volume;
    res.bump("allocation_groups", fs.sb.agcount);
    res.bump("inode_size", fs.sb.inodesize);
    res.bump("xfs_version", fs.sb.crc ? 5 : 4);

    // ---- collect inode numbers from every AG's inode B+tree ---------------
    prog.setPhase("walking inode B+trees");
    // ir_startino is an *AG-relative* inode number. Treating it as absolute
    // makes every allocation group's chunk collide with AG 0's, so only the
    // last group's inodes survive and their free bitmap is applied to the
    // wrong inodes.
    struct Chunk { u32 agno; u64 startino; u64 freeMask; };
    std::vector<Chunk> chunks;
    u32 currentAg = 0;

    // A damaged or hostile tree can point back at a block already on the
    // way down (a cycle) or anywhere else in the tree; without this set the
    // walk re-reads the same blocks forever. Block numbers are unique
    // across AGs because every pointer is offset by ag*agblocks.
    std::unordered_set<u64> visitedBlocks;

    auto walkInobt = [&](u64 blockNo, int depth, auto&& self) -> void {
        if (depth > 16 || chunks.size() > 4000000) return;
        if (!visitedBlocks.insert(blockNo).second) return;
        // Unsigned offset math: (i64)blockNo * blocksize overflows for huge
        // disk block numbers and can wrap to a wrong in-volume block.
        u64 offU = blockNo * (u64)fs.sb.blocksize;
        if (offU >= (u64)fs.volume ||
            (u64)fs.volume - offU < (u64)fs.sb.blocksize)
            return;
        i64 off = (i64)offU;
        auto raw = disk.readBlock((u64)off, fs.sb.blocksize);
        Bytes b(raw);
        bool v5 = b.eq(0, "IAB3", 4);
        bool v4 = b.eq(0, "IABT", 4);
        if (!v4 && !v5) return;
        size_t hdr = v5 ? 56 : 16;
        u16 level   = b.be16(4);
        u16 numrecs = b.be16(6);
        if (numrecs > (fs.sb.blocksize / 8)) return;

        if (level == 0) {
            for (u16 i = 0; i < numrecs; i++) {
                size_t p = hdr + (size_t)i * 16;
                if (!b.has(p, 16)) break;
                Chunk c;
                c.agno     = currentAg;
                c.startino = b.be32(p);
                c.freeMask = b.be64(p + 8);
                chunks.push_back(c);
            }
        } else {
            // Keys occupy the first half, pointers the second.
            size_t maxrecs = (fs.sb.blocksize - hdr) / (4 + 4);
            for (u16 i = 0; i < numrecs; i++) {
                size_t p = hdr + maxrecs * 4 + (size_t)i * 4;
                if (!b.has(p, 4)) break;
                u32 childAgbno = b.be32(p);
                if (childAgbno == 0 || childAgbno == 0xFFFFFFFFu) continue;
                // Pointers are AG-relative; recover the AG from the block we
                // are currently in.
                u64 agno = blockNo / fs.sb.agblocks;
                self(agno * fs.sb.agblocks + childAgbno, depth + 1, self);
            }
        }
    };

    for (u32 ag = 0; ag < fs.sb.agcount && !prog.cancelled(); ag++) {
        prog.set(ag, fs.sb.agcount);
        // AG layout: sector 0 SB, 1 AGF, 2 AGI, 3 AGFL
        // (i64)ag * agblocks * blocksize overflows i64 for unbounded
        // agblocks; compute unsigned and bound against the volume.
        u64 agiOffU = (u64)ag * (u64)fs.sb.agblocks * (u64)fs.sb.blocksize +
                      2 * (u64)fs.sb.sectsize;
        if (agiOffU >= (u64)fs.volume ||
            (u64)fs.volume - agiOffU < (u64)fs.sb.sectsize)
            break;
        auto agi = disk.readBlock(agiOffU, fs.sb.sectsize);
        Bytes a(agi);
        if (!a.eq(0, "XAGI", 4)) continue;
        u32 root = a.be32(0x14);
        if (root == 0) continue;
        currentAg = ag;
        walkInobt((u64)ag * fs.sb.agblocks + root, 0, walkInobt);
    }
    res.technique("inode_btree_walk");
    res.bump("inode_chunks", (i64)chunks.size());

    // ---- read the inodes --------------------------------------------------
    prog.setPhase("reading inodes");
    struct Node {
        XInode in;
        std::vector<u8> fork;
        bool freeSlot = false;
    };
    std::unordered_map<u64, Node> inodes;
    inodes.reserve(std::min<size_t>(chunks.size() * 64, 400000));

    i64 freeHarvest = 0;
    for (size_t ci = 0; ci < chunks.size() && !prog.cancelled(); ci++) {
        if ((i64)inodes.size() >= opt.max_files * 2) break;
        const Chunk& c = chunks[ci];
        for (int slot = 0; slot < 64; slot++) {
            bool isFree = (c.freeMask >> slot) & 1;
            if (isFree && !opt.orphans) continue;
            const u64 agShift = (u64)fs.sb.agblklog + fs.sb.inopblog;
            u64 ino = ((u64)c.agno << agShift) | (c.startino + (u64)slot);
            i64 off = fs.inoToByte(ino);
            if (off < 0 || off + fs.sb.inodesize > fs.volume) continue;
            auto raw = disk.readBlock((u64)off, fs.sb.inodesize);
            Bytes b(raw);
            XInode in = parseInode(b, 0, fs.sb.bigtime, fs.sb.nrext64);
            if (!in.valid) continue;
            if (in.mode == 0) continue;               // slot fully cleared
            if (isFree) freeHarvest++;
            if (!isFree && !opt.include_live) continue;

            Node n;
            n.in = in;
            n.freeSlot = isFree;
            size_t forkStart = in.fork_offset;
            size_t forkLen = in.forkoff ? (size_t)in.forkoff * 8 : (fs.sb.inodesize - forkStart);
            if (forkStart + forkLen > raw.size()) forkLen = raw.size() > forkStart ? raw.size() - forkStart : 0;
            if (forkLen) n.fork.assign(raw.begin() + forkStart, raw.begin() + forkStart + forkLen);
            inodes[ino] = std::move(n);
        }
    }
    if (freeHarvest) {
        res.technique("free_inode_slot_harvest");
        res.bump("free_slot_inodes_recovered", freeHarvest);
    }

    // ---- extents ----------------------------------------------------------
    auto forkExtents = [&](const Node& n) -> std::vector<Extent> {
        std::vector<Extent> ex;
        Bytes f(n.fork);
        if (n.in.format == 2) {                     // inline extent list
            u32 count = n.in.nextents;
            if (count > n.fork.size() / 16) count = (u32)(n.fork.size() / 16);
            for (u32 i = 0; i < count; i++) {
                u64 l0 = f.be64((size_t)i * 16);
                u64 l1 = f.be64((size_t)i * 16 + 8);
                XExtent e = decodeExtent(l0, l1);
                if (e.blockcount == 0) continue;
                i64 off = fs.fsbToByte(e.startblock);
                i64 len = (i64)e.blockcount * fs.sb.blocksize;
                if (off < 0 || off >= fs.volume) continue;
                if (!ex.empty() && ex.back().offset + ex.back().length == off) ex.back().length += len;
                else ex.push_back(Extent(off, len));
            }
        } else if (n.in.format == 3) {              // B+tree extent map
            // Root is a bmbt block header followed by keys then pointers.
            u16 level = f.be16(0);
            u16 numrecs = f.be16(2);
            size_t maxrecs = (n.fork.size() - 4) / 16;
            std::vector<u64> children;
            for (size_t i = 0; i < (size_t)numrecs && i < maxrecs; i++) {
                size_t p = 4 + maxrecs * 8 + (size_t)i * 8;
                if (!f.has(p, 8)) break;
                children.push_back(f.be64(p));
            }
            std::set<u64> seen;
            std::function<void(u64, int)> walk = [&](u64 blk, int depth) {
                if (depth > 12 || ex.size() > 200000) return;
                if (!seen.insert(blk).second) return;
                i64 off = fs.fsbToByte(blk);
                if (off < 0 || off + (i64)fs.sb.blocksize > fs.volume) return;
                auto raw = disk.readBlock((u64)off, fs.sb.blocksize);
                Bytes b(raw);
                bool v5 = b.eq(0, "BMA3", 4);
                bool v4 = b.eq(0, "BMAP", 4);
                if (!v4 && !v5) return;
                size_t hdr = v5 ? 72 : 24;
                u16 lvl = b.be16(4);
                u16 nrec = b.be16(6);
                if (lvl == 0) {
                    for (u16 i = 0; i < nrec; i++) {
                        size_t p = hdr + (size_t)i * 16;
                        if (!b.has(p, 16)) break;
                        XExtent e = decodeExtent(b.be64(p), b.be64(p + 8));
                        if (e.blockcount == 0) continue;
                        i64 eo = fs.fsbToByte(e.startblock);
                        i64 el = (i64)e.blockcount * fs.sb.blocksize;
                        if (eo < 0 || eo >= fs.volume) continue;
                        if (!ex.empty() && ex.back().offset + ex.back().length == eo)
                            ex.back().length += el;
                        else ex.push_back(Extent(eo, el));
                    }
                } else {
                    size_t mr = (fs.sb.blocksize - hdr) / 16;
                    for (u16 i = 0; i < nrec; i++) {
                        size_t p = hdr + mr * 8 + (size_t)i * 8;
                        if (!b.has(p, 8)) break;
                        walk(b.be64(p), depth + 1);
                    }
                }
            };
            for (u64 c : children) walk(c, 1);
            (void)level;
        }
        return ex;
    };

    // ---- directories ------------------------------------------------------
    prog.setPhase("reading directories");
    std::unordered_map<u64, std::string> names;
    std::unordered_map<u64, u64> parents;

    auto parseShortForm = [&](u64 dirIno, const Node& n) {
        Bytes f(n.fork);
        u8 count   = f.u8at(0);
        u8 i8count = f.u8at(1);
        size_t p = 2;
        p += i8count ? 8 : 4;                       // parent inode number
        u8 total = count ? count : i8count;
        for (u8 i = 0; i < total; i++) {
            if (!f.has(p, 3)) break;
            u8 namelen = f.u8at(p);
            p += 3;                                  // namelen + offset(2)
            if (!f.has(p, namelen)) break;
            std::string nm = f.str(p, namelen);
            p += namelen;
            if (fs.sb.ftype) p += 1;
            u64 ino;
            if (i8count) { ino = f.be64(p); p += 8; }
            else         { ino = f.be32(p); p += 4; }
            if (ino == 0 || nm.empty() || nm == "." || nm == "..") continue;
            names[ino] = nm;
            parents[ino] = dirIno;
        }
    };

    auto parseDataBlock = [&](u64 dirIno, const std::vector<u8>& blk) {
        Bytes b(blk);
        size_t p = 0;
        bool v3 = b.eq(0, "XDD3", 4) || b.eq(0, "XDB3", 4);
        bool v2 = b.eq(0, "XD2D", 4) || b.eq(0, "XD2B", 4);
        if (v3) p = 64;
        else if (v2) p = 16;
        else return;
        while (p + 8 <= b.size()) {
            u16 freetag = b.be16(p);
            if (freetag == 0xFFFF) {
                u16 len = b.be16(p + 2);
                if (len < 4) break;
                p += len;
                continue;
            }
            u64 ino = b.be64(p);
            u8  namelen = b.u8at(p + 8);
            if (namelen == 0) break;
            if (!b.has(p + 9, namelen)) break;
            std::string nm = b.str(p + 9, namelen);
            size_t entLen = 8 + 1 + namelen + (fs.sb.ftype ? 1 : 0) + 2;
            entLen = (entLen + 7) & ~size_t(7);
            if (ino && nm != "." && nm != "..") {
                names[ino] = nm;
                parents[ino] = dirIno;
            }
            p += entLen;
        }
    };

    if (opt.resolve_paths) {
        for (const auto& [ino, n] : inodes) {
            if (prog.cancelled()) break;
            if (kindOf(n.in.mode) != FileKind::Directory) continue;
            if (n.in.format == 1) {
                parseShortForm(ino, n);
            } else {
                auto ex = forkExtents(n);
                i64 budget = 0;
                for (const auto& e : ex) {
                    for (i64 o = 0; o < e.length && budget < 32LL * 1024 * 1024;
                         o += fs.sb.blocksize, budget += fs.sb.blocksize) {
                        auto blk = disk.readBlock((u64)(e.offset + o), fs.sb.blocksize);
                        if (blk.size() < 16) break;
                        parseDataBlock(ino, blk);
                    }
                }
            }
        }
        res.technique("directory_walk");
        res.technique("path_reconstruction");
    }

    // ---- build results ----------------------------------------------------
    auto pathOf = [&](u64 ino) -> std::string {
        std::vector<std::string> parts;
        u64 cur = ino;
        int guard = 0;
        while (cur != fs.sb.rootino && guard++ < 128) {
            auto n = names.find(cur);
            if (n == names.end()) break;
            parts.push_back(n->second);
            auto p = parents.find(cur);
            if (p == parents.end()) break;
            cur = p->second;
        }
        if (parts.empty()) return {};
        std::string out;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) { out += '/'; out += *it; }
        return out;
    };

    for (const auto& [ino, n] : inodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        RecoveredFile f;
        f.id = ino;
        f.size = (i64)n.in.size;
        f.alloc_size = (i64)std::min<u64>(n.in.nblocks * (u64)fs.sb.blocksize, (u64)INT64_MAX);
        f.uid = n.in.uid; f.gid = n.in.gid; f.mode = n.in.mode & 0x0FFF;
        f.nlink = n.in.nlink;
        f.mtime = n.in.mtime; f.atime = n.in.atime; f.ctime = n.in.ctime; f.crtime = n.in.crtime;
        f.kind = kindOf(n.in.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = n.freeSlot || n.in.nlink == 0;
        auto nit = names.find(ino);
        f.name = (nit != names.end()) ? nit->second
                                      : ((f.is_deleted ? "deleted_inode_" : "inode_") + std::to_string(ino));
        auto pit = parents.find(ino);
        if (pit != parents.end()) f.parent_id = pit->second;
        f.path = pathOf(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;

        if (n.in.format == 1 && f.kind == FileKind::Symlink) {
            f.resident = n.fork;
            f.method = "local_fork";
        } else if (n.in.format == 1 && !f.is_dir) {
            f.resident = n.fork;
            if ((i64)f.resident.size() > f.size && f.size > 0) f.resident.resize((size_t)f.size);
            f.method = "local_fork";
        } else {
            f.extents = forkExtents(n);
            f.method = n.in.format == 3 ? "bmbt_extent_btree" : "inline_extent_list";
            if (n.freeSlot) f.method = "free_inode_slot_harvest";
        }
        finalizeFile(f, fs.volume);
        if (f.is_deleted) {
            f.confidence = (f.recoverable > 0 && f.size > 0)
                               ? std::min(1.0, (double)f.recoverable / (double)f.size)
                               : 0.2;
        }
        if (!pushFile(res, std::move(f), opt)) break;
    }

    res.technique("extent_list_decoding");
    prog.setFound((i64)res.files.size());
    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });
    return res;
}

}  // namespace xfs
}  // namespace ghost
