// GHOST//RECOVER — HFS+/HFSX and APFS drivers.
//
// Neither existed before: HFS+ volumes fell through to "unsupported" and APFS
// was not even detected.
//
// HFS+ walks the catalog B-tree leaf chain, which gives names, both forks and
// the extent descriptors. APFS sweeps every B-tree leaf in the container and
// reassembles inodes, directory records and file extents from the j_* records;
// as with Btrfs, sweeping rather than descending the live tree is what recovers
// deleted objects from superseded checkpoints.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <vector>

namespace ghost {

// ===========================================================================
// HFS+ / HFSX
// ===========================================================================
namespace hfs {
namespace {

struct ForkData {
    u64 logical = 0;
    u32 totalBlocks = 0;
    struct Ext { u32 start, count; };
    Ext extents[8] = {};
};

ForkData readFork(const Bytes& b, size_t off) {
    ForkData f;
    f.logical     = b.be64(off + 0);
    f.totalBlocks = b.be32(off + 12);
    for (int i = 0; i < 8; i++) {
        f.extents[i].start = b.be32(off + 16 + (size_t)i * 8);
        f.extents[i].count = b.be32(off + 16 + (size_t)i * 8 + 4);
    }
    return f;
}

}  // namespace

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "hfsplus";
    const i64 volume = disk.size();

    auto vhRaw = disk.readBlock(1024, 512);
    Bytes vh(vhRaw);
    u16 sig = vh.be16(0);
    if (vhRaw.size() < 512) {
        res.error = "volume header not readable";
        return res;
    }
    if (sig == 0x4244) {                      // 'BD' — classic HFS
        // Master Directory Block at 1024; the catalog is a B*-tree (HFS
        // node format: fLink/bLink/type/height/numRecords/reserved, records
        // keyed {parID,name}, offsets at the node tail, roff[0] == 14).
        // Allocation blocks are relative to the first allocation block.
        res.filesystem = "hfs";
        res.technique("catalog_btree_walk");
        const u32 alBlkSiz = vh.be32(20);
        if (alBlkSiz < 512 || alBlkSiz > (1u << 20) || (alBlkSiz & (alBlkSiz - 1))) {
            res.error = "implausible HFS allocation block size";
            return res;
        }
        res.block_size   = alBlkSiz;
        res.bump("file_count", vh.be32(84));    // drFilCnt
        res.bump("folder_count", vh.be32(88));  // drDirCnt
        res.bump("free_blocks", vh.be16(34));   // drFreeBks

        const u16 alBlSt  = vh.be16(28);
        const u16 ctStart = vh.be16(150);       // drCTExtRec[0].xdrStABN
        if (ctStart == 0) { res.error = "catalog file has no extents"; return res; }
        const u64 catPhys = ((u64)alBlSt + ctStart) * 512;
        i64 catLen = (i64)vh.be16(152) * 512;   // drCTExtRec[0].xdrNumABlks
        if (catPhys >= (u64)volume || catLen > volume - (i64)catPhys)
            catLen = (i64)std::max<i64>(0, volume - (i64)catPhys);
        if (catLen < 512) { res.error = "catalog file unreadable"; return res; }

        auto readCat = [&](u64 off, i64 len) -> std::vector<u8> {
            if (off >= (u64)catLen) return {};
            len = std::min<i64>(len, catLen - (i64)off);
            if (len <= 0) return {};
            return disk.readBlock(catPhys + off, len);
        };

        auto hnRaw = readCat(0, 512);
        if (hnRaw.size() < 512) { res.error = "catalog header node unreadable"; return res; }
        Bytes hb(hnRaw);
        if (hb.u8at(8) != 1) {                  // ndType: 1 = header node
            res.error = "catalog header node not found";
            return res;
        }
        const u32 nodeSize = hb.be16(32);       // bthNodeSize in the header record
        if (nodeSize < 512 || nodeSize > 65536 || (nodeSize & (nodeSize - 1))) {
            res.error = "implausible HFS catalog node size";
            return res;
        }
        u32 firstLeaf = hb.be32(24);            // bthFNode
        prog.setPhase("walking HFS catalog");

        res.ok = true;
        std::unordered_map<u32, std::string> names;
        std::unordered_map<u32, u32> parents;
        std::vector<RecoveredFile> found;
        i64 catEntries = 0;

        u32 node = firstLeaf;
        int guard = 0;
        i64 leaves = 0;
        while (node != 0 && guard++ < 4000000 && !prog.cancelled()) {
            auto nb = readCat((u64)node * nodeSize, nodeSize);
            if ((u32)nb.size() < nodeSize) break;
            Bytes b(nb);
            u32 fLink = b.be32(0);
            i8  kind  = (i8)b.u8at(8);
            u16 numRecs = b.be16(10);
            if (kind != -1) { node = fLink; continue; }   // ndLeafNode == 0xFF
            leaves++;
            if (numRecs > nodeSize / 16) { node = fLink; continue; }

            for (u16 r = 0; r < numRecs; r++) {
                size_t offPos = nodeSize - (size_t)(r + 1) * 2;
                size_t recOff = b.be16(offPos);
                if (recOff < 14 || recOff >= nodeSize) continue;
                u8 keyLen = b.u8at(recOff);
                u32 parentID = b.be32(recOff + 2);
                u8 nameLen = b.u8at(recOff + 6);
                std::string name;
                if (nameLen && b.has(recOff + 7, nameLen))
                    name.assign((const char*)(b.p + recOff + 7), nameLen);
                if (name.find('\0') != std::string::npos) name.clear();

                size_t dataOff = recOff + ((2 + keyLen) & ~size_t(1));
                if (dataOff + 2 > nodeSize) continue;
                u8 recType = b.u8at(dataOff);

                if (recType == 1) {                       // folder
                    u32 id = b.be32(dataOff + 6);         // dirDirID
                    if (id && !name.empty() && catEntries < (i64)opt.max_files * 2) {
                        names[id] = name; parents[id] = parentID; catEntries++;
                    }
                } else if (recType == 2) {                // file
                    if (dataOff + 100 > nodeSize) continue;
                    RecoveredFile f;
                    f.id = parentID;
                    f.parent_id = parentID;
                    f.name = name;
                    f.size = b.be32(dataOff + 26);        // filLgLen
                    f.crtime = hfsTimeToUnix(b.be32(dataOff + 44));
                    f.mtime  = hfsTimeToUnix(b.be32(dataOff + 48));
                    f.method = "catalog_btree_walk";
                    for (int i = 0; i < 3; i++) {         // filExtRec, in allocation blocks
                        u16 st  = b.be16(dataOff + 74 + (size_t)i * 4);
                        u16 cnt = b.be16(dataOff + 76 + (size_t)i * 4);
                        if (!cnt) continue;
                        i64 off = ((i64)alBlSt + st) * alBlkSiz;
                        i64 len = (i64)cnt * alBlkSiz;
                        if (off < 0 || off >= volume) continue;
                        f.extents.push_back(Extent(off, len));
                    }
                    finalizeFile(f, volume);
                    found.push_back(std::move(f));
                    if ((i64)found.size() >= opt.max_files) break;
                }
                // rtype 3/4 are file/dir thread records — only used for
                // alias resolution, not for recovery.
            }
            if ((i64)found.size() >= opt.max_files) break;
            node = fLink;
        }
        res.bump("catalog_leaf_nodes", leaves);

        auto pathOf = [&](u32 par) -> std::string {
            std::vector<std::string> parts;
            u32 cur = par;
            int g = 0;
            while (cur > 2 && g++ < 128) {          // 2 = root directory
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

        for (auto& f : found) {
            f.path = pathOf((u32)f.parent_id);
            if (f.path.empty()) f.path = "/$orphans/" + f.name;
            res.files.push_back(std::move(f));
        }
        prog.setFound((i64)res.files.size());
        return res;
    }
    if (sig != 0x482B && sig != 0x4858) {
        // The alternate volume header lives in the second-to-last sector.
        auto alt = disk.readBlock((u64)std::max<i64>(0, volume - 1024), 512);
        Bytes ab(alt);
        if (alt.size() >= 512 && (ab.be16(0) == 0x482B || ab.be16(0) == 0x4858)) {
            vhRaw = alt;
            vh = Bytes(vhRaw);
            sig = vh.be16(0);
            res.technique("alternate_volume_header_recovery");
        } else {
            res.ok = false;
            res.error = "HFS+ volume header not found (primary and alternate both unreadable)";
            return res;
        }
    }
    if (sig == 0x4858) res.filesystem = "hfsx";


    const u32 blockSize   = vh.be32(40);
    const u32 totalBlocks = vh.be32(44);
    const u32 freeBlocks  = vh.be32(48);
    if (blockSize < 512 || blockSize > 1u << 20 || (blockSize & (blockSize - 1))) {
        res.ok = false;
        res.error = "implausible HFS+ allocation block size";
        return res;
    }

    res.ok           = true;
    res.block_size   = blockSize;
    res.total_blocks = totalBlocks;
    res.free_blocks  = freeBlocks;
    res.volume_size  = volume;
    res.bump("file_count", vh.be32(32));
    res.bump("folder_count", vh.be32(36));
    res.technique("catalog_btree_walk");

    ForkData catalog = readFork(vh, 272);
    if (catalog.totalBlocks == 0) {
        res.error = "catalog file has no extents";
        return res;
    }

    // Read the catalog file through its (up to eight) extent descriptors.
    auto readCatalog = [&](u64 offset, i64 len) -> std::vector<u8> {
        std::vector<u8> out;
        u64 pos = 0;
        for (int i = 0; i < 8 && (i64)out.size() < len; i++) {
            u64 runBytes = (u64)catalog.extents[i].count * blockSize;
            if (runBytes == 0) continue;
            if (pos + runBytes <= offset) { pos += runBytes; continue; }
            u64 skip = offset > pos ? offset - pos : 0;
            i64 take = std::min<i64>((i64)(runBytes - skip), len - (i64)out.size());
            i64 phys = (i64)catalog.extents[i].start * blockSize + (i64)skip;
            if (phys < 0 || phys >= volume) break;
            auto part = disk.readBlock((u64)phys, take);
            out.insert(out.end(), part.begin(), part.end());
            pos += runBytes;
            if ((i64)part.size() < take) break;
        }
        return out;
    };

    auto headerNode = readCatalog(0, 512);
    Bytes hn(headerNode);
    u32 nodeSize = hn.be16(32);
    u32 firstLeaf = hn.be32(14 + 10);
    if (nodeSize < 512 || nodeSize > 65536 || (nodeSize & (nodeSize - 1))) nodeSize = 4096;

    prog.setPhase("walking HFS+ catalog");
    std::unordered_map<u32, std::string> names;
    std::unordered_map<u32, u32> parents;
    struct Rec { RecoveredFile f; };
    std::vector<RecoveredFile> found;
    // Folder records never count toward `found`, but a crafted catalog can
    // still nominate unbounded names/parents pairs; bound the two maps the
    // same way every other object map in this engine is bounded.
    i64 catEntries = 0;

    u32 node = firstLeaf;
    int guard = 0;
    i64 leaves = 0;
    while (node != 0 && guard++ < 4000000 && !prog.cancelled()) {
        auto nb = readCatalog((u64)node * nodeSize, nodeSize);
        if ((u32)nb.size() < nodeSize) break;
        Bytes b(nb);
        u32 fLink = b.be32(0);
        i8  kind  = (i8)b.u8at(8);
        u16 numRecs = b.be16(10);
        if (kind != -1) { node = fLink; continue; }        // not a leaf
        leaves++;

        for (u16 r = 0; r < numRecs; r++) {
            size_t offPos = nodeSize - (size_t)(r + 1) * 2;
            size_t recOff = b.be16(offPos);
            if (recOff < 14 || recOff >= nodeSize) continue;
            u16 keyLen = b.be16(recOff);
            if (keyLen < 6 || recOff + 2 + keyLen > nodeSize) continue;
            u32 parentID = b.be32(recOff + 2);
            u16 nameLen  = b.be16(recOff + 6);
            std::string name;
            if (nameLen && nameLen <= 255 && b.has(recOff + 8, (size_t)nameLen * 2))
                name = utf16beToUtf8(b.p + recOff + 8, (size_t)nameLen * 2);

            size_t dataOff = recOff + 2 + keyLen;
            dataOff = (dataOff + 1) & ~size_t(1);
            if (dataOff + 2 > nodeSize) continue;
            u16 recType = b.be16(dataOff);

            if (recType == 1) {                            // folder
                u32 id = b.be32(dataOff + 8);
                if (id && !name.empty() && catEntries < (i64)opt.max_files * 2) {
                    names[id] = name; parents[id] = parentID; catEntries++;
                }
            } else if (recType == 2) {                     // file
                if (dataOff + 248 > nodeSize) continue;
                u32 id = b.be32(dataOff + 8);
                if (id && !name.empty() && catEntries < (i64)opt.max_files * 2) {
                    names[id] = name; parents[id] = parentID; catEntries++;
                }
                ForkData dataFork = readFork(b, dataOff + 88);
                ForkData rsrcFork = readFork(b, dataOff + 168);

                RecoveredFile f;
                f.id = id;
                f.parent_id = parentID;
                f.name = name;
                f.size = (i64)dataFork.logical;
                f.alloc_size = (i64)dataFork.totalBlocks * blockSize;
                f.crtime = hfsTimeToUnix(b.be32(dataOff + 12));
                f.mtime  = hfsTimeToUnix(b.be32(dataOff + 16));
                f.ctime  = hfsTimeToUnix(b.be32(dataOff + 20));
                f.atime  = hfsTimeToUnix(b.be32(dataOff + 24));
                f.mode   = b.be16(dataOff + 32 + 8) & 0x0FFF;
                f.method = "catalog_btree_walk";
                for (int i = 0; i < 8; i++) {
                    if (!dataFork.extents[i].count) continue;
                    i64 off = (i64)dataFork.extents[i].start * blockSize;
                    i64 len = (i64)dataFork.extents[i].count * blockSize;
                    if (off < 0 || off >= volume) continue;
                    f.extents.push_back(Extent(off, len));
                }
                finalizeFile(f, volume);
                found.push_back(std::move(f));

                if (rsrcFork.logical > 0) {
                    RecoveredFile rf;
                    rf.id = id;
                    rf.parent_id = parentID;
                    rf.name = name + "/..namedfork/rsrc";
                    rf.size = (i64)rsrcFork.logical;
                    rf.is_adstream = true;
                    rf.method = "resource_fork";
                    for (int i = 0; i < 8; i++) {
                        if (!rsrcFork.extents[i].count) continue;
                        i64 off = (i64)rsrcFork.extents[i].start * blockSize;
                        i64 len = (i64)rsrcFork.extents[i].count * blockSize;
                        if (off < 0 || off >= volume) continue;
                        rf.extents.push_back(Extent(off, len));
                    }
                    finalizeFile(rf, volume);
                    found.push_back(std::move(rf));
                }
            }
        }
        node = fLink;
        if ((i64)found.size() >= opt.max_files) break;
    }
    res.bump("catalog_leaf_nodes", leaves);

    auto pathOf = [&](u32 id) -> std::string {
        std::vector<std::string> parts;
        u32 cur = id;
        int g = 0;
        while (cur > 2 && g++ < 128) {          // 2 = root folder
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

    for (auto& f : found) {
        f.path = pathOf((u32)f.id);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;
        if (f.is_adstream) f.path += "/..namedfork/rsrc";
        res.files.push_back(std::move(f));
    }
    res.technique("resource_fork_recovery");
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace hfs

// ===========================================================================
// APFS
// ===========================================================================
namespace apfs {
namespace {

constexpr u32 kObjTypeBtreeNode = 0x0003;
constexpr u32 kObjTypeBtreeRoot = 0x0002;
constexpr u32 kObjSubtypeFsTree = 0x0000000E;

constexpr u8 kJInode      = 3;
constexpr u8 kJFileExtent = 8;
constexpr u8 kJDirRec     = 9;

constexpr u16 kBtnodeRoot     = 0x0001;
constexpr u16 kBtnodeLeaf     = 0x0002;
constexpr u16 kBtnodeFixedKv  = 0x0004;

FileKind kindFromApfsMode(u16 mode) {
    switch (mode & 0xF000) {
        case 0x8000: return FileKind::Regular;
        case 0x4000: return FileKind::Directory;
        case 0xA000: return FileKind::Symlink;
        default:     return FileKind::Other;
    }
}

i64 apfsTimeToUnix(u64 nanos) { return (i64)(nanos / 1000000000ull); }

}  // namespace

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "apfs";
    const i64 volume = disk.size();

    auto nxRaw = disk.readBlock(0, 4096);
    Bytes nx(nxRaw);
    if (nxRaw.size() < 4096 || !nx.eq(32, "NXSB", 4)) {
        res.ok = false;
        res.error = "APFS container superblock (NXSB) not found";
        return res;
    }
    u32 blockSize = nx.le32(36);
    u64 blockCount = nx.le64(40);
    if (blockSize < 512 || blockSize > 65536 || (blockSize & (blockSize - 1))) blockSize = 4096;

    res.ok           = true;
    res.block_size   = blockSize;
    res.total_blocks = (i64)blockCount;
    res.volume_size  = volume;
    res.bump("container_block_size", blockSize);
    res.technique("fs_tree_leaf_sweep");
    res.technique("checkpoint_history_recovery");

    // Volume names live in the apfs_superblock (APSB) objects.
    prog.setPhase("locating APFS volumes");
    i64 scanLimit = volume;
    if (opt.max_scan_bytes > 0) scanLimit = std::min(scanLimit, opt.max_scan_bytes);

    struct Node {
        u16 mode = 0;
        u32 uid = 0, gid = 0, nlink = 0;
        u64 parent = 0;
        u64 size = 0;
        i64 crtime = 0, mtime = 0, ctime = 0, atime = 0;
        std::string name;
        std::vector<Extent> extents;
        bool haveInode = false;
    };
    std::unordered_map<u64, Node> objs;

    prog.setPhase("sweeping APFS B-tree leaves");
    prog.set(0, scanLimit);

    const i64 chunkSize = 4 * 1024 * 1024;
    std::vector<u8> chunk;
    i64 leaves = 0, records = 0;

    for (i64 base = 0; base < scanLimit && !prog.cancelled(); base += chunkSize) {
        prog.set(base, scanLimit);
        i64 want = std::min(chunkSize, scanLimit - base);
        chunk = disk.readBlock((u64)base, want);
        if (chunk.empty()) break;

        for (size_t bo = 0; bo + blockSize <= chunk.size(); bo += blockSize) {
            Bytes b(chunk.data() + bo, blockSize);
            u32 objType    = b.le32(24) & 0xFFFF;
            u32 objSubtype = b.le32(28);
            if (objType != kObjTypeBtreeNode && objType != kObjTypeBtreeRoot) continue;
            if (objSubtype != kObjSubtypeFsTree) continue;
            u16 flags = b.le16(32);
            if (!(flags & kBtnodeLeaf)) continue;
            u32 nkeys = b.le32(36);
            if (nkeys == 0 || nkeys > blockSize / 8) continue;
            u16 tocOff = b.le16(40);
            u16 tocLen = b.le16(42);
            const size_t kNodeDataStart = 56;
            size_t tocBase = kNodeDataStart + tocOff;
            size_t keyBase = tocBase + tocLen;
            size_t valBase = blockSize - ((flags & kBtnodeRoot) ? 40 : 0);
            bool fixed = (flags & kBtnodeFixedKv) != 0;
            if (keyBase >= blockSize) continue;
            leaves++;

            for (u32 i = 0; i < nkeys; i++) {
                size_t te = tocBase + (size_t)i * (fixed ? 4 : 8);
                if (!b.has(te, fixed ? 4u : 8u)) break;
                size_t kOff, kLen, vOff, vLen;
                if (fixed) {
                    kOff = b.le16(te); kLen = 16;
                    vOff = b.le16(te + 2); vLen = 16;
                } else {
                    kOff = b.le16(te); kLen = b.le16(te + 2);
                    vOff = b.le16(te + 4); vLen = b.le16(te + 6);
                }
                size_t kp = keyBase + kOff;
                if (vOff > valBase || kLen < 8 || vLen == 0) continue;
                size_t vp = valBase - vOff;
                if (!b.has(kp, kLen) || !b.has(vp, vLen)) continue;

                u64 keyHdr = b.le64(kp);
                u64 oid = keyHdr & 0x0FFFFFFFFFFFFFFFull;
                u8  jtype = (u8)(keyHdr >> 60);
                records++;

                if (jtype == kJInode) {
                    if (vLen < 92 || !b.has(vp, 92)) continue;
                    // Crafted trees can nominate an unbounded number of stub
                    // j_inodes; stop growing once the harvest is beyond the
                    // file cap the scan works to.
                    if (objs.find(oid) == objs.end() &&
                        objs.size() >= (size_t)opt.max_files * 2)
                        continue;
                    Node& n = objs[oid];
                    n.parent = b.le64(vp + 0);
                    n.crtime = apfsTimeToUnix(b.le64(vp + 16));
                    n.mtime  = apfsTimeToUnix(b.le64(vp + 24));
                    n.ctime  = apfsTimeToUnix(b.le64(vp + 32));
                    n.atime  = apfsTimeToUnix(b.le64(vp + 40));
                    n.nlink  = b.le32(vp + 56);
                    n.uid    = b.le32(vp + 72);
                    n.gid    = b.le32(vp + 76);
                    n.mode   = b.le16(vp + 80);
                    n.haveInode = true;
                } else if (jtype == kJDirRec) {
                    // key: hdr(8) + name_len_and_hash(4) + name
                    if (kLen < 12 || !b.has(kp + 8, 4)) continue;
                    u32 nlh = b.le32(kp + 8);
                    u32 nameLen = nlh & 0x3FF;
                    if (nameLen == 0 || nameLen > 512 || !b.has(kp + 12, nameLen)) continue;
                    std::string nm = b.str(kp + 12, nameLen);
                    while (!nm.empty() && nm.back() == '\0') nm.pop_back();
                    if (nm.empty()) continue;
                    if (vLen < 8 || !b.has(vp, 8)) continue;
                    u64 childId = b.le64(vp) & 0x0FFFFFFFFFFFFFFFull;
                    if (objs.find(childId) == objs.end() &&
                        objs.size() >= (size_t)opt.max_files * 2) continue;
                    Node& c = objs[childId];
                    if (c.name.empty()) { c.name = nm; c.parent = oid; }
                } else if (jtype == kJFileExtent) {
                    if (vLen < 24 || !b.has(vp, 24)) continue;
                    u64 lenAndFlags = b.le64(vp);
                    u64 len = lenAndFlags & 0x00FFFFFFFFFFFFFFull;
                    u64 physBlock = b.le64(vp + 8);
                    if (len == 0 || physBlock == 0) continue;
                    i64 off = (i64)(physBlock * blockSize);
                    if (off < 0 || off >= volume) continue;
                    if (objs.find(oid) == objs.end() &&
                        objs.size() >= (size_t)opt.max_files * 2) continue;
                    Node& n = objs[oid];
                    bool dup = false;
                    for (const auto& e : n.extents)
                        if (e.offset == off && e.length == (i64)len) { dup = true; break; }
                    if (!dup && n.extents.size() < 100000)
                        n.extents.push_back(Extent(off, (i64)len));
                }
            }
        }
    }
    res.bump("fs_tree_leaves", leaves);
    res.bump("j_records", records);

    prog.setPhase("assembling APFS objects");
    auto pathOf = [&](u64 id) -> std::string {
        std::vector<std::string> parts;
        u64 cur = id;
        int g = 0;
        while (cur != 2 && g++ < 128) {         // 2 = root directory
            auto it = objs.find(cur);
            if (it == objs.end() || it->second.name.empty()) break;
            parts.push_back(it->second.name);
            u64 par = it->second.parent;
            if (par == 0 || par == cur) break;
            cur = par;
        }
        if (parts.empty()) return {};
        std::string out;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) { out += '/'; out += *it; }
        return out;
    };

    for (auto& [oid, n] : objs) {
        if ((i64)res.files.size() >= opt.max_files) break;
        if (!n.haveInode && n.extents.empty()) continue;
        RecoveredFile f;
        f.id = oid;
        f.parent_id = n.parent;
        f.name = n.name.empty() ? ("oid_" + std::to_string(oid)) : n.name;
        f.uid = n.uid; f.gid = n.gid; f.mode = n.mode & 0x0FFF;
        f.nlink = n.nlink;
        f.mtime = n.mtime; f.ctime = n.ctime; f.atime = n.atime; f.crtime = n.crtime;
        f.kind = kindFromApfsMode(n.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = (n.haveInode && n.nlink == 0) || (!n.haveInode && !n.extents.empty());
        f.path = pathOf(oid);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;
        std::sort(n.extents.begin(), n.extents.end(),
                  [](const Extent& a, const Extent& b) { return a.offset < b.offset; });
        f.extents = n.extents;
        f.method = "fs_tree_leaf_sweep";
        i64 total = 0;
        for (const auto& e : f.extents) total += e.length;
        f.size = total;
        finalizeFile(f, volume);
        if (f.is_deleted) f.confidence = f.recoverable > 0 ? 0.7 : 0.2;
        res.files.push_back(std::move(f));
    }

    if (res.files.empty())
        res.error = "no APFS filesystem-tree records were readable — the container may be "
                    "FileVault-encrypted, in which case only carving of unlocked data will help";
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace apfs
}  // namespace ghost
