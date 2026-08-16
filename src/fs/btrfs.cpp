// GHOST RECOVER — Btrfs driver.
//
// Replaces a stub. Parses the superblock (and its backups), bootstraps the
// chunk map from sys_chunk_array, walks the chunk tree to build a full
// logical->physical map, then harvests every metadata leaf in the volume.
//
// Sweeping the leaves rather than descending the live tree is deliberate: Btrfs
// is copy-on-write, so leaves from earlier generations are still on disk after
// a file is deleted. Reading them back is what recovers deleted files here,
// and it also survives a corrupted root tree.
#include "ghost/fs.h"

#include "ghost/decompress.h"
#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <unordered_map>
#include <vector>

namespace ghost {
namespace btrfs {

namespace {

constexpr u64 kSbOffsets[] = {0x10000ull, 0x4000000ull, 0x4000000000ull, 0x4000000000000ull};
constexpr size_t kHeaderSize = 101;
constexpr size_t kItemSize   = 25;

constexpr u8 kKeyInodeItem   = 1;
constexpr u8 kKeyInodeRef    = 12;
constexpr u8 kKeyInodeExtref = 13;
constexpr u8 kKeyDirItem     = 84;
constexpr u8 kKeyDirIndex    = 96;
constexpr u8 kKeyExtentData  = 108;
constexpr u8 kKeyRootItem    = 132;
constexpr u8 kKeyChunkItem   = 228;

constexpr u64 kBlockGroupSystem   = 1ull << 1;
constexpr u64 kBlockGroupMetadata = 1ull << 2;

struct ChunkMap {
    u64 logical = 0;
    u64 length = 0;
    u64 physical = 0;      // first stripe on this device
    u64 type = 0;
    u16 num_stripes = 1;
    u64 stripe_len = 65536;
};

struct BtrfsFs {
    DiskReader* d = nullptr;
    i64 volume = 0;
    u32 sectorsize = 4096, nodesize = 16384;
    u64 total_bytes = 0, bytes_used = 0;
    u64 root_logical = 0, chunk_root_logical = 0;
    u8  fsid[16] = {0};
    std::string label, uuid;
    std::vector<ChunkMap> chunks;

    i64 toPhysical(u64 logical) const {
        for (const auto& c : chunks) {
            // Subtraction form: c.logical + c.length could wrap u64 with a
            // hostile key/offset pair.
            if (logical >= c.logical && logical - c.logical < c.length)
                return (i64)(c.physical + (logical - c.logical));
        }
        return -1;
    }

    std::vector<u8> readLogical(u64 logical, i64 len) const {
        i64 phys = toPhysical(logical);
        if (phys < 0 || phys >= volume) return {};
        return d->readBlock((u64)phys, len);
    }

    bool loadSuper(std::string* err) {
        for (u64 off : kSbOffsets) {
            if ((i64)off + 4096 > volume) break;
            auto raw = d->readBlock(off, 4096);
            Bytes b(raw);
            if (raw.size() < 4096 || !b.eq(0x40, "_BHRfS_M", 8)) continue;

            std::memcpy(fsid, raw.data() + 0x20, 16);
            root_logical       = b.le64(0x50);
            chunk_root_logical = b.le64(0x58);
            total_bytes        = b.le64(0x70);
            bytes_used         = b.le64(0x78);
            sectorsize         = b.le32(0x90);
            nodesize           = b.le32(0x94);
            u32 sysArraySize   = b.le32(0xA0);
            label              = b.trimmed(0x12B, 256);
            {
                char buf[40];
                const u8* g = fsid;
                snprintf(buf, sizeof(buf),
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         g[0],g[1],g[2],g[3],g[4],g[5],g[6],g[7],g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
                uuid = buf;
            }
            if (nodesize < 4096 || nodesize > 65536) nodesize = 16384;
            if (sectorsize < 512 || sectorsize > 65536) sectorsize = 4096;

            // sys_chunk_array bootstraps just enough of the map to reach the
            // chunk tree itself.
            const size_t kSysArrayOff = 0x32B;
            if (sysArraySize > 2048) sysArraySize = 2048;
            size_t p = kSysArrayOff;
            size_t end = kSysArrayOff + sysArraySize;
            while (p + 17 + 48 <= end && p + 17 + 48 <= raw.size()) {
                u64 keyObj  = b.le64(p);
                u8  keyType = b.u8at(p + 8);
                u64 keyOff  = b.le64(p + 9);
                size_t cp = p + 17;
                if (keyType != kKeyChunkItem) break;
                ChunkMap cm;
                cm.logical     = keyOff;
                cm.length      = b.le64(cp + 0);
                cm.stripe_len  = b.le64(cp + 16);
                cm.type        = b.le64(cp + 24);
                cm.num_stripes = b.le16(cp + 44);
                if (cm.num_stripes == 0 || cm.num_stripes > 64) break;
                cm.physical    = b.le64(cp + 48 + 8);   // stripe[0].offset
                if (cm.length == 0 || cm.length > (u64)volume ||
                    cm.physical >= (u64)volume)
                    break;
                chunks.push_back(cm);
                p = cp + 48 + (size_t)cm.num_stripes * 32;
                (void)keyObj;
            }
            return true;
        }
        if (err) *err = "no valid Btrfs superblock found";
        return false;
    }

    // Descend the chunk tree so the map covers the whole volume.
    void loadChunkTree(Progress& prog) {
        std::vector<u64> stack{chunk_root_logical};
        std::vector<u64> seen;
        int guard = 0;
        while (!stack.empty() && guard++ < 100000 && !prog.cancelled()) {
            u64 logical = stack.back();
            stack.pop_back();
            if (logical == 0) continue;
            if (std::find(seen.begin(), seen.end(), logical) != seen.end()) continue;
            seen.push_back(logical);
            auto raw = readLogical(logical, nodesize);
            if (raw.size() < kHeaderSize) continue;
            Bytes b(raw);
            if (std::memcmp(raw.data() + 32, fsid, 16) != 0) continue;
            u32 nritems = b.le32(96);
            u8  level   = b.u8at(100);
            if (nritems > nodesize / 25) continue;

            if (level > 0) {
                for (u32 i = 0; i < nritems; i++) {
                    size_t p = kHeaderSize + (size_t)i * 33;
                    if (!b.has(p, 33)) break;
                    stack.push_back(b.le64(p + 17));
                }
                continue;
            }
            for (u32 i = 0; i < nritems; i++) {
                size_t p = kHeaderSize + (size_t)i * kItemSize;
                if (!b.has(p, kItemSize)) break;
                u8  type   = b.u8at(p + 8);
                u64 keyOff = b.le64(p + 9);
                u32 dataOff = b.le32(p + 17);
                u32 dataLen = b.le32(p + 21);
                if (type != kKeyChunkItem) continue;
                size_t cp = kHeaderSize + dataOff;
                if (!b.has(cp, 48) || dataLen < 48) continue;
                ChunkMap cm;
                cm.logical     = keyOff;
                cm.length      = b.le64(cp + 0);
                cm.stripe_len  = b.le64(cp + 16);
                cm.type        = b.le64(cp + 24);
                cm.num_stripes = b.le16(cp + 44);
                if (cm.num_stripes == 0 || cm.num_stripes > 64) continue;
                if (!b.has(cp + 48 + 8, 8)) continue;
                cm.physical = b.le64(cp + 48 + 8);
                if (cm.length == 0 || cm.length > (u64)volume ||
                    cm.physical >= (u64)volume)
                    continue;
                bool dup = false;
                for (const auto& e : chunks) if (e.logical == cm.logical) { dup = true; break; }
                if (!dup) chunks.push_back(cm);
            }
        }
        std::sort(chunks.begin(), chunks.end(),
                  [](const ChunkMap& a, const ChunkMap& b2) { return a.logical < b2.logical; });
    }
};

struct BInode {
    u64 size = 0, nbytes = 0;
    u32 nlink = 0, uid = 0, gid = 0, mode = 0;
    i64 atime = 0, ctime = 0, mtime = 0, otime = 0;
    u64 generation = 0;
    bool valid = false;
};

BInode parseInodeItem(const Bytes& b, size_t p) {
    BInode in;
    if (!b.has(p, 160)) return in;
    in.generation = b.le64(p + 0);
    in.size   = b.le64(p + 16);
    in.nbytes = b.le64(p + 24);
    in.nlink  = b.le32(p + 40);
    in.uid    = b.le32(p + 44);
    in.gid    = b.le32(p + 48);
    in.mode   = b.le32(p + 52);
    in.atime  = (i64)b.le64(p + 112);
    in.ctime  = (i64)b.le64(p + 124);
    in.mtime  = (i64)b.le64(p + 136);
    in.otime  = (i64)b.le64(p + 148);
    in.valid  = true;
    return in;
}

FileKind kindOf(u32 mode) {
    switch (mode & 0xF000) {
        case 0x8000: return FileKind::Regular;
        case 0x4000: return FileKind::Directory;
        case 0xA000: return FileKind::Symlink;
        default:     return FileKind::Other;
    }
}

// Btrfs compression algorithm ids: 1 = zlib, 2 = lzo, 3 = zstd.
const char* codecOf(u8 compression) {
    switch (compression) {
        case 1: return "btrfs-zlib";
        case 2: return "btrfs-lzo";
        case 3: return "btrfs-zstd";
        default: return nullptr;
    }
}

}  // namespace

// ---------------------------------------------------------------------------

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "btrfs";

    BtrfsFs fs;
    fs.d = &disk;
    fs.volume = disk.size();

    std::string err;
    if (!fs.loadSuper(&err)) {
        res.ok = false;
        res.error = err;
        return res;
    }
    prog.setPhase("mapping chunk tree");
    fs.loadChunkTree(prog);

    res.ok           = true;
    res.block_size   = fs.sectorsize;
    res.label        = fs.label;
    res.uuid         = fs.uuid;
    res.volume_size  = fs.volume;
    res.total_blocks = fs.total_bytes ? (i64)(fs.total_bytes / fs.sectorsize) : 0;
    res.free_blocks  = (fs.total_bytes > fs.bytes_used)
                           ? (i64)((fs.total_bytes - fs.bytes_used) / fs.sectorsize) : 0;
    res.bump("node_size", fs.nodesize);
    res.bump("chunks_mapped", (i64)fs.chunks.size());
    res.technique("chunk_tree_mapping");

    // ---- sweep every metadata leaf ---------------------------------------
    prog.setPhase("harvesting metadata leaves");

    struct Node {
        BInode in;
        std::string name;
        u64 parent = 0;
        std::vector<Extent> extents;
        std::vector<i64> decompSizes;   // parallel to extents for compressed files
        std::string codec;
        std::vector<u8> inlineData;
        u64 bestGeneration = 0;
        bool haveInode = false;
        bool stale = false;
    };
    std::unordered_map<u64, Node> inodes;
    std::unordered_map<u64, u64> latestGen;   // inode -> newest generation seen

    i64 leavesSeen = 0, staleLeaves = 0;
    i64 totalMetaBytes = 0;
    for (const auto& c : fs.chunks)
        if (c.type & (kBlockGroupMetadata | kBlockGroupSystem)) totalMetaBytes += (i64)c.length;
    prog.set(0, totalMetaBytes ? totalMetaBytes : 1);
    i64 scanned = 0;

    for (const auto& c : fs.chunks) {
        if (prog.cancelled()) break;
        if (!(c.type & (kBlockGroupMetadata | kBlockGroupSystem))) continue;

        for (u64 off = 0; off + fs.nodesize <= c.length; off += fs.nodesize) {
            if (prog.cancelled()) break;
            // Bounded like ext/xfs: stop harvesting leaves once the inode map
            // already holds more entries than the scan will ever report.
            if ((i64)inodes.size() >= (i64)opt.max_files * 2) break;
            scanned += fs.nodesize;
            if ((scanned % (16 * 1024 * 1024)) == 0) prog.set(scanned, totalMetaBytes);

            u64 physical = c.physical + off;
            // Unsigned bounds: (i64)physical + nodesize would be negative and
            // slip past a signed check when a hostile chunk maps near 2^63,
            // turning the sweep into a ~2^48-iteration spin on empty reads.
            if ((u64)fs.volume <= (u64)fs.nodesize ||
                physical > (u64)fs.volume - (u64)fs.nodesize)
                break;
            auto raw = disk.readBlock(physical, fs.nodesize);
            if (raw.size() < kHeaderSize) break;
            Bytes b(raw);
            if (std::memcmp(raw.data() + 32, fs.fsid, 16) != 0) continue;
            u64 bytenr = b.le64(48);
            if (bytenr != c.logical + off) continue;        // not a real node here
            u8 level = b.u8at(100);
            if (level != 0) continue;                       // interior node
            u32 nritems = b.le32(96);
            if (nritems == 0 || nritems > fs.nodesize / kItemSize) continue;
            u64 generation = b.le64(80);
            u64 owner = b.le64(88);
            leavesSeen++;

            for (u32 i = 0; i < nritems; i++) {
                size_t p = kHeaderSize + (size_t)i * kItemSize;
                if (!b.has(p, kItemSize)) break;
                u64 objectid = b.le64(p);
                u8  type     = b.u8at(p + 8);
                u64 keyoff   = b.le64(p + 9);
                u32 dataOff  = b.le32(p + 17);
                u32 dataLen  = b.le32(p + 21);
                size_t dp = kHeaderSize + dataOff;
                if (!b.has(dp, dataLen) || dataLen == 0) continue;

                switch (type) {
                    case kKeyInodeItem: {
                        BInode in = parseInodeItem(b, dp);
                        if (!in.valid) break;
                        auto& n = inodes[objectid];
                        auto git = latestGen.find(objectid);
                        bool newer = (git == latestGen.end() || generation >= git->second);
                        if (newer) {
                            latestGen[objectid] = generation;
                            n.in = in;
                            n.haveInode = true;
                            n.bestGeneration = generation;
                        } else if (!n.haveInode) {
                            n.in = in;
                            n.haveInode = true;
                            n.stale = true;
                        }
                        break;
                    }
                    case kKeyInodeRef: {
                        // key: objectid = inode, offset = parent directory
                        u16 nameLen = b.le16(dp + 8);
                        if (!b.has(dp + 10, nameLen) || nameLen == 0 || nameLen > 255) break;
                        auto& n = inodes[objectid];
                        if (n.name.empty()) {
                            n.name = b.str(dp + 10, nameLen);
                            n.parent = keyoff;
                        }
                        break;
                    }
                    case kKeyInodeExtref: {
                        u64 parent = b.le64(dp + 0);
                        u16 nameLen = b.le16(dp + 16);
                        if (!b.has(dp + 18, nameLen) || nameLen == 0) break;
                        auto& n = inodes[objectid];
                        if (n.name.empty()) { n.name = b.str(dp + 18, nameLen); n.parent = parent; }
                        break;
                    }
                    case kKeyDirItem:
                    case kKeyDirIndex: {
                        // location key -> child inode; name follows the header
                        u64 childIno = b.le64(dp + 0);
                        u16 nameLen  = b.le16(dp + 27);
                        u16 dataLen2 = b.le16(dp + 25);
                        if (nameLen == 0 || nameLen > 255) break;
                        if (!b.has(dp + 30, nameLen)) break;
                        (void)dataLen2;
                        auto& n = inodes[childIno];
                        if (n.name.empty()) {
                            n.name = b.str(dp + 30, nameLen);
                            n.parent = objectid;
                        }
                        break;
                    }
                    case kKeyExtentData: {
                        u8 extType = b.u8at(dp + 20);
                        auto& n = inodes[objectid];
                        if (extType == 0) {                 // inline
                            u8 compression = b.u8at(dp + 16);
                            u64 ramBytes = b.le64(dp + 8);
                            // A hostile inline item can claim gigabytes of
                            // decompressed data; real btrfs inline items are
                            // a few KiB, so anything past 16 MiB is bogus.
                            // (Unclamped, the zlib path would inflate up to
                            // its 512 MiB ceiling per inode.)
                            if (ramBytes > 16 * 1024 * 1024) break;
                            size_t len = dataLen > 21 ? dataLen - 21 : 0;
                            if (b.has(dp + 21, len) && n.inlineData.empty()) {
                                std::vector<u8> blob(b.p + dp + 21, b.p + dp + 21 + len);
                                if (compression == 0) {
                                    n.inlineData = std::move(blob);
                                } else {
                                    const char* codec = codecOf(compression);
                                    if (codec) {
                                        n.inlineData = decompressBlock(
                                            codec, blob.data(), blob.size(),
                                            (i64)ramBytes > 0 ? (i64)ramBytes : 0,
                                            fs.sectorsize);
                                    }
                                }
                            }
                            break;
                        }
                        if (!b.has(dp + 21, 32)) break;
                        u8 compression = b.u8at(dp + 16);
                        u64 diskBytenr  = b.le64(dp + 21);
                        u64 diskNumBytes = b.le64(dp + 29);
                        u64 extOffset  = b.le64(dp + 37);
                        u64 numBytes   = b.le64(dp + 45);
                        if (diskBytenr == 0 || numBytes == 0) break;   // hole
                        // Both fields are caller-controlled u64s. A crafted
                        // extent item may claim a blob of up to 16 EiB; the
                        // scan would allocate that at extract time. Real
                        // btrfs extents cap out around 128 KiB, so anything
                        // pasting 128 MiB (or 1 GiB decompressed) is bogus —
                        // refuse the extent.
                        if (diskNumBytes > 128 * 1024 * 1024 ||
                            numBytes > 1024 * 1024 * 1024) break;
                        if (compression != 0) {
                            // Compressed extent: the on-disk blob (diskNumBytes
                            // bytes) decompresses to numBytes. Decompression
                            // happens at extract time so huge extents are not
                            // inflated during the scan.
                            i64 phys = fs.toPhysical(diskBytenr);
                            if (phys < 0 || phys >= fs.volume) break;
                            const char* codec = codecOf(compression);
                            if (!codec) break;
                            if (n.codec.empty()) n.codec = codec;
                            else if (n.codec != codec) { n.codec.clear(); n.decompSizes.clear(); break; }
                            bool dup = false;
                            for (const auto& e : n.extents)
                                if (e.offset == phys && e.length == (i64)diskNumBytes) { dup = true; break; }
                            if (!dup) {
                                n.extents.push_back(Extent(phys, (i64)diskNumBytes));
                                n.decompSizes.push_back((i64)numBytes);
                            }
                            break;
                        }
                        // diskBytenr + extOffset can wrap u64 with hostile
                        // fields; clamp the sum to the volume before mapping.
                        if (diskBytenr > (u64)fs.volume ||
                            extOffset > (u64)fs.volume - diskBytenr)
                            break;
                        i64 phys = fs.toPhysical(diskBytenr + extOffset);
                        if (phys < 0 || phys >= fs.volume) break;
                        // Deduplicate: CoW means the same extent shows up in
                        // several generations of the tree.
                        bool dup = false;
                        for (const auto& e : n.extents)
                            if (e.offset == phys && e.length == (i64)numBytes) { dup = true; break; }
                        if (!dup) n.extents.push_back(Extent(phys, (i64)numBytes));
                        break;
                    }
                    case kKeyRootItem:
                    default:
                        break;
                }
            }
            (void)owner;
        }
    }
    res.technique("metadata_leaf_sweep");
    res.technique("cow_stale_leaf_recovery");
    res.bump("metadata_leaves_scanned", leavesSeen);
    res.bump("stale_generation_leaves", staleLeaves);

    // ---- assemble ---------------------------------------------------------
    prog.setPhase("reconstructing paths");
    auto pathOf = [&](u64 ino) -> std::string {
        std::vector<std::string> parts;
        u64 cur = ino;
        int guard = 0;
        while (cur != 256 && guard++ < 128) {         // 256 = FS tree root dir
            auto it = inodes.find(cur);
            if (it == inodes.end() || it->second.name.empty()) break;
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

    for (auto& [ino, n] : inodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        if (!n.haveInode && n.extents.empty() && n.inlineData.empty()) continue;

        RecoveredFile f;
        f.id = ino;
        f.name = n.name.empty() ? ("inode_" + std::to_string(ino)) : n.name;
        f.parent_id = n.parent;
        f.size = (i64)n.in.size;
        f.alloc_size = (i64)n.in.nbytes;
        f.uid = n.in.uid; f.gid = n.in.gid; f.mode = n.in.mode & 0x0FFF;
        f.nlink = n.in.nlink;
        f.mtime = n.in.mtime; f.atime = n.in.atime; f.ctime = n.in.ctime; f.crtime = n.in.otime;
        f.kind = kindOf(n.in.mode);
        f.is_dir = f.kind == FileKind::Directory;
        // nlink 0, or metadata only present in an older generation, means the
        // file is no longer live.
        f.is_deleted = (n.in.nlink == 0) || n.stale;
        f.path = pathOf(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;

        if (!n.inlineData.empty()) {
            f.resident = n.inlineData;
            f.method = "inline_extent";
        } else {
            // Sort by disk offset; keep the parallel decompression sizes in
            // step with their extents.
            std::vector<std::pair<Extent, i64>> zipped;
            zipped.reserve(n.extents.size());
            for (size_t i = 0; i < n.extents.size(); i++)
                zipped.push_back({n.extents[i],
                                  i < n.decompSizes.size() ? n.decompSizes[i] : 0});
            std::sort(zipped.begin(), zipped.end(),
                      [](const auto& a, const auto& b2) { return a.first.offset < b2.first.offset; });
            n.extents.clear();
            n.decompSizes.clear();
            for (auto& z : zipped) {
                n.extents.push_back(z.first);
                n.decompSizes.push_back(z.second);
            }
            f.extents = n.extents;
            if (!n.codec.empty()) {
                f.codec = n.codec;
                f.is_compressed = true;
                f.sectorsize = fs.sectorsize;
                f.decomp_sizes = n.decompSizes;
            }
            f.method = n.stale ? "cow_stale_leaf_recovery" : "extent_data_items";
        }
        finalizeFile(f, fs.volume);
        if (f.is_deleted)
            f.confidence = (f.recoverable > 0 && f.size > 0)
                               ? std::min(1.0, (double)f.recoverable / (double)f.size) : 0.25;
        if (!pushFile(res, std::move(f), opt)) break;
    }

    prog.setFound((i64)res.files.size());
    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });
    return res;
}

}  // namespace btrfs
}  // namespace ghost
