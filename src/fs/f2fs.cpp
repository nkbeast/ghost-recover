// GHOST//RECOVER — F2FS driver.
//
// Replaces a stub. F2FS is log-structured, so obsolete node blocks from before
// a delete are still sitting in the main area. Sweeping the main area for node
// blocks therefore recovers both live and deleted files, and F2FS conveniently
// stores the filename inside the inode itself, so names survive too.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <unordered_map>

namespace ghost {
namespace f2fs {

namespace {

constexpr u32 kMagic = 0xF2F52010;
constexpr size_t kAddrsPerInode = 923;
constexpr size_t kAddrsPerBlock = 1018;
constexpr size_t kInodeAddrOff  = 360;
constexpr size_t kInodeNidOff   = kInodeAddrOff + kAddrsPerInode * 4;   // 4052

struct F2fsSb {
    u32 blocksize = 4096;
    u32 log_blocks_per_seg = 9;
    u64 block_count = 0;
    u32 segment_count_main = 0;
    u32 main_blkaddr = 0;
    u32 segment0_blkaddr = 0;
    u32 root_ino = 3, node_ino = 1, meta_ino = 2;
    std::string label, uuid;
};

FileKind kindOf(u16 mode) {
    switch (mode & 0xF000) {
        case 0x8000: return FileKind::Regular;
        case 0x4000: return FileKind::Directory;
        case 0xA000: return FileKind::Symlink;
        default:     return FileKind::Other;
    }
}

}  // namespace

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "f2fs";

    F2fsSb sb;
    bool loaded = false;
    for (u64 sbOff : {1024ull, 4096ull + 1024ull}) {
        auto raw = disk.readBlock(sbOff, 1024);
        Bytes b(raw);
        if (raw.size() < 512 || b.le32(0) != kMagic) continue;
        u32 logBlockSize = b.le32(0x10);
        if (logBlockSize > 16) continue;
        sb.blocksize          = 1u << logBlockSize;
        sb.log_blocks_per_seg = b.le32(0x14);
        sb.block_count        = b.le64(0x24);
        sb.segment_count_main = b.le32(0x44);
        sb.segment0_blkaddr   = b.le32(0x48);
        sb.main_blkaddr       = b.le32(0x5C);
        sb.root_ino           = b.le32(0x60);
        sb.node_ino           = b.le32(0x64);
        sb.meta_ino           = b.le32(0x68);
        if (raw.size() >= 0x6C + 16) {
            const u8* g = raw.data() + 0x6C;
            char buf[40];
            snprintf(buf, sizeof(buf),
                     "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     g[0],g[1],g[2],g[3],g[4],g[5],g[6],g[7],g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
            sb.uuid = buf;
        }
        // volume_name is UTF-16LE
        if (raw.size() >= 0x7C + 64) sb.label = utf16leToUtf8(raw.data() + 0x7C, 64);
        if (sb.blocksize < 512 || sb.blocksize > 65536) continue;
        loaded = true;
        if (sbOff != 1024) {
            res.technique("backup_superblock_recovery");
            res.bump("superblock_recovered_from_backup", 1);
        }
        break;
    }
    if (!loaded) {
        res.ok = false;
        res.error = "F2FS superblock not found (neither copy)";
        return res;
    }

    res.ok           = true;
    res.block_size   = sb.blocksize;
    res.total_blocks = (i64)sb.block_count;
    res.label        = sb.label;
    res.uuid         = sb.uuid;
    res.volume_size  = disk.size();
    res.technique("node_block_sweep");
    res.technique("log_structured_stale_node_recovery");

    const i64 volume = disk.size();
    const size_t footerOff = sb.blocksize - 24;

    i64 mainStart = (i64)sb.main_blkaddr * sb.blocksize;
    if (mainStart <= 0 || mainStart >= volume) mainStart = 0;
    i64 mainEnd = volume;
    if (opt.max_scan_bytes > 0) mainEnd = std::min(mainEnd, mainStart + opt.max_scan_bytes);

    prog.setPhase("sweeping node blocks");
    prog.set(0, mainEnd - mainStart);

    struct Node {
        u16 mode = 0;
        u32 uid = 0, gid = 0, links = 0, pino = 0;
        u64 size = 0, blocks = 0;
        i64 atime = 0, ctime = 0, mtime = 0;
        std::string name;
        std::vector<u32> addrs;
        std::vector<u32> nids;
        u64 cpVer = 0;
        bool inlineData = false;
        std::vector<u8> inlineBytes;
    };
    std::unordered_map<u32, Node> inodes;   // ino -> newest node seen
    std::unordered_map<u32, std::vector<u32>> directNodes;   // nid -> addresses

    const i64 chunkSize = 4 * 1024 * 1024;
    std::vector<u8> chunk;
    i64 nodeBlocks = 0;

    for (i64 off = mainStart; off < mainEnd && !prog.cancelled(); off += chunkSize) {
        prog.set(off - mainStart, mainEnd - mainStart);
        i64 want = std::min(chunkSize, mainEnd - off);
        chunk = disk.readBlock((u64)off, want);
        if (chunk.empty()) break;
        Bytes cb(chunk);

        for (size_t bo = 0; bo + sb.blocksize <= chunk.size(); bo += sb.blocksize) {
            size_t f = bo + footerOff;
            if (!cb.has(f, 24)) break;
            u32 nid = cb.le32(f + 0);
            u32 ino = cb.le32(f + 4);
            u64 cpVer = cb.le64(f + 12);
            if (nid == 0 || ino == 0) continue;
            if (nid > (1u << 28) || ino > (1u << 28)) continue;

            if (nid != ino) {
                // Direct node: a flat array of block addresses.
                std::vector<u32> addrs;
                addrs.reserve(kAddrsPerBlock);
                bool any = false;
                for (size_t i = 0; i < kAddrsPerBlock; i++) {
                    u32 a = cb.le32(bo + i * 4);
                    addrs.push_back(a);
                    if (a) any = true;
                }
                if (any) directNodes[nid] = std::move(addrs);
                continue;
            }

            // Inode block.
            u16 mode = cb.le16(bo + 0);
            if (mode == 0) continue;
            u64 size = cb.le64(bo + 16);
            if (size > (u64)volume) continue;

            Node n;
            n.mode   = mode;
            n.uid    = cb.le32(bo + 4);
            n.gid    = cb.le32(bo + 8);
            n.links  = cb.le32(bo + 12);
            n.size   = size;
            n.blocks = cb.le64(bo + 24);
            n.atime  = (i64)cb.le64(bo + 32);
            n.ctime  = (i64)cb.le64(bo + 40);
            n.mtime  = (i64)cb.le64(bo + 48);
            n.pino   = cb.le32(bo + 84);
            n.cpVer  = cpVer;
            u32 namelen = cb.le32(bo + 88);
            if (namelen > 0 && namelen <= 255 && cb.has(bo + 92, namelen))
                n.name = cb.str(bo + 92, namelen);

            u8 inlineFlags = cb.u8at(bo + 3);
            const u8 kInlineData = 0x02;
            if (inlineFlags & kInlineData) {
                n.inlineData = true;
                size_t len = std::min<size_t>((size_t)size, kAddrsPerInode * 4 - 4);
                if (cb.has(bo + kInodeAddrOff + 4, len))
                    n.inlineBytes.assign(cb.p + bo + kInodeAddrOff + 4,
                                         cb.p + bo + kInodeAddrOff + 4 + len);
            } else {
                n.addrs.reserve(kAddrsPerInode);
                for (size_t i = 0; i < kAddrsPerInode; i++)
                    n.addrs.push_back(cb.le32(bo + kInodeAddrOff + i * 4));
                for (size_t i = 0; i < 5; i++)
                    n.nids.push_back(cb.le32(bo + kInodeNidOff + i * 4));
            }

            nodeBlocks++;
            auto it = inodes.find(ino);
            // Keep the newest checkpoint version, but never let a version with
            // no data replace one that has data.
            if (it == inodes.end() || cpVer >= it->second.cpVer) inodes[ino] = std::move(n);
        }
    }
    res.bump("inode_node_blocks", nodeBlocks);
    res.bump("direct_node_blocks", (i64)directNodes.size());

    // ---- assemble ---------------------------------------------------------
    prog.setPhase("assembling files");
    auto addrsToExtents = [&](const std::vector<u32>& addrs, std::vector<Extent>& out) {
        for (u32 a : addrs) {
            if (a == 0 || a == 0xFFFFFFFFu) { out.push_back(Extent(0, sb.blocksize, true)); continue; }
            i64 off = (i64)a * sb.blocksize;
            if (off < 0 || off >= volume) continue;
            if (!out.empty() && !out.back().sparse && out.back().offset + out.back().length == off)
                out.back().length += sb.blocksize;
            else out.push_back(Extent(off, sb.blocksize));
        }
    };

    std::unordered_map<u32, std::string> nameByIno;
    for (const auto& [ino, n] : inodes) if (!n.name.empty()) nameByIno[ino] = n.name;

    auto pathOf = [&](u32 ino) -> std::string {
        std::vector<std::string> parts;
        u32 cur = ino;
        int guard = 0;
        while (cur != sb.root_ino && guard++ < 128) {
            auto it = inodes.find(cur);
            if (it == inodes.end() || it->second.name.empty()) break;
            parts.push_back(it->second.name);
            u32 par = it->second.pino;
            if (par == 0 || par == cur) break;
            cur = par;
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
        f.name = n.name.empty() ? ("inode_" + std::to_string(ino)) : n.name;
        f.parent_id = n.pino;
        f.size = (i64)n.size;
        f.alloc_size = (i64)n.blocks * sb.blocksize;
        f.uid = n.uid; f.gid = n.gid; f.mode = n.mode & 0x0FFF;
        f.nlink = n.links;
        f.mtime = n.mtime; f.atime = n.atime; f.ctime = n.ctime;
        f.kind = kindOf(n.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = (n.links == 0);
        f.path = pathOf(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;

        if (n.inlineData) {
            f.resident = n.inlineBytes;
            f.method = "inline_data";
        } else {
            addrsToExtents(n.addrs, f.extents);
            for (size_t i = 0; i < n.nids.size(); i++) {
                u32 nid = n.nids[i];
                if (!nid) continue;
                auto dit = directNodes.find(nid);
                if (dit == directNodes.end()) continue;
                if (i < 2) {
                    addrsToExtents(dit->second, f.extents);   // direct node
                } else {
                    // Indirect: entries point at further direct nodes.
                    for (u32 sub : dit->second) {
                        if (!sub) continue;
                        auto sit = directNodes.find(sub);
                        if (sit != directNodes.end()) addrsToExtents(sit->second, f.extents);
                        if (f.extents.size() > 200000) break;
                    }
                }
                if (f.extents.size() > 200000) break;
            }
            f.method = "node_block_sweep";
        }
        finalizeFile(f, volume);
        if (f.is_deleted)
            f.confidence = (f.recoverable > 0 && f.size > 0)
                               ? std::min(1.0, (double)f.recoverable / (double)f.size) : 0.3;
        res.files.push_back(std::move(f));
    }

    prog.setFound((i64)res.files.size());
    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });
    return res;
}

}  // namespace f2fs
}  // namespace ghost
