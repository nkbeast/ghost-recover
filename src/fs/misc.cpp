// GHOST//RECOVER — SquashFS, cramfs, romfs, MINIX, JFFS2, UFS/FFS, ReiserFS,
// JFS and ZFS.
//
// All of these were previously stubs that returned a filesystem name and an
// empty file list.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>
#include <vector>

#ifdef GHOST_HAVE_ZLIB
#include <zlib.h>
#endif

namespace ghost {

namespace {

FileKind kindFromPosixMode(u32 mode) {
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

#ifdef GHOST_HAVE_ZLIB
// Inflate a zlib stream; returns empty on failure.
std::vector<u8> inflateBuf(const u8* src, size_t srcLen, size_t expected) {
    std::vector<u8> out;
    if (srcLen == 0) return out;
    out.resize(expected ? expected : srcLen * 4);
    z_stream zs{};
    if (inflateInit(&zs) != Z_OK) return {};
    zs.next_in = const_cast<Bytef*>(src);
    zs.avail_in = (uInt)srcLen;
    size_t total = 0;
    int ret = Z_OK;
    while (true) {
        zs.next_out = out.data() + total;
        zs.avail_out = (uInt)(out.size() - total);
        ret = inflate(&zs, Z_NO_FLUSH);
        total = out.size() - zs.avail_out;
        if (ret == Z_STREAM_END) break;
        if (ret != Z_OK) { inflateEnd(&zs); return {}; }
        if (zs.avail_out == 0) {
            if (out.size() > 256u * 1024 * 1024) { inflateEnd(&zs); return {}; }
            out.resize(out.size() * 2);
        } else if (zs.avail_in == 0) {
            break;
        }
    }
    inflateEnd(&zs);
    out.resize(total);
    return out;
}
#endif

}  // namespace

// ===========================================================================
// SquashFS
// ===========================================================================
namespace squashfs {
namespace {

struct SqFs {
    DiskReader* d = nullptr;
    i64 volume = 0;
    u32 block_size = 131072;
    u16 compression = 1;      // 1 gzip, 2 lzma, 3 lzo, 4 xz, 5 lz4, 6 zstd
    u64 inode_table = 0, dir_table = 0, frag_table = 0;
    u64 root_inode_ref = 0;
    u32 inodes = 0;
    u64 bytes_used = 0;
    u16 major = 4;

    // Metadata is a chain of <=8 KiB blocks, each with a 2-byte header whose
    // top bit means "stored uncompressed".
    bool readMetaBlock(u64 offset, std::vector<u8>& out, u64& nextOffset) const {
        auto hdr = d->readBlock(offset, 2);
        if (hdr.size() < 2) return false;
        u16 h = (u16)(hdr[0] | (u16)hdr[1] << 8);
        bool uncompressed = (h & 0x8000) != 0;
        u16 size = h & 0x7FFF;
        if (size == 0 || size > 8192) return false;
        auto raw = d->readBlock(offset + 2, size);
        if (raw.size() < size) return false;
        nextOffset = offset + 2 + size;
        if (uncompressed) { out = std::move(raw); return true; }
#ifdef GHOST_HAVE_ZLIB
        if (compression == 1) {
            out = inflateBuf(raw.data(), raw.size(), 8192);
            return !out.empty();
        }
#endif
        return false;
    }

    // Reads `len` bytes of the metadata stream starting at (blockStart, offset).
    bool readMeta(u64 tableStart, u64 blockOff, u16 inBlock, size_t len,
                  std::vector<u8>& out) const {
        out.clear();
        u64 pos = tableStart + blockOff;
        u16 skip = inBlock;
        int guard = 0;
        while (out.size() < len && guard++ < 4096) {
            std::vector<u8> blk;
            u64 next = 0;
            if (!readMetaBlock(pos, blk, next)) return false;
            if (skip) {
                if (skip >= blk.size()) { skip -= (u16)blk.size(); pos = next; continue; }
                blk.erase(blk.begin(), blk.begin() + skip);
                skip = 0;
            }
            out.insert(out.end(), blk.begin(), blk.end());
            pos = next;
            if (pos >= (u64)volume) break;
        }
        // Metadata blocks are 8 KiB; the caller asked for a specific number of
        // bytes and must not see the records that follow, or a directory walk
        // runs straight on into the next directory's entries.
        if (out.size() > len) out.resize(len);
        return !out.empty();
    }
};

}  // namespace

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "squashfs";
    const i64 volume = disk.size();

    auto raw = disk.readBlock(0, 96);
    Bytes b(raw);
    if (raw.size() < 96 || !(b.eq(0, "hsqs", 4) || b.eq(0, "sqsh", 4))) {
        res.ok = false;
        res.error = "SquashFS superblock not found";
        return res;
    }

    SqFs fs;
    fs.d = &disk;
    fs.volume = volume;
    fs.inodes       = b.le32(4);
    fs.block_size   = b.le32(12);
    fs.compression  = b.le16(20);
    fs.major        = b.le16(28);
    fs.root_inode_ref = b.le64(32);
    fs.bytes_used   = b.le64(40);
    fs.inode_table  = b.le64(64);
    fs.dir_table    = b.le64(72);
    fs.frag_table   = b.le64(80);

    res.ok = true;
    res.block_size = fs.block_size;
    res.total_inodes = fs.inodes;
    res.volume_size = volume;
    res.bump("squashfs_version", fs.major);
    res.bump("compressor_id", fs.compression);
    res.technique("superblock_parse");

    static const char* kCompressors[] = {"?", "gzip", "lzma", "lzo", "xz", "lz4", "zstd"};
    std::string comp = (fs.compression < 7) ? kCompressors[fs.compression] : "unknown";

    if (fs.major != 4) {
        res.error = "only SquashFS 4.x is supported (image reports version " +
                    std::to_string(fs.major) + ")";
        return res;
    }
#ifndef GHOST_HAVE_ZLIB
    res.error = "SquashFS metadata is " + comp + "-compressed and this build has no "
                "decompressor; rebuild with zlib to list the archive contents";
    return res;
#else
    if (fs.compression != 1) {
        res.error = "SquashFS image uses the " + comp + " compressor; only gzip metadata can be "
                    "decoded by this build. Signature carving still applies to the image.";
        return res;
    }

    prog.setPhase("reading SquashFS fragment table");

    // Files smaller than the block size are packed into shared fragment blocks.
    // Without this table those files have no data at all, which is most of a
    // typical image.
    struct FragEntry { u64 start; u32 size; };
    std::vector<FragEntry> fragments;
    if (fs.frag_table && fs.frag_table < (u64)volume && b.le32(16) > 0) {
        u32 fragCount = b.le32(16);
        u32 indexes = (fragCount * 16 + 8191) / 8192;
        auto idxRaw = disk.readBlock(fs.frag_table, (i64)indexes * 8);
        Bytes ib2(idxRaw);
        for (u32 i = 0; i < indexes; i++) {
            u64 metaOff = ib2.le64((size_t)i * 8);
            std::vector<u8> blk;
            u64 next = 0;
            if (!fs.readMetaBlock(metaOff, blk, next)) break;
            Bytes fb(blk);
            for (size_t p = 0; p + 16 <= blk.size() && fragments.size() < fragCount; p += 16)
                fragments.push_back({fb.le64(p), fb.le32(p + 8)});
        }
        res.bump("fragments", (i64)fragments.size());
    }

    prog.setPhase("reading SquashFS inode table");

    // Walk the directory table, resolving each entry's inode.
    struct Entry { u64 ref; std::string path; bool isDir; };
    std::vector<Entry> queue;
    queue.push_back({fs.root_inode_ref, "", true});
    std::set<u64> visited;
    i64 filesFound = 0;

    auto readInode = [&](u64 ref, std::vector<u8>& out) -> bool {
        u64 blockOff = ref >> 16;
        u16 inBlock  = (u16)(ref & 0xFFFF);
        return fs.readMeta(fs.inode_table, blockOff, inBlock, 512, out) || !out.empty();
    };

    while (!queue.empty() && !prog.cancelled() && filesFound < opt.max_files) {
        Entry cur = queue.back();
        queue.pop_back();
        if (!visited.insert(cur.ref).second) continue;

        std::vector<u8> inodeBuf;
        if (!readInode(cur.ref, inodeBuf) || inodeBuf.size() < 32) continue;
        Bytes ib(inodeBuf);
        u16 type = ib.le16(0);
        if (type != 1 && type != 8) continue;             // directory / ext directory

        // squashfs_dir_inode_header:  start_block@16 nlink@20 file_size@24 offset@26 parent@28
        // squashfs_ldir_inode_header: nlink@16 file_size@20 start_block@24 parent@28 offset@34
        u32 startBlock, fileSize, parentIno;
        u16 offset;
        if (type == 1) {
            startBlock = ib.le32(16);
            fileSize   = ib.le16(24);
            offset     = ib.le16(26);
            parentIno  = ib.le32(28);
        } else {
            fileSize   = ib.le32(20);
            startBlock = ib.le32(24);
            parentIno  = ib.le32(28);
            offset     = ib.le16(34);
        }
        (void)parentIno;
        if (fileSize <= 3) continue;

        std::vector<u8> dirBuf;
        if (!fs.readMeta(fs.dir_table, startBlock, offset, fileSize - 3, dirBuf)) continue;
        Bytes db(dirBuf);

        size_t p = 0;
        while (p + 12 <= db.size()) {
            u32 count      = db.le32(p) + 1;
            u32 startBlk   = db.le32(p + 4);
            u32 inodeBase  = db.le32(p + 8);
            p += 12;
            if (count > 256) break;
            for (u32 i = 0; i < count && p + 8 <= db.size(); i++) {
                u16 entryOff = db.le16(p);
                i16 inodeDelta = (i16)db.le16(p + 2);
                u16 etype = db.le16(p + 4);
                u16 nameLen = db.le16(p + 6) + 1;
                p += 8;
                if (!db.has(p, nameLen)) { p = db.size(); break; }
                std::string name = db.str(p, nameLen);
                p += nameLen;

                u64 childRef = ((u64)startBlk << 16) | entryOff;
                std::string path = cur.path + "/" + name;
                bool isDir = (etype == 1 || etype == 8);
                if (isDir) { queue.push_back({childRef, path, true}); }

                std::vector<u8> cbuf;
                if (!readInode(childRef, cbuf) || cbuf.size() < 32) continue;
                Bytes cb(cbuf);
                u16 ctype = cb.le16(0);
                RecoveredFile f;
                f.id = inodeBase + (u32)inodeDelta;
                f.name = name;
                f.path = path;
                f.mode = cb.le16(2) & 0x0FFF;
                f.uid = cb.le16(4);
                f.gid = cb.le16(6);
                f.mtime = cb.le32(8);
                f.is_dir = isDir;
                f.kind = isDir ? FileKind::Directory : FileKind::Regular;
                f.method = "inode_table_walk";

                if (ctype == 2 || ctype == 9) {          // regular / ext regular
                    u64 blocksStart;
                    u64 fsize;
                    u32 fragIndex, fragOffset;
                    size_t blockListOff;
                    if (ctype == 2) {
                        blocksStart = cb.le32(16);
                        fragIndex   = cb.le32(20);
                        fragOffset  = cb.le32(24);
                        fsize       = cb.le32(28);
                        blockListOff = 32;
                    } else {
                        blocksStart = cb.le64(16);
                        fsize       = cb.le64(24);
                        fragIndex   = cb.le32(44);
                        fragOffset  = cb.le32(48);
                        blockListOff = 56;
                    }
                    f.size = (i64)fsize;
                    const bool hasFragment = (fragIndex != 0xFFFFFFFFu &&
                                              fragIndex < fragments.size());
                    u64 fullBlocks = hasFragment ? fsize / fs.block_size
                                                 : (fsize + fs.block_size - 1) / fs.block_size;
                    u64 pos = blocksStart;
                    bool anyCompressed = false;
                    for (u64 k = 0; k < fullBlocks && cb.has(blockListOff + k * 4, 4); k++) {
                        u32 sz = cb.le32(blockListOff + k * 4);
                        u32 realSize = sz & 0x00FFFFFF;
                        bool uncompressed = (sz & 0x01000000) != 0;
                        if (realSize == 0) continue;      // a hole: block of zeroes
                        if ((i64)pos < volume) f.extents.push_back(Extent((i64)pos, realSize));
                        if (!uncompressed) anyCompressed = true;
                        pos += realSize;
                    }
                    if (hasFragment) {
                        // The tail of the file lives inside a shared fragment
                        // block; record it so the extractor can pull it out.
                        const FragEntry& fe = fragments[fragIndex];
                        u32 realSize = fe.size & 0x00FFFFFF;
                        bool uncompressed = (fe.size & 0x01000000) != 0;
                        if (realSize && (i64)fe.start < volume) {
                            f.extents.push_back(Extent((i64)fe.start, realSize));
                            f.fragment_offset = (i64)fragOffset;
                            f.fragment_length = (i64)(fsize % fs.block_size);
                            if (f.fragment_length == 0) f.fragment_length = (i64)fsize;
                            if (!uncompressed) anyCompressed = true;
                        }
                    }
                    if (anyCompressed) {
                        f.is_compressed = true;
                        f.codec = "zlib-block";
                    }
                }
                finalizeFile(f, volume);
                res.files.push_back(std::move(f));
                filesFound++;
                if (filesFound >= opt.max_files) break;
            }
        }
    }

    res.technique("directory_table_walk");
    if (fs.frag_table) res.bump("fragment_table_present", 1);
    prog.setFound((i64)res.files.size());
    return res;
#endif
}

}  // namespace squashfs

// ===========================================================================
// cramfs
// ===========================================================================
namespace cramfs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "cramfs";
    const i64 volume = disk.size();

    auto raw = disk.readBlock(0, 128);
    Bytes b(raw);
    if (raw.size() < 76 || b.le32(0) != 0x28CD3D45) {
        res.ok = false;
        res.error = "cramfs superblock magic not found";
        return res;
    }
    res.ok = true;
    res.block_size = 4096;
    res.label = b.trimmed(48, 16);
    res.total_blocks = b.le32(40);
    res.total_inodes = b.le32(44);
    res.volume_size = volume;
    res.technique("superblock_parse");
    res.technique("inode_tree_walk");

    // cramfs_inode is a 12-byte bitfield: mode:16 uid:16 | size:24 gid:8 |
    // namelen:6 offset:26.
    struct CInode {
        u32 mode = 0, uid = 0, gid = 0, size = 0;
        u32 nameLen = 0, offset = 0;
    };
    auto readInode = [&](const Bytes& src, size_t p, CInode& out) -> bool {
        if (!src.has(p, 12)) return false;
        out.mode = src.le16(p);
        out.uid  = src.le16(p + 2);
        u32 w1 = src.le32(p + 4);
        out.size = w1 & 0x00FFFFFF;
        out.gid  = (w1 >> 24) & 0xFF;
        u32 w2 = src.le32(p + 8);
        out.nameLen = (w2 & 0x3F) * 4;
        out.offset  = (w2 >> 6) * 4;
        return true;
    };

    prog.setPhase("walking cramfs inodes");
    struct Pending { u32 dirOffset; u32 dirSize; std::string path; };
    std::vector<Pending> queue;
    {
        CInode root;
        if (!readInode(b, 64, root) || root.size == 0) {
            res.error = "cramfs root inode unreadable";
            return res;
        }
        queue.push_back({root.offset, root.size, ""});
    }

    std::set<u32> visited;
    i64 files = 0;
    while (!queue.empty() && !prog.cancelled() && files < opt.max_files) {
        Pending cur = queue.back();
        queue.pop_back();
        if (!visited.insert(cur.dirOffset).second) continue;
        auto dirBuf = disk.readBlock(cur.dirOffset, std::min<i64>(cur.dirSize, 16LL * 1024 * 1024));
        Bytes db(dirBuf);
        size_t p = 0;
        while (p + 12 <= db.size()) {
            CInode in;
            if (!readInode(db, p, in)) break;
            size_t nameOff = p + 12;
            if (!db.has(nameOff, in.nameLen)) break;
            std::string name = db.str(nameOff, in.nameLen);
            while (!name.empty() && name.back() == '\0') name.pop_back();
            p = nameOff + in.nameLen;
            if (name.empty()) continue;

            std::string path = cur.path + "/" + name;
            RecoveredFile f;
            f.id = in.offset;
            f.name = name;
            f.path = path;
            f.mode = in.mode & 0x0FFF;
            f.uid = in.uid; f.gid = in.gid;
            f.size = in.size;
            f.kind = kindFromPosixMode(in.mode);
            f.is_dir = f.kind == FileKind::Directory;
            f.method = "inode_tree_walk";

            if (f.is_dir) {
                if (in.size) queue.push_back({in.offset, in.size, path});
            } else if (f.kind == FileKind::Regular && in.size && in.offset) {
                // Data is a table of le32 block-end offsets followed by the
                // zlib-compressed 4 KiB blocks.
                u32 nblocks = (in.size + 4095) / 4096;
                auto tbl = disk.readBlock(in.offset, (i64)nblocks * 4);
                Bytes tb(tbl);
                u32 start = in.offset + nblocks * 4;
                for (u32 k = 0; k < nblocks && tb.has((size_t)k * 4, 4); k++) {
                    u32 end = tb.le32(k * 4);
                    if (end <= start) break;
                    if ((i64)start < volume) f.extents.push_back(Extent(start, end - start));
                    start = end;
                }
                f.is_compressed = true;
                f.codec = "zlib-block";
            }
            finalizeFile(f, volume);
            res.files.push_back(std::move(f));
            files++;
        }
    }
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace cramfs

// ===========================================================================
// romfs
// ===========================================================================
namespace romfs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "romfs";
    const i64 volume = disk.size();

    auto hdr = disk.readBlock(0, 512);
    Bytes h(hdr);
    if (hdr.size() < 32 || !h.eq(0, "-rom1fs-", 8)) {
        res.ok = false;
        res.error = "romfs signature not found";
        return res;
    }
    u32 fullSize = h.be32(8);
    // Volume name is NUL-terminated and padded to 16 bytes.
    std::string volName;
    for (size_t i = 16; i < hdr.size() && hdr[i]; i++) volName += (char)hdr[i];
    res.ok = true;
    res.label = volName;
    res.volume_size = volume;
    res.total_blocks = fullSize;
    res.technique("header_parse");
    res.technique("file_header_walk");

    u32 firstHeader = (u32)((16 + volName.size() + 1 + 15) & ~size_t(15));

    prog.setPhase("walking romfs entries");
    struct Pending { u32 off; std::string path; };
    std::vector<Pending> queue{{firstHeader, ""}};
    std::set<u32> visited;
    i64 files = 0;

    while (!queue.empty() && !prog.cancelled() && files < opt.max_files) {
        Pending cur = queue.back();
        queue.pop_back();
        u32 off = cur.off;
        int guard = 0;
        while (off && (i64)off + 16 <= volume && guard++ < 100000) {
            if (!visited.insert(off).second) break;
            auto e = disk.readBlock(off, 16);
            Bytes eb(e);
            if (e.size() < 16) break;
            u32 nextRaw = eb.be32(0);
            u32 next = nextRaw & ~0xFu;
            u32 type = nextRaw & 0x7;
            u32 spec = eb.be32(4);
            u32 size = eb.be32(8);

            std::string name;
            auto nameBuf = disk.readBlock(off + 16, 256);
            for (size_t i = 0; i < nameBuf.size() && nameBuf[i]; i++) name += (char)nameBuf[i];
            u32 namePadded = (u32)((name.size() + 1 + 15) & ~size_t(15));
            u32 dataOff = off + 16 + namePadded;

            if (!name.empty() && name != "." && name != "..") {
                std::string path = cur.path + "/" + name;
                RecoveredFile f;
                f.id = off;
                f.name = name;
                f.path = path;
                f.size = size;
                f.method = "file_header_walk";
                switch (type) {
                    case 1:                                  // directory
                        f.is_dir = true;
                        f.kind = FileKind::Directory;
                        if (spec) queue.push_back({spec, path});
                        break;
                    case 2:                                  // regular file
                        f.kind = FileKind::Regular;
                        if (size && (i64)dataOff < volume)
                            f.extents.push_back(Extent(dataOff, size));
                        break;
                    case 3:                                  // symlink
                        f.kind = FileKind::Symlink;
                        f.resident = disk.readBlock(dataOff, std::min<i64>(size, 4096));
                        break;
                    default:
                        f.kind = FileKind::Other;
                        break;
                }
                finalizeFile(f, volume);
                res.files.push_back(std::move(f));
                files++;
            }
            if (next == off) break;
            off = next;
        }
    }
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace romfs

// ===========================================================================
// MINIX
// ===========================================================================
namespace minixfs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "minix";
    const i64 volume = disk.size();
    const u32 kBlock = 1024;

    auto raw = disk.readBlock(1024, 64);
    Bytes b(raw);
    u16 magic = b.le16(0x10);
    int version = 0, nameLen = 14;
    if (magic == 0x137F)      { version = 1; nameLen = 14; }
    else if (magic == 0x138F) { version = 1; nameLen = 30; }
    else if (magic == 0x2468) { version = 2; nameLen = 14; }
    else if (magic == 0x2478) { version = 2; nameLen = 30; }
    else {
        res.ok = false;
        res.error = "MINIX superblock magic not recognised";
        return res;
    }

    u32 ninodes    = b.le16(0);
    u32 imapBlocks = b.le16(4);
    u32 zmapBlocks = b.le16(6);
    u32 firstData  = b.le16(8);
    u32 nzones     = (version == 2) ? b.le32(20) : b.le16(2);
    if (ninodes == 0 || imapBlocks == 0) {
        res.ok = false;
        res.error = "implausible MINIX superblock";
        return res;
    }

    res.ok = true;
    res.block_size = kBlock;
    res.total_inodes = ninodes;
    res.total_blocks = nzones;
    res.volume_size = volume;
    res.bump("minix_version", version);
    res.technique("superblock_parse");
    res.technique("inode_table_scan");

    const u32 inodeSize = (version == 2) ? 64 : 32;
    const u64 inodeTable = (u64)(2 + imapBlocks + zmapBlocks) * kBlock;
    (void)firstData;

    struct MInode {
        u16 mode = 0; u32 uid = 0, gid = 0, nlinks = 0;
        u64 size = 0; i64 mtime = 0, atime = 0, ctime = 0;
        std::vector<u32> zones;
    };
    std::unordered_map<u32, MInode> inodes;

    prog.setPhase("reading MINIX inodes");
    const u32 perRead = 256;
    for (u32 i = 0; i < ninodes; i += perRead) {
        if (prog.cancelled()) break;
        u32 count = std::min(perRead, ninodes - i);
        auto buf = disk.readBlock(inodeTable + (u64)i * inodeSize, (i64)count * inodeSize);
        Bytes ib(buf);
        for (u32 k = 0; k < count; k++) {
            size_t p = (size_t)k * inodeSize;
            if (!ib.has(p, inodeSize)) break;
            MInode in;
            if (version == 1) {
                in.mode = ib.le16(p + 0);
                if (in.mode == 0) continue;
                in.uid = ib.le16(p + 2);
                in.size = ib.le32(p + 4);
                in.mtime = ib.le32(p + 8);
                in.gid = ib.u8at(p + 12);
                in.nlinks = ib.u8at(p + 13);
                for (int z = 0; z < 9; z++) in.zones.push_back(ib.le16(p + 14 + (size_t)z * 2));
            } else {
                in.mode = ib.le16(p + 0);
                if (in.mode == 0) continue;
                in.nlinks = ib.le16(p + 2);
                in.uid = ib.le16(p + 4);
                in.gid = ib.le16(p + 6);
                in.size = ib.le32(p + 8);
                in.atime = ib.le32(p + 12);
                in.mtime = ib.le32(p + 16);
                in.ctime = ib.le32(p + 20);
                for (int z = 0; z < 10; z++) in.zones.push_back(ib.le32(p + 24 + (size_t)z * 4));
            }
            inodes[i + k + 1] = std::move(in);
        }
    }

    auto zonesToExtents = [&](const MInode& in, std::vector<Extent>& out) {
        const int direct = 7;   // both Minix v1 and v2 use seven direct zones
        for (int z = 0; z < direct && z < (int)in.zones.size(); z++) {
            u32 zn = in.zones[z];
            if (!zn) { out.push_back(Extent(0, kBlock, true)); continue; }
            i64 off = (i64)zn * kBlock;
            if (off < 0 || off >= volume) continue;
            if (!out.empty() && !out.back().sparse && out.back().offset + out.back().length == off)
                out.back().length += kBlock;
            else out.push_back(Extent(off, kBlock));
        }
        // Single indirect
        if ((int)in.zones.size() > direct && in.zones[direct]) {
            auto blk = disk.readBlock((u64)in.zones[direct] * kBlock, kBlock);
            Bytes bb(blk);
            u32 per = (version == 2) ? kBlock / 4 : kBlock / 2;
            for (u32 i = 0; i < per; i++) {
                u32 zn = (version == 2) ? bb.le32((size_t)i * 4) : bb.le16((size_t)i * 2);
                if (!zn) continue;
                i64 off = (i64)zn * kBlock;
                if (off < 0 || off >= volume) continue;
                if (!out.empty() && !out.back().sparse && out.back().offset + out.back().length == off)
                    out.back().length += kBlock;
                else out.push_back(Extent(off, kBlock));
            }
        }
    };

    // Directory pass for names and paths.
    prog.setPhase("walking MINIX directories");
    std::unordered_map<u32, std::string> names;
    std::unordered_map<u32, u32> parents;
    const u32 entSize = (u32)(2 + nameLen);
    for (const auto& [ino, in] : inodes) {
        if ((in.mode & 0xF000) != 0x4000) continue;
        std::vector<Extent> ex;
        zonesToExtents(in, ex);
        i64 budget = 0;
        for (const auto& e : ex) {
            if (e.sparse) continue;
            auto buf = disk.readBlock((u64)e.offset, std::min<i64>(e.length, 256 * 1024));
            Bytes db(buf);
            for (size_t p = 0; p + entSize <= db.size(); p += entSize) {
                u32 child = db.le16(p);
                if (!child) continue;
                std::string nm = db.str(p + 2, nameLen);
                while (!nm.empty() && nm.back() == '\0') nm.pop_back();
                if (nm.empty() || nm == "." || nm == "..") continue;
                names[child] = nm;
                parents[child] = ino;
            }
            budget += e.length;
            if (budget > 8LL * 1024 * 1024) break;
        }
    }
    res.technique("directory_walk");

    auto pathOf = [&](u32 ino) -> std::string {
        std::vector<std::string> parts;
        u32 cur = ino;
        int g = 0;
        while (cur != 1 && g++ < 128) {
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

    for (const auto& [ino, in] : inodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        RecoveredFile f;
        f.id = ino;
        auto nit = names.find(ino);
        f.name = (nit != names.end()) ? nit->second : ("inode_" + std::to_string(ino));
        f.path = pathOf(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;
        f.size = (i64)in.size;
        f.mode = in.mode & 0x0FFF;
        f.uid = in.uid; f.gid = in.gid; f.nlink = in.nlinks;
        f.mtime = in.mtime; f.atime = in.atime; f.ctime = in.ctime;
        f.kind = kindFromPosixMode(in.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = (in.nlinks == 0);
        f.method = f.is_deleted ? "orphan_inode_scan" : "inode_table_scan";
        zonesToExtents(in, f.extents);
        finalizeFile(f, volume);
        res.files.push_back(std::move(f));
    }
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace minixfs

// ===========================================================================
// JFFS2
// ===========================================================================
namespace jffs2 {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "jffs2";
    const i64 volume = disk.size();
    res.ok = true;
    res.volume_size = volume;
    res.technique("node_scan");
    res.technique("dirent_reassembly");

    constexpr u16 kMagic = 0x1985;
    constexpr u16 kDirent = 0xE001;
    constexpr u16 kInode  = 0xE002;

    struct Frag { u64 offset; u32 csize, dsize; u8 compr; };
    struct Node {
        std::string name;
        u32 pino = 0;
        u32 mode = 0, uid = 0, gid = 0;
        u64 size = 0;
        i64 mtime = 0, atime = 0, ctime = 0;
        u32 version = 0;
        bool deleted = false;
        std::vector<Frag> frags;
    };
    std::unordered_map<u32, Node> inodes;

    prog.setPhase("scanning JFFS2 nodes");
    const i64 chunkSize = 4LL * 1024 * 1024;
    i64 limit = volume;
    if (opt.max_scan_bytes > 0) limit = std::min(limit, opt.max_scan_bytes);
    prog.set(0, limit);
    i64 nodes = 0;

    for (i64 base = 0; base < limit && !prog.cancelled(); base += chunkSize) {
        prog.set(base, limit);
        auto chunk = disk.readBlock((u64)base, std::min(chunkSize, limit - base));
        if (chunk.empty()) break;
        Bytes b(chunk);
        size_t p = 0;
        while (p + 12 <= b.size()) {
            if (b.le16(p) != kMagic) { p += 4; continue; }
            u16 type = b.le16(p + 2);
            u32 totlen = b.le32(p + 4);
            if (totlen < 12 || totlen > 1024 * 1024 || p + totlen > b.size()) { p += 4; continue; }
            nodes++;

            if (type == kDirent && p + 40 <= b.size()) {
                u32 pino = b.le32(p + 12);
                u32 version = b.le32(p + 16);
                u32 ino = b.le32(p + 20);
                i64 mctime = b.le32(p + 24);
                u8  nsize = b.u8at(p + 28);
                if (nsize && b.has(p + 40, nsize)) {
                    std::string nm = b.str(p + 40, nsize);
                    Node& n = inodes[ino ? ino : pino];
                    if (ino == 0) {
                        // ino 0 in a dirent means the name was unlinked.
                        Node& dead = inodes[pino];
                        dead.deleted = true;
                        (void)dead;
                    } else if (version >= n.version) {
                        n.name = nm;
                        n.pino = pino;
                        n.version = version;
                        n.ctime = mctime;
                    }
                    (void)n;
                }
            } else if (type == kInode && p + 68 <= b.size()) {
                u32 ino = b.le32(p + 12);
                u32 version = b.le32(p + 16);
                u32 mode = b.le32(p + 20);
                u32 uid = b.le16(p + 24);
                u32 gid = b.le16(p + 26);
                u32 isize = b.le32(p + 28);
                i64 atime = b.le32(p + 32);
                i64 mtime = b.le32(p + 36);
                i64 ctime = b.le32(p + 40);
                u32 offset = b.le32(p + 44);
                u32 csize = b.le32(p + 48);
                u32 dsize = b.le32(p + 52);
                u8  compr = b.u8at(p + 56);
                Node& n = inodes[ino];
                if (version >= n.version || n.size == 0) {
                    n.mode = mode; n.uid = uid; n.gid = gid;
                    n.size = std::max<u64>(n.size, isize);
                    n.atime = atime; n.mtime = mtime; n.ctime = ctime;
                }
                if (csize && dsize) {
                    Frag fr;
                    fr.offset = (u64)(base + (i64)p + 68);
                    fr.csize = csize;
                    fr.dsize = dsize;
                    fr.compr = compr;
                    if (n.frags.size() < 100000) n.frags.push_back(fr);
                }
                (void)offset;
            }
            p += (totlen + 3) & ~size_t(3);
        }
    }
    res.bump("nodes_scanned", nodes);

    auto pathOf = [&](u32 ino) -> std::string {
        std::vector<std::string> parts;
        u32 cur = ino;
        int g = 0;
        while (cur != 1 && g++ < 128) {
            auto it = inodes.find(cur);
            if (it == inodes.end() || it->second.name.empty()) break;
            parts.push_back(it->second.name);
            u32 par = it->second.pino;
            if (!par || par == cur) break;
            cur = par;
        }
        if (parts.empty()) return {};
        std::string out;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) { out += '/'; out += *it; }
        return out;
    };

    for (auto& [ino, n] : inodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        RecoveredFile f;
        f.id = ino;
        f.name = n.name.empty() ? ("inode_" + std::to_string(ino)) : n.name;
        f.path = pathOf(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;
        f.parent_id = n.pino;
        f.size = (i64)n.size;
        f.mode = n.mode & 0x0FFF;
        f.uid = n.uid; f.gid = n.gid;
        f.mtime = n.mtime; f.atime = n.atime; f.ctime = n.ctime;
        f.kind = kindFromPosixMode(n.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = n.deleted;
        f.method = "node_scan";
        bool compressed = false;
        for (const auto& fr : n.frags) {
            if ((i64)fr.offset >= volume) continue;
            f.extents.push_back(Extent((i64)fr.offset, fr.csize));
            if (fr.compr != 0) compressed = true;
        }
        if (compressed) { f.is_compressed = true; f.codec = "zlib-block"; }
        finalizeFile(f, volume);
        res.files.push_back(std::move(f));
    }
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace jffs2

// ===========================================================================
// UFS / FFS (UFS1 and UFS2)
// ===========================================================================
namespace ufs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "ufs";
    const i64 volume = disk.size();

    u64 sbOff = 0;
    int version = 0;
    for (u64 off : {8192ull, 65536ull, 262144ull}) {
        auto raw = disk.readBlock(off, 0x600);
        Bytes b(raw);
        u32 magic = b.le32(0x55C);
        if (magic == 0x00011954) { sbOff = off; version = 1; break; }
        if (magic == 0x19540119) { sbOff = off; version = 2; break; }
    }
    if (!version) {
        res.ok = false;
        res.error = "UFS superblock magic not found at any standard offset";
        return res;
    }
    res.filesystem = version == 2 ? "ufs2" : "ufs";

    auto sbRaw = disk.readBlock(sbOff, 0x600);
    Bytes sb(sbRaw);
    u32 bsize = sb.le32(48);
    u32 fsize = sb.le32(52);
    u32 frag  = sb.le32(56);
    u32 ncg   = sb.le32(44);
    u32 ipg   = sb.le32(184);
    u32 fpg   = sb.le32(188);
    u32 iblkno = sb.le32(16);
    u32 cgoffset = sb.le32(36);
    u32 cgmask   = sb.le32(40);

    if (bsize < 512 || bsize > 65536 || ncg == 0 || ipg == 0 || fpg == 0) {
        res.ok = false;
        res.error = "implausible UFS superblock geometry";
        return res;
    }
    res.ok = true;
    res.block_size = bsize;
    res.total_inodes = (i64)ipg * ncg;
    res.volume_size = volume;
    res.bump("cylinder_groups", ncg);
    res.technique("superblock_parse");
    res.technique("cylinder_group_inode_scan");

    const u32 dinodeSize = version == 2 ? 256 : 128;
    auto cgstart = [&](u32 c) -> u64 {
        if (version == 2) return (u64)fpg * c;
        return (u64)fpg * c + (u64)(cgoffset * (c & ~cgmask));
    };

    struct UInode {
        u16 mode = 0; u32 uid = 0, gid = 0, nlink = 0;
        u64 size = 0; i64 atime = 0, mtime = 0, ctime = 0;
        std::vector<u64> db, ib;
    };
    std::unordered_map<u64, UInode> inodes;

    prog.setPhase("reading UFS inodes");
    prog.set(0, ncg);
    for (u32 c = 0; c < ncg && !prog.cancelled(); c++) {
        prog.set(c, ncg);
        u64 itableFrag = cgstart(c) + iblkno;
        u64 itableOff = itableFrag * fsize;
        for (u32 i = 0; i < ipg; i += 128) {
            u32 count = std::min<u32>(128, ipg - i);
            auto buf = disk.readBlock(itableOff + (u64)i * dinodeSize, (i64)count * dinodeSize);
            Bytes ib(buf);
            for (u32 k = 0; k < count; k++) {
                size_t p = (size_t)k * dinodeSize;
                if (!ib.has(p, dinodeSize)) break;
                UInode in;
                in.mode = ib.le16(p);
                if (in.mode == 0) continue;
                in.nlink = ib.le16(p + 2);
                if (version == 2) {
                    in.uid = ib.le32(p + 4);
                    in.gid = ib.le32(p + 8);
                    in.size = ib.le64(p + 16);
                    in.atime = (i64)ib.le64(p + 32);
                    in.mtime = (i64)ib.le64(p + 40);
                    in.ctime = (i64)ib.le64(p + 48);
                    for (int z = 0; z < 12; z++) in.db.push_back(ib.le64(p + 112 + (size_t)z * 8));
                    for (int z = 0; z < 3; z++)  in.ib.push_back(ib.le64(p + 208 + (size_t)z * 8));
                } else {
                    in.size = ib.le64(p + 8);
                    in.atime = ib.le32(p + 16);
                    in.mtime = ib.le32(p + 24);
                    in.ctime = ib.le32(p + 32);
                    for (int z = 0; z < 12; z++) in.db.push_back(ib.le32(p + 40 + (size_t)z * 4));
                    for (int z = 0; z < 3; z++)  in.ib.push_back(ib.le32(p + 88 + (size_t)z * 4));
                    in.uid = ib.le32(p + 112);
                    in.gid = ib.le32(p + 116);
                }
                if (in.size > (u64)volume) continue;
                inodes[(u64)c * ipg + k + i + 1] = std::move(in);
            }
        }
        if ((i64)inodes.size() > opt.max_files * 2) break;
    }

    auto blocksToExtents = [&](const UInode& in, std::vector<Extent>& out) {
        u64 remaining = in.size;
        for (u64 blk : in.db) {
            if (!remaining) break;
            i64 len = std::min<u64>(bsize, remaining);
            if (!blk) { out.push_back(Extent(0, len, true)); remaining -= len; continue; }
            i64 off = (i64)blk * fsize;
            if (off < 0 || off >= volume) break;
            out.push_back(Extent(off, len));
            remaining -= len;
        }
        // single indirect
        if (remaining && !in.ib.empty() && in.ib[0]) {
            auto blk = disk.readBlock((u64)in.ib[0] * fsize, bsize);
            Bytes bb(blk);
            u32 per = bsize / (version == 2 ? 8 : 4);
            for (u32 i = 0; i < per && remaining; i++) {
                u64 b2 = version == 2 ? bb.le64(i * 8) : bb.le32(i * 4);
                i64 len = std::min<u64>(bsize, remaining);
                if (!b2) { out.push_back(Extent(0, len, true)); remaining -= len; continue; }
                i64 off = (i64)b2 * fsize;
                if (off < 0 || off >= volume) break;
                out.push_back(Extent(off, len));
                remaining -= len;
            }
        }
        (void)frag;
    };

    prog.setPhase("walking UFS directories");
    std::unordered_map<u64, std::string> names;
    std::unordered_map<u64, u64> parents;
    for (const auto& [ino, in] : inodes) {
        if ((in.mode & 0xF000) != 0x4000) continue;
        std::vector<Extent> ex;
        blocksToExtents(in, ex);
        for (const auto& e : ex) {
            if (e.sparse) continue;
            auto buf = disk.readBlock((u64)e.offset, std::min<i64>(e.length, 256LL * 1024));
            Bytes db(buf);
            size_t p = 0;
            while (p + 8 <= db.size()) {
                u32 child = db.le32(p);
                u16 reclen = db.le16(p + 4);
                u8  namlen = db.u8at(p + 7);
                if (reclen < 8 || (reclen & 3) || p + reclen > db.size()) break;
                if (child && namlen && db.has(p + 8, namlen)) {
                    std::string nm = db.str(p + 8, namlen);
                    if (nm != "." && nm != "..") { names[child] = nm; parents[child] = ino; }
                }
                p += reclen;
            }
        }
    }
    res.technique("directory_walk");

    auto pathOf = [&](u64 ino) -> std::string {
        std::vector<std::string> parts;
        u64 cur = ino;
        int g = 0;
        while (cur != 2 && g++ < 128) {
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

    for (const auto& [ino, in] : inodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        RecoveredFile f;
        f.id = ino;
        auto nit = names.find(ino);
        f.name = (nit != names.end()) ? nit->second : ("inode_" + std::to_string(ino));
        f.path = pathOf(ino);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;
        f.size = (i64)in.size;
        f.mode = in.mode & 0x0FFF;
        f.uid = in.uid; f.gid = in.gid; f.nlink = in.nlink;
        f.mtime = in.mtime; f.atime = in.atime; f.ctime = in.ctime;
        f.kind = kindFromPosixMode(in.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = (in.nlink == 0);
        f.method = f.is_deleted ? "orphan_inode_scan" : "cylinder_group_inode_scan";
        blocksToExtents(in, f.extents);
        finalizeFile(f, volume);
        res.files.push_back(std::move(f));
    }
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace ufs

// ===========================================================================
// ReiserFS — leaf-node sweep
// ===========================================================================
namespace reiserfs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "reiserfs";
    const i64 volume = disk.size();

    u32 blockSize = 4096;
    bool found = false;
    for (u64 off : {0x10000ull, 0x2000ull}) {
        auto raw = disk.readBlock(off, 128);
        Bytes b(raw);
        if (b.eq(52, "ReIsErFs", 8) || b.eq(52, "ReIsEr2Fs", 9) || b.eq(52, "ReIsEr3Fs", 9)) {
            blockSize = b.le16(44);
            res.total_blocks = b.le32(0);
            res.free_blocks = b.le32(4);
            found = true;
            break;
        }
    }
    if (!found) {
        res.ok = false;
        res.error = "ReiserFS superblock not found";
        return res;
    }
    if (blockSize < 512 || blockSize > 65536) blockSize = 4096;

    res.ok = true;
    res.block_size = blockSize;
    res.volume_size = volume;
    res.technique("leaf_node_sweep");
    res.technique("stat_data_recovery");

    struct RNode {
        u32 mode = 0, nlink = 0, uid = 0, gid = 0;
        u64 size = 0;
        i64 atime = 0, mtime = 0, ctime = 0;
        std::string name;
        u32 parent = 0;
        std::vector<Extent> extents;
        std::vector<u8> direct;
        bool haveStat = false;
    };
    std::unordered_map<u32, RNode> objs;

    prog.setPhase("sweeping ReiserFS leaves");
    i64 limit = volume;
    if (opt.max_scan_bytes > 0) limit = std::min(limit, opt.max_scan_bytes);
    prog.set(0, limit);
    i64 leaves = 0;

    for (i64 off = 0; off + blockSize <= limit && !prog.cancelled(); off += blockSize) {
        if ((off % (64LL * 1024 * 1024)) == 0) prog.set(off, limit);
        auto raw = disk.readBlock((u64)off, blockSize);
        if ((i64)raw.size() < blockSize) break;
        Bytes b(raw);
        u16 level = b.le16(0);
        u16 nitems = b.le16(2);
        u16 freeSpace = b.le16(4);
        if (level != 1) continue;                       // only leaves carry items
        if (nitems == 0 || nitems > (blockSize - 24) / 24) continue;
        if (freeSpace > blockSize) continue;
        leaves++;

        for (u16 i = 0; i < nitems; i++) {
            size_t ih = 24 + (size_t)i * 24;
            if (!b.has(ih, 24)) break;
            u32 dirId    = b.le32(ih + 0);
            u32 objectId = b.le32(ih + 4);
            u32 offLo    = b.le32(ih + 8);
            u32 typeV1   = b.le32(ih + 12);
            u16 itemLen  = b.le16(ih + 18);
            u16 itemLoc  = b.le16(ih + 20);
            u16 version  = b.le16(ih + 22);
            if (itemLoc + itemLen > blockSize || itemLen == 0) continue;
            size_t data = itemLoc;

            int itype;
            u64 itemOffset;
            if (version == 0) {
                itemOffset = offLo;
                switch (typeV1) {
                    case 0: itype = 0; break;                      // stat data
                    case 0xFFFFFFFF: itype = 3; break;             // directory
                    case 0xFFFFFFFE: itype = 2; break;             // direct
                    default: itype = 1; break;                     // indirect
                }
            } else {
                u64 off64 = b.le64(ih + 8);
                itemOffset = off64 & 0x0FFFFFFFFFFFFFFFull;
                itype = (int)(off64 >> 60);
                // v2 type codes: 0 stat, 1 indirect, 2 direct, 3 directory
            }

            RNode& n = objs[objectId];
            if (itype == 0) {                            // stat data
                if (version == 0 && b.has(data, 32)) {
                    n.mode = b.le16(data);
                    n.nlink = b.le16(data + 2);
                    n.uid = b.le16(data + 4);
                    n.gid = b.le16(data + 6);
                    n.size = b.le32(data + 8);
                    n.atime = b.le32(data + 12);
                    n.mtime = b.le32(data + 16);
                    n.ctime = b.le32(data + 20);
                    n.haveStat = true;
                } else if (b.has(data, 44)) {
                    n.mode = b.le16(data);
                    n.nlink = b.le32(data + 4);
                    n.size = b.le64(data + 8);
                    n.uid = b.le32(data + 16);
                    n.gid = b.le32(data + 20);
                    n.atime = b.le32(data + 24);
                    n.mtime = b.le32(data + 28);
                    n.ctime = b.le32(data + 32);
                    n.haveStat = true;
                }
            } else if (itype == 1) {                     // indirect: block numbers
                for (size_t k = 0; k + 4 <= itemLen; k += 4) {
                    u32 blk = b.le32(data + k);
                    if (!blk) { n.extents.push_back(Extent(0, blockSize, true)); continue; }
                    i64 bo = (i64)blk * blockSize;
                    if (bo < 0 || bo >= volume) continue;
                    if (!n.extents.empty() && !n.extents.back().sparse &&
                        n.extents.back().offset + n.extents.back().length == bo)
                        n.extents.back().length += blockSize;
                    else n.extents.push_back(Extent(bo, blockSize));
                }
            } else if (itype == 2) {                     // direct: tail data inline
                if (b.has(data, itemLen) && itemOffset <= 8192) {
                    if (n.direct.size() < 65536)
                        n.direct.insert(n.direct.end(), b.p + data, b.p + data + itemLen);
                }
            } else if (itype == 3) {                     // directory entries
                u16 entryCount = b.le16(ih + 16);
                for (u16 e = 0; e < entryCount; e++) {
                    size_t deh = data + (size_t)e * 16;
                    if (!b.has(deh, 16)) break;
                    u32 childDir = b.le32(deh + 4);
                    u32 childObj = b.le32(deh + 8);
                    u16 loc = b.le16(deh + 12);
                    if (loc >= itemLen) continue;
                    size_t nameStart = data + loc;
                    size_t nameEnd = (e == 0) ? data + itemLen
                                              : data + b.le16(deh - 16 + 12);
                    if (nameEnd <= nameStart || nameEnd > data + itemLen) continue;
                    std::string nm = b.str(nameStart, nameEnd - nameStart);
                    while (!nm.empty() && nm.back() == '\0') nm.pop_back();
                    if (nm.empty() || nm == "." || nm == "..") continue;
                    RNode& c = objs[childObj];
                    if (c.name.empty()) { c.name = nm; c.parent = objectId; }
                    (void)childDir;
                }
            }
            (void)dirId;
        }
    }
    res.bump("leaf_nodes", leaves);

    auto pathOf = [&](u32 id) -> std::string {
        std::vector<std::string> parts;
        u32 cur = id;
        int g = 0;
        while (cur != 2 && g++ < 128) {
            auto it = objs.find(cur);
            if (it == objs.end() || it->second.name.empty()) break;
            parts.push_back(it->second.name);
            u32 par = it->second.parent;
            if (!par || par == cur) break;
            cur = par;
        }
        if (parts.empty()) return {};
        std::string out;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) { out += '/'; out += *it; }
        return out;
    };

    for (auto& [id, n] : objs) {
        if ((i64)res.files.size() >= opt.max_files) break;
        if (!n.haveStat && n.extents.empty() && n.direct.empty()) continue;
        RecoveredFile f;
        f.id = id;
        f.name = n.name.empty() ? ("object_" + std::to_string(id)) : n.name;
        f.path = pathOf(id);
        if (f.path.empty()) f.path = "/$orphans/" + f.name;
        f.parent_id = n.parent;
        f.size = (i64)n.size;
        f.mode = n.mode & 0x0FFF;
        f.uid = n.uid; f.gid = n.gid; f.nlink = n.nlink;
        f.mtime = n.mtime; f.atime = n.atime; f.ctime = n.ctime;
        f.kind = kindFromPosixMode(n.mode);
        f.is_dir = f.kind == FileKind::Directory;
        f.is_deleted = n.haveStat && n.nlink == 0;
        f.method = "leaf_node_sweep";
        if (!n.extents.empty()) f.extents = n.extents;
        else if (!n.direct.empty()) f.resident = n.direct;
        finalizeFile(f, volume);
        res.files.push_back(std::move(f));
    }
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace reiserfs

// ===========================================================================
// JFS
// ===========================================================================
namespace jfs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "jfs";
    const i64 volume = disk.size();

    auto raw = disk.readBlock(32768, 512);
    Bytes b(raw);
    if (raw.size() < 128 || !b.eq(0, "JFS1", 4)) {
        // Secondary superblock lives one aggregate block later.
        auto alt = disk.readBlock(65536, 512);
        if (alt.size() >= 128 && Bytes(alt).eq(0, "JFS1", 4)) {
            raw = alt;
            b = Bytes(raw);
            res.technique("secondary_superblock_recovery");
        } else {
            res.ok = false;
            res.error = "JFS superblock not found";
            return res;
        }
    }
    u32 bsize = b.le32(16);
    u64 size = b.le64(8);
    if (bsize < 512 || bsize > 65536) bsize = 4096;

    res.ok = true;
    res.block_size = bsize;
    res.total_blocks = (i64)size;
    res.label = b.trimmed(101, 16);
    res.volume_size = volume;
    res.technique("superblock_parse");
    res.technique("dinode_signature_scan");

    // JFS dinodes are 512 bytes and carry di_inostamp/di_number; scan the
    // volume for slots whose self-describing fields agree.
    prog.setPhase("scanning JFS inodes");
    i64 limit = volume;
    if (opt.max_scan_bytes > 0) limit = std::min(limit, opt.max_scan_bytes);
    prog.set(0, limit);

    const i64 chunkSize = 4LL * 1024 * 1024;
    i64 found = 0;
    for (i64 base = 0; base < limit && !prog.cancelled(); base += chunkSize) {
        prog.set(base, limit);
        auto chunk = disk.readBlock((u64)base, std::min(chunkSize, limit - base));
        if (chunk.empty()) break;
        Bytes cb(chunk);
        for (size_t p = 0; p + 512 <= chunk.size(); p += 512) {
            u32 inostamp = cb.le32(p + 0);
            u32 fileset  = cb.le32(p + 4);
            u32 number   = cb.le32(p + 8);
            u32 gen      = cb.le32(p + 12);
            // di_ixpxd occupies 16..23; size follows at 24, and the ownership
            // and mode fields sit after nblocks — reading them from 16/28/32/40
            // landed in the extent descriptor and never validated.
            u64 isize    = cb.le64(p + 24);
            u32 nlink    = cb.le32(p + 40);
            u32 uid      = cb.le32(p + 44);
            u32 gid      = cb.le32(p + 48);
            u32 mode     = cb.le32(p + 52);
            if (inostamp == 0 || number == 0 || number > (1u << 28)) continue;
            if (fileset != 16 && fileset != 0) continue;      // AGGREGATE_I / FILESYSTEM_I
            u16 fmt = mode & 0xF000;
            if (fmt != 0x8000 && fmt != 0x4000 && fmt != 0xA000) continue;
            if (isize > (u64)volume) continue;
            if (nlink > 65535) continue;
            (void)gen;

            RecoveredFile f;
            f.id = number;
            f.name = "inode_" + std::to_string(number);
            f.path = "/$jfs/" + f.name;
            f.size = (i64)isize;
            f.mode = mode & 0x0FFF;
            f.uid = uid; f.gid = gid; f.nlink = nlink;
            f.mtime = (i64)cb.le32(p + 72);   // di_mtime.tv_sec
            f.kind = kindFromPosixMode(mode);
            f.is_dir = f.kind == FileKind::Directory;
            f.is_deleted = (nlink == 0);
            f.method = "dinode_signature_scan";
            f.confidence = 0.6;

            // The xtree root sits at offset 0x100 in the dinode; leaf entries
            // are xad_t (16 bytes) with a 40-bit address and 24-bit length.
            size_t xtree = p + 0x100;
            u8 xflag = cb.u8at(xtree + 0);
            u16 nextIdx = cb.le16(xtree + 2);
            if ((xflag & 0x01) && nextIdx > 2 && nextIdx < 20) {   // XAD_LEAF
                for (u16 k = 2; k < nextIdx; k++) {
                    size_t xad = xtree + 16 + (size_t)k * 16;
                    if (!cb.has(xad, 16)) break;
                    u32 len = cb.le24(xad + 1);
                    u64 addr = ((u64)cb.le32(xad + 12)) | ((u64)cb.u8at(xad + 8) << 32);
                    if (!len || !addr) continue;
                    i64 off = (i64)(addr * bsize);
                    if (off < 0 || off >= volume) continue;
                    f.extents.push_back(Extent(off, (i64)len * bsize));
                }
            }
            finalizeFile(f, volume);
            res.files.push_back(std::move(f));
            if (++found >= opt.max_files) break;
        }
        if (found >= opt.max_files) break;
    }
    res.bump("dinodes_recovered", found);
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace jfs

// ===========================================================================
// ZFS
// ===========================================================================
namespace zfs {

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "zfs";
    const i64 volume = disk.size();
    res.volume_size = volume;

    // Four vdev labels: two at the front, two at the back.
    std::vector<u64> labelOffsets = {0, 0x40000};
    if (volume > 0x80000) {
        labelOffsets.push_back((u64)volume - 0x80000);
        labelOffsets.push_back((u64)volume - 0x40000);
    }

    i64 validLabels = 0;
    u64 bestTxg = 0;
    std::string poolName;
    for (u64 lbl : labelOffsets) {
        if ((i64)lbl + 0x4000 > volume) continue;
        // The name/value pair list sits at label+16 KiB and is XDR-encoded; the
        // pool name is easy to locate without a full nvlist decoder.
        auto nv = disk.readBlock(lbl + 0x4000, 8192);
        Bytes nb(nv);
        for (size_t i = 0; i + 8 < nv.size(); i++) {
            if (nb.eq(i, "name", 4) && nb.be32(i - 4) == 4) {
                u32 len = nb.be32(i + 8);
                if (len > 0 && len < 128 && nb.has(i + 16, len)) {
                    std::string cand = nb.str(i + 16, len);
                    bool printable = !cand.empty();
                    for (char c : cand) if (c < 0x20 || c > 0x7E) printable = false;
                    if (printable && poolName.empty()) poolName = cand;
                }
                break;
            }
        }
        bool any = false;
        for (int u = 0; u < 128; u++) {
            auto ub = disk.readBlock(lbl + 0x20000 + (u64)u * 1024, 64);
            Bytes b(ub);
            u64 magic = b.le64(0);
            u64 magicBe = b.be64(0);
            if (magic != 0x00bab10cULL && magicBe != 0x00bab10cULL) continue;
            u64 txg = (magic == 0x00bab10cULL) ? b.le64(16) : b.be64(16);
            if (txg > bestTxg) bestTxg = txg;
            any = true;
        }
        if (any) validLabels++;
    }

    if (validLabels == 0) {
        res.ok = false;
        res.error = "no valid ZFS vdev label with an uberblock was found";
        return res;
    }

    res.ok = true;
    res.label = poolName;
    res.bump("valid_vdev_labels", validLabels);
    res.bump("highest_txg", (i64)bestTxg);
    res.technique("vdev_label_parse");
    res.technique("uberblock_scan");
    // Be explicit rather than pretending: reconstructing files needs the DMU
    // object-set walk plus LZ4/gzip/ZSTD block decompression, which this engine
    // does not implement. Say so and point at what does work.
    res.error = "ZFS pool detected" + (poolName.empty() ? std::string() : (" ('" + poolName + "')")) +
                ". File-level metadata recovery requires a full DMU traversal, which this engine "
                "does not implement — import the pool read-only with 'zpool import -o readonly=on' "
                "to browse it, or run signature carving here to recover file contents directly "
                "from uncompressed blocks.";
    prog.setFound(0);
    (void)opt;
    return res;
}

}  // namespace zfs
}  // namespace ghost
