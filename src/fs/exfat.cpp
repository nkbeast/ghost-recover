// GHOST RECOVER — exFAT driver.
//
// exFAT was previously routed into the FAT12/16/32 driver, which parsed the
// exFAT boot sector as a FAT BPB. Every field it read (bytes-per-sector,
// sectors-per-cluster, FAT size) is zero in exFAT, so the result was always an
// empty or nonsensical scan. exFAT is a different filesystem and gets its own
// driver.
//
// Deleted files recover well here: unlinking only clears the in-use bit of the
// directory entry type, so the stream-extension entry still carries the first
// cluster, the data length and the NoFatChain flag.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <unordered_set>
#include <vector>

namespace ghost {
namespace exfat {

namespace {

constexpr u8 kEntryFile      = 0x85;
constexpr u8 kEntryStream    = 0xC0;
constexpr u8 kEntryName      = 0xC1;
constexpr u8 kEntryBitmap    = 0x81;
constexpr u8 kEntryUpcase    = 0x82;
constexpr u8 kEntryVolLabel  = 0x83;
constexpr u8 kInUseBit       = 0x80;

struct ExFatFs {
    DiskReader* d = nullptr;
    i64 volume = 0;

    u32 bytes_per_sector = 512;
    u32 sectors_per_cluster = 8;
    u64 volume_length = 0;
    u32 fat_offset = 0, fat_length = 0;
    u32 heap_offset = 0, cluster_count = 0;
    u32 root_cluster = 0;
    u8  num_fats = 1;
    u8  percent_used = 0;
    std::string serial, label;
    std::vector<u8> fat;
    std::vector<u8> bitmap;
    u64 bitmap_clusters = 0;

    u32 clusterSize() const { return bytes_per_sector * sectors_per_cluster; }
    i64 clusterOffset(u64 c) const {
        if (c < 2) return -1;
        return (i64)(((u64)heap_offset + (c - 2) * sectors_per_cluster) * bytes_per_sector);
    }

    bool load(std::string* err) {
        auto raw = d->readBlock(0, 512);
        Bytes b(raw);
        if (raw.size() < 512 || !b.eq(3, "EXFAT   ", 8)) {
            if (err) *err = "not an exFAT volume";
            return false;
        }
        u8 bpsShift = b.u8at(0x6C);
        u8 spcShift = b.u8at(0x6D);
        if (bpsShift < 9 || bpsShift > 12) { if (err) *err = "bad BytesPerSectorShift"; return false; }
        if (spcShift > 25 - bpsShift)      { if (err) *err = "bad SectorsPerClusterShift"; return false; }
        bytes_per_sector    = 1u << bpsShift;
        sectors_per_cluster = 1u << spcShift;
        volume_length = b.le64(0x48);
        fat_offset    = b.le32(0x50);
        fat_length    = b.le32(0x54);
        heap_offset   = b.le32(0x58);
        cluster_count = b.le32(0x5C);
        root_cluster  = b.le32(0x60);
        num_fats      = b.u8at(0x6E);
        percent_used  = b.u8at(0x70);
        char sbuf[16];
        u32 ser = b.le32(0x64);
        snprintf(sbuf, sizeof(sbuf), "%04X-%04X", (ser >> 16) & 0xFFFF, ser & 0xFFFF);
        serial = sbuf;

        if (fat_offset == 0 || fat_length == 0 || cluster_count == 0 || root_cluster < 2) {
            if (err) *err = "implausible exFAT boot region";
            return false;
        }
        i64 fatBytes = std::min<i64>((i64)fat_length * bytes_per_sector, 512LL * 1024 * 1024);
        fat = d->readBlock((u64)fat_offset * bytes_per_sector, fatBytes);
        return true;
    }

    u32 fatEntry(u64 cluster) const {
        Bytes f(fat);
        return f.le32(cluster * 4);
    }

    std::vector<u64> chain(u64 first, u64 maxClusters) const {
        std::vector<u64> out;
        std::unordered_set<u64> seen;
        u64 cur = first;
        while (cur >= 2 && cur < (u64)cluster_count + 2 && out.size() < maxClusters) {
            if (!seen.insert(cur).second) break;
            out.push_back(cur);
            u32 next = fatEntry(cur);
            if (next == 0 || next == 0xFFFFFFFFu || next < 2) break;
            cur = next;
        }
        return out;
    }

    std::vector<u64> contiguous(u64 first, i64 size) const {
        std::vector<u64> out;
        if (first < 2 || size <= 0) return out;
        u64 need = ((u64)size + clusterSize() - 1) / clusterSize();
        // `size` comes from a 64-bit untrusted directory-entry field (up to
        // 2^63) and `need` can reach billions of clusters on paper — one u64
        // per cluster adds up to gigabytes. Real filesystems satisfy this with
        // far fewer clusters (a 4 MiB cluster gives 2^41 bytes of reach).
        // Cap the scan; the tail of an absurdly claimed run is dropped.
        if (need > (1ull << 22)) need = (1ull << 22);
        for (u64 i = 0; i < need && first + i < (u64)cluster_count + 2; i++)
            out.push_back(first + i);
        return out;
    }

    std::vector<Extent> toExtents(const std::vector<u64>& cl) const {
        std::vector<Extent> ex;
        for (u64 c : cl) {
            i64 off = clusterOffset(c);
            if (off < 0 || off >= volume) continue;
            i64 len = clusterSize();
            if (!ex.empty() && ex.back().offset + ex.back().length == off) ex.back().length += len;
            else ex.push_back(Extent(off, len));
        }
        return ex;
    }

    bool clusterFree(u64 c) const {
        if (bitmap.empty() || c < 2) return true;
        u64 idx = c - 2;
        size_t byte = (size_t)(idx / 8);
        if (byte >= bitmap.size()) return true;
        return !((bitmap[byte] >> (idx % 8)) & 1);
    }

    std::vector<u8> readClusters(const std::vector<u64>& cl, i64 maxBytes) const {
        std::vector<u8> out;
        for (u64 c : cl) {
            i64 off = clusterOffset(c);
            if (off < 0) break;
            auto part = d->readBlock((u64)off, clusterSize());
            out.insert(out.end(), part.begin(), part.end());
            if ((i64)out.size() >= maxBytes) break;
        }
        return out;
    }
};

}  // namespace

// ---------------------------------------------------------------------------

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "exfat";

    ExFatFs fs;
    fs.d = &disk;
    fs.volume = disk.size();

    std::string err;
    if (!fs.load(&err)) {
        // exFAT keeps a full backup boot region 12 sectors in.
        auto bk = disk.readBlock(12LL * 512, 512);
        if (bk.size() == 512 && Bytes(bk).eq(3, "EXFAT   ", 8)) {
            res.technique("backup_boot_region_recovery");
            res.bump("boot_region_recovered_from_backup", 1);
            Bytes b(bk);
            // The primary boot region already failed plausibility checks; apply
            // the same ones to the backup before using its shift counts, which
            // feed power-of-two computations.
            u8 bpsShift = b.u8at(0x6C);
            u8 spcShift = b.u8at(0x6D);
            if (bpsShift < 9 || bpsShift > 12 || spcShift > 25 - bpsShift) {
                res.ok = false; res.error = err; return res;
            }
            fs.bytes_per_sector    = 1u << bpsShift;
            fs.sectors_per_cluster = 1u << spcShift;
            fs.volume_length = b.le64(0x48);
            fs.fat_offset    = b.le32(0x50);
            fs.fat_length    = b.le32(0x54);
            fs.heap_offset   = b.le32(0x58);
            fs.cluster_count = b.le32(0x5C);
            fs.root_cluster  = b.le32(0x60);
            if (fs.fat_offset && fs.fat_length && fs.cluster_count && fs.root_cluster >= 2) {
                fs.fat = disk.readBlock((u64)fs.fat_offset * fs.bytes_per_sector,
                                        std::min<i64>((i64)fs.fat_length * fs.bytes_per_sector,
                                                      512LL << 20));
            } else {
                res.ok = false; res.error = err; return res;
            }
        } else {
            res.ok = false;
            res.error = err;
            return res;
        }
    }

    res.ok           = true;
    res.block_size   = fs.clusterSize();
    res.total_blocks = fs.cluster_count;
    res.uuid         = fs.serial;
    res.volume_size  = fs.volume;
    res.bump("cluster_size", fs.clusterSize());
    res.bump("percent_in_use", fs.percent_used);
    res.technique("directory_entry_set_walk");

    // ---- root directory: allocation bitmap, upcase table, volume label ----
    prog.setPhase("reading root directory");
    {
        auto rootChain = fs.chain(fs.root_cluster, 65536);
        auto rootBuf = fs.readClusters(rootChain, 4LL * 1024 * 1024);
        Bytes b(rootBuf);
        for (size_t i = 0; i + 32 <= b.size(); i += 32) {
            u8 type = b.u8at(i);
            if (type == 0) break;
            if (type == kEntryVolLabel) {
                u8 chars = b.u8at(i + 1);
                if (chars <= 11 && b.has(i + 2, (size_t)chars * 2))
                    res.label = utf16leToUtf8(b.p + i + 2, (size_t)chars * 2);
            } else if (type == kEntryBitmap) {
                u32 first = b.le32(i + 20);
                u64 len   = b.le64(i + 24);
                if (first >= 2 && len > 0 && len < 512ull * 1024 * 1024) {
                    auto cl = fs.chain(first, 1u << 20);
                    fs.bitmap = fs.readClusters(cl, (i64)len);
                    fs.bitmap.resize(std::min<size_t>(fs.bitmap.size(), (size_t)len));
                    res.technique("allocation_bitmap");
                }
            } else if (type == kEntryUpcase) {
                res.bump("upcase_table_present", 1);
            }
        }
        if (!fs.bitmap.empty()) {
            u64 free = 0;
            // Counting free clusters is diagnostic only; a corrupt bitmap can
            // claim billions of clusters, so cap the walk.
            u64 freeLimit = std::min((u64)fs.cluster_count + 2, (u64)1 << 26);
            for (u64 c = 2; c < freeLimit; c++) if (fs.clusterFree(c)) free++;
            res.free_blocks = (i64)free;
        }
    }

    // ---- walk the tree ----------------------------------------------------
    prog.setPhase("walking directories");
    struct Pending { u64 cluster; bool noFatChain; i64 length; std::string path; };
    std::vector<Pending> queue{{fs.root_cluster, false, 0, ""}};
    std::unordered_set<u64> visited;
    i64 filesFound = 0, deleted = 0;

    while (!queue.empty() && !prog.cancelled() && filesFound < opt.max_files) {
        Pending cur = queue.back();
        queue.pop_back();
        if (!visited.insert(cur.cluster).second) continue;

        std::vector<u64> cl = cur.noFatChain && cur.length > 0
                                  ? fs.contiguous(cur.cluster, cur.length)
                                  : fs.chain(cur.cluster, 65536);
        if (cl.empty()) continue;
        auto buf = fs.readClusters(cl, 16LL * 1024 * 1024);
        Bytes b(buf);

        size_t i = 0;
        while (i + 32 <= b.size()) {
            u8 type = b.u8at(i);
            if (type == 0x00) {
                if (!opt.slack) break;
                // Past the terminator lies slack that may still hold complete
                // deleted entry sets.
                i += 32;
                continue;
            }
            bool inUse = (type & kInUseBit) != 0;
            u8 base = type & 0x7F;

            if (base != (kEntryFile & 0x7F)) { i += 32; continue; }

            // A file is an entry *set*: 0x85 file entry, 0xC0 stream extension,
            // then 0xC1 name entries.
            u8 secondaryCount = b.u8at(i + 1);
            if (secondaryCount < 1 || secondaryCount > 18) { i += 32; continue; }
            u16 attrs = b.le16(i + 4);
            i64 ctime = fatTimeToUnix(b.le16(i + 10), b.le16(i + 8), b.u8at(i + 20));
            i64 mtime = fatTimeToUnix(b.le16(i + 14), b.le16(i + 12), b.u8at(i + 21));
            i64 atime = fatTimeToUnix(b.le16(i + 18), b.le16(i + 16), 0);

            size_t p = i + 32;
            u8  streamFlags = 0, nameLen = 0;
            u64 firstCluster = 0, dataLength = 0, validLength = 0;
            bool haveStream = false;
            std::vector<u8> nameUtf16;

            for (int s = 0; s < secondaryCount && p + 32 <= b.size(); s++, p += 32) {
                u8 t = b.u8at(p);
                u8 tb = t & 0x7F;
                // Only 0xC0 (stream) and 0xC1 (name) are legal secondaries. A
                // corrupt count would otherwise swallow whole following entry
                // sets — stop at the first non-secondary entry instead.
                if (tb != (kEntryStream & 0x7F) && tb != (kEntryName & 0x7F)) break;
                if (tb == (kEntryStream & 0x7F)) {
                    streamFlags  = b.u8at(p + 1);
                    nameLen      = b.u8at(p + 3);
                    validLength  = b.le64(p + 8);
                    firstCluster = b.le32(p + 20);
                    dataLength   = b.le64(p + 24);
                    haveStream = true;
                } else if (tb == (kEntryName & 0x7F)) {
                    for (int k = 0; k < 30; k++) nameUtf16.push_back(b.u8at(p + 2 + k));
                }
            }

            if (!haveStream) { i += 32; continue; }

            std::string name;
            if (!nameUtf16.empty()) {
                size_t want = std::min<size_t>((size_t)nameLen * 2, nameUtf16.size());
                name = utf16leToUtf8(nameUtf16.data(), want);
            }
            if (name.empty()) name = "entry_" + std::to_string(firstCluster);

            bool isDir = (attrs & 0x10) != 0;
            bool noFatChain = (streamFlags & 0x02) != 0;
            std::string path = cur.path + "/" + name;

            if (isDir && inUse && firstCluster >= 2) {
                queue.push_back({firstCluster, noFatChain, (i64)dataLength, path});
            }

            if (inUse && !opt.include_live) { i = p; continue; }

            RecoveredFile f;
            f.id = firstCluster;
            f.name = name;
            f.path = path;
            f.size = (i64)dataLength;
            f.alloc_size = (i64)dataLength;
            f.is_dir = isDir;
            f.kind = isDir ? FileKind::Directory : FileKind::Regular;
            f.is_deleted = !inUse;
            f.mtime = mtime; f.ctime = ctime; f.atime = atime; f.crtime = ctime;
            f.mode = (attrs & 0x01) ? 0444 : 0644;

            if (!isDir && firstCluster >= 2) {
                std::vector<u64> fcl;
                if (noFatChain) {
                    fcl = fs.contiguous(firstCluster, (i64)dataLength);
                    f.method = inUse ? "contiguous_stream" : "deleted_contiguous_stream";
                } else if (inUse) {
                    fcl = fs.chain(firstCluster, 1u << 22);
                    f.method = "fat_chain_walk";
                } else {
                    // The chain was released on delete; fall back to contiguous
                    // allocation, which exFAT overwhelmingly uses in practice.
                    fcl = fs.contiguous(firstCluster, (i64)dataLength);
                    f.method = "deleted_contiguous_heuristic";
                    f.confidence = 0.7;
                }
                f.extents = fs.toExtents(fcl);
                // ValidDataLength marks how much of the allocation was ever
                // written; the tail is uninitialised, so do not claim it.
                if (validLength > 0 && (i64)validLength < f.size) {
                    f.alloc_size = f.size;
                    f.size = (i64)validLength;
                    f.is_sparse = true;
                }
            }
            if (!inUse) {
                deleted++;
                if (f.confidence >= 1.0) f.confidence = 0.85;
            }

            finalizeFile(f, fs.volume);
            if (f.is_deleted && f.size > 0)
                f.confidence = std::min(f.confidence, (double)f.recoverable / (double)f.size);
            if (!pushFile(res, std::move(f), opt)) break;
            filesFound++;
            i = p;
        }
    }

    if (deleted) res.technique("deleted_entry_set_recovery");
    res.bump("deleted_entries", deleted);
    prog.setFound((i64)res.files.size());
    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });
    return res;
}

}  // namespace exfat
}  // namespace ghost
