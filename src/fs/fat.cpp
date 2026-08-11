// GHOST//RECOVER — FAT12 / FAT16 / FAT32 / VFAT driver.
//
// The previous version read only the root directory, skipped every deleted
// entry with `continue` and then tested for the deleted marker in unreachable
// code, ignored long filenames entirely, never walked a FAT chain (it assumed
// every file was contiguous from its first cluster) and read the first-cluster
// field from the wrong offsets, mixing the high cluster word with the size.
//
// This driver walks the real FAT chains, reassembles long filenames, recurses
// through subdirectories, and recovers deleted entries — including brute-forcing
// the short name's first character from the long-name checksum, diffing the two
// FAT copies, mining directory slack and picking up orphaned cluster chains.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

namespace ghost {
namespace fat {

namespace {

constexpr u8 kAttrReadOnly  = 0x01;
constexpr u8 kAttrVolumeId  = 0x08;
constexpr u8 kAttrDirectory = 0x10;
constexpr u8 kAttrLfn       = 0x0F;

u8 shortNameChecksum(const u8* name11) {
    u8 sum = 0;
    for (int i = 0; i < 11; i++) sum = (u8)(((sum & 1) ? 0x80 : 0) + (sum >> 1) + name11[i]);
    return sum;
}

std::string formatShortName(const u8* raw, u8 ntFlags) {
    std::string base, ext;
    for (int i = 0; i < 8; i++) {
        char c = (char)raw[i];
        if (c == ' ') continue;
        base += (ntFlags & 0x08) ? (char)::tolower((unsigned char)c) : c;
    }
    for (int i = 8; i < 11; i++) {
        char c = (char)raw[i];
        if (c == ' ') continue;
        ext += (ntFlags & 0x10) ? (char)::tolower((unsigned char)c) : c;
    }
    if (base.empty() && ext.empty()) return {};
    return ext.empty() ? base : base + "." + ext;
}

struct FatFs {
    DiskReader* d = nullptr;
    i64  volume = 0;

    u16 bps = 512;
    u8  spc = 1;
    u16 reserved = 1;
    u8  num_fats = 2;
    u16 root_entries = 0;
    u64 total_sectors = 0;
    u32 fat_size = 0;
    u32 root_cluster = 0;
    int bits = 16;                     // 12, 16 or 32
    u64 cluster_count = 0;
    u64 data_start_sector = 0;
    u64 root_dir_sectors = 0;
    std::string label, serial;
    i64 free_clusters = -1;
    bool boot_backup_ok = false;

    std::vector<u8> fat1, fat2;

    u32 clusterSize() const { return (u32)bps * spc; }
    i64 clusterOffset(u64 cl) const {
        if (cl < 2) return -1;
        return (i64)((data_start_sector + (cl - 2) * spc) * bps);
    }

    bool load(std::string* err) {
        auto raw = d->readBlock(0, 512);
        Bytes b(raw);
        if (raw.size() < 512) { if (err) *err = "cannot read boot sector"; return false; }

        bps          = b.le16(11);
        spc          = b.u8at(13);
        reserved     = b.le16(14);
        num_fats     = b.u8at(16);
        root_entries = b.le16(17);
        u16 ts16     = b.le16(19);
        u32 ts32     = b.le32(32);
        total_sectors = ts16 ? ts16 : ts32;
        u16 fs16     = b.le16(22);
        u32 fs32     = b.le32(36);
        fat_size     = fs16 ? fs16 : fs32;
        root_cluster = b.le32(44);

        if (bps < 512 || bps > 4096 || (bps & (bps - 1))) { if (err) *err = "bad bytes-per-sector"; return false; }
        if (spc == 0 || spc > 128 || (spc & (spc - 1)))   { if (err) *err = "bad sectors-per-cluster"; return false; }
        if (reserved == 0 || num_fats == 0 || fat_size == 0 || total_sectors == 0) {
            if (err) *err = "implausible BPB";
            return false;
        }

        root_dir_sectors  = ((u64)root_entries * 32 + bps - 1) / bps;
        u64 meta          = (u64)reserved + (u64)num_fats * fat_size + root_dir_sectors;
        if (meta >= total_sectors) { if (err) *err = "BPB metadata exceeds volume"; return false; }
        data_start_sector = meta;
        cluster_count     = (total_sectors - meta) / spc;

        if (cluster_count < 4085)       bits = 12;
        else if (cluster_count < 65525) bits = 16;
        else                            bits = 32;

        label  = (bits == 32) ? b.trimmed(71, 11) : b.trimmed(43, 11);
        if (label == "NO NAME") label.clear();
        u32 ser = (bits == 32) ? b.le32(67) : b.le32(39);
        char sbuf[16];
        snprintf(sbuf, sizeof(sbuf), "%04X-%04X", (ser >> 16) & 0xFFFF, ser & 0xFFFF);
        serial = sbuf;

        // FAT32 keeps a boot-sector backup (usually sector 6) and an FSInfo
        // sector; both are useful diagnostics after damage.
        if (bits == 32) {
            u16 backupSector = b.le16(50);
            if (backupSector == 0 || backupSector > 32) backupSector = 6;
            auto bk = d->readBlock((u64)backupSector * bps, 512);
            boot_backup_ok = bk.size() == 512 && Bytes(bk).u8at(510) == 0x55 && Bytes(bk).u8at(511) == 0xAA;
            u16 fsinfoSector = b.le16(48);
            if (fsinfoSector) {
                auto fi = d->readBlock((u64)fsinfoSector * bps, 512);
                Bytes f(fi);
                if (f.le32(0) == 0x41615252 && f.le32(484) == 0x61417272) {
                    u32 fc = f.le32(488);
                    if (fc != 0xFFFFFFFFu) free_clusters = fc;
                }
            }
        }

        // Load both FAT copies; capped so a bogus fat_size cannot allocate GBs.
        i64 fatBytes = std::min<i64>((i64)fat_size * bps, 512LL * 1024 * 1024);
        fat1 = d->readBlock((u64)reserved * bps, fatBytes);
        if (num_fats > 1)
            fat2 = d->readBlock((u64)(reserved + fat_size) * bps, fatBytes);
        return true;
    }

    u32 fatEntry(const std::vector<u8>& fatbuf, u64 cluster) const {
        Bytes f(fatbuf);
        if (bits == 12) {
            u64 off = cluster + (cluster / 2);
            u16 v = f.le16(off);
            return (cluster & 1) ? (u32)(v >> 4) : (u32)(v & 0x0FFF);
        }
        if (bits == 16) return f.le16(cluster * 2);
        return f.le32(cluster * 4) & 0x0FFFFFFFu;
    }

    bool isEof(u32 e) const {
        if (bits == 12) return e >= 0x0FF8;
        if (bits == 16) return e >= 0xFFF8;
        return e >= 0x0FFFFFF8u;
    }
    bool isBad(u32 e) const {
        if (bits == 12) return e == 0x0FF7;
        if (bits == 16) return e == 0xFFF7;
        return e == 0x0FFFFFF7u;
    }

    // Follow a chain in the given FAT copy.
    std::vector<u64> chain(const std::vector<u8>& fatbuf, u64 first, u64 maxClusters) const {
        std::vector<u64> out;
        std::unordered_set<u64> seen;
        u64 cur = first;
        while (cur >= 2 && cur < cluster_count + 2 && out.size() < maxClusters) {
            if (!seen.insert(cur).second) break;             // loop in a damaged FAT
            out.push_back(cur);
            u32 next = fatEntry(fatbuf, cur);
            if (next == 0 || isEof(next) || isBad(next)) break;
            cur = next;
        }
        return out;
    }

    std::vector<Extent> clustersToExtents(const std::vector<u64>& cl) const {
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

    // A deleted file's FAT chain has been zeroed. Rebuild it by taking the
    // clusters that follow the start cluster and are still marked free. An
    // allocated cluster in the middle means the space was reused — the file
    // stops there rather than stepping over it, which would misalign every
    // subsequent extent; the result is flagged as fragmented.
    std::vector<u64> rebuildDeletedChain(u64 first, i64 size, bool* fragmented) const {
        std::vector<u64> out;
        if (first < 2 || size <= 0) return out;
        // A corrupt directory entry can claim a huge size; cap both the number
        // of clusters we want and how far we are willing to scan for them.
        const u64 kCapClusters = 1u << 24;             // ~64 GiB of data
        u64 need = std::min(kCapClusters, ((u64)size + clusterSize() - 1) / clusterSize());
        u64 cur = first;
        u64 scanned = 0;
        bool skipped = false;
        const u64 kMaxScan = std::min(kCapClusters * 8 + 64, (u64)1 << 26);
        while (out.size() < need && cur < cluster_count + 2 && scanned < kMaxScan) {
            u32 e = fatEntry(fat1, cur);
            if (e == 0 || out.empty()) {
                out.push_back(cur);
            } else {
                skipped = true;
                break;
            }
            cur++;
            scanned++;
        }
        if (fragmented) *fragmented = skipped;
        return out;
    }
};

// -------------------------------------------------------------------------
struct DirEntry {
    std::string name;
    std::string shortName;
    u8   attr = 0;
    u64  cluster = 0;
    i64  size = 0;
    i64  mtime = 0, ctime = 0, atime = 0;
    bool deleted = false;
    bool lfn_recovered = false;
    bool first_char_recovered = false;
    bool from_slack = false;
};

// Parses one directory buffer. LFN entries accumulate in reverse order ahead of
// their 8.3 entry; deleted entries keep their long-name characters, so the full
// original filename survives an unlink even though the 8.3 entry lost its first
// character.
void parseDirBuffer(const std::vector<u8>& buf, std::vector<DirEntry>& out, bool wantDeleted,
                    bool scanPastEnd, i64* lfnRecovered, i64* firstCharRecovered) {
    Bytes b(buf);
    std::vector<std::pair<u8, std::u16string>> lfnParts;   // (sequence, chars)
    u8  lfnChecksum = 0;
    bool lfnDeleted = false;
    bool ended = false;

    auto flushLfn = [&]() { lfnParts.clear(); lfnChecksum = 0; lfnDeleted = false; };

    auto assembleLfn = [&]() -> std::string {
        if (lfnParts.empty()) return {};
        std::sort(lfnParts.begin(), lfnParts.end(),
                  [](const auto& a, const auto& b2) { return a.first < b2.first; });
        std::u16string u;
        for (const auto& p : lfnParts) u += p.second;
        while (!u.empty() && (u.back() == 0xFFFF || u.back() == 0)) u.pop_back();
        std::vector<u8> raw;
        raw.reserve(u.size() * 2);
        for (char16_t c : u) { raw.push_back((u8)(c & 0xFF)); raw.push_back((u8)(c >> 8)); }
        return utf16leToUtf8(raw.data(), raw.size());
    };

    for (size_t i = 0; i + 32 <= b.size(); i += 32) {
        u8 first = b.u8at(i);
        if (first == 0x00) {
            ended = true;
            if (!scanPastEnd) break;
            // Past the end-of-directory marker is slack: entries that were
            // deleted and then overwritten by the terminator still sit here.
            continue;
        }
        u8 attr = b.u8at(i + 11);
        bool deleted = (first == 0xE5);

        if (attr == kAttrLfn) {
            // A deleted LFN entry has its sequence byte overwritten with 0xE5,
            // so ordering has to come from position instead. LFN entries are
            // stored in reverse (highest sequence first), so counting down from
            // 0xFF as they are encountered restores the original order while
            // still sorting after any surviving real sequence numbers.
            u8 seq = (u8)(first & 0x3F);
            if (deleted || seq == 0 || seq > 20)
                seq = (u8)(0xFF - std::min<size_t>(lfnParts.size(), 0x7F));
            std::u16string chars;
            const int offs[] = {1,3,5,7,9, 14,16,18,20,22,24, 28,30};
            for (int k = 0; k < 13; k++) {
                u16 c = b.le16(i + offs[k]);
                chars.push_back((char16_t)c);
            }
            if (lfnParts.empty()) {
                lfnChecksum = b.u8at(i + 13);
                lfnDeleted = deleted;
            }
            lfnParts.emplace_back(seq, chars);
            continue;
        }

        if (attr & kAttrVolumeId) { flushLfn(); continue; }
        if (deleted && !wantDeleted) { flushLfn(); continue; }

        u8 raw11[11];
        for (int k = 0; k < 11; k++) raw11[k] = b.u8at(i + k);

        DirEntry e;
        e.deleted   = deleted;
        e.attr      = attr;
        e.from_slack = ended;
        e.cluster   = ((u64)b.le16(i + 20) << 16) | b.le16(i + 26);
        e.size      = (i64)b.le32(i + 28);
        e.ctime     = fatTimeToUnix(b.le16(i + 16), b.le16(i + 14), b.u8at(i + 13));
        e.atime     = fatTimeToUnix(b.le16(i + 18), 0, 0);
        e.mtime     = fatTimeToUnix(b.le16(i + 24), b.le16(i + 22), 0);

        std::string longName = assembleLfn();
        bool lfnMatches = false;
        if (!longName.empty()) {
            u8 want = lfnChecksum;
            if (shortNameChecksum(raw11) == want) {
                lfnMatches = true;
            } else if (deleted) {
                // The 8.3 entry lost byte 0 to the 0xE5 marker. Recover it by
                // finding the byte that makes the checksum match the long name.
                for (int c = 1; c < 256; c++) {
                    u8 probe[11];
                    std::memcpy(probe, raw11, 11);
                    probe[0] = (u8)c;
                    if (shortNameChecksum(probe) == want) {
                        raw11[0] = (u8)c;
                        lfnMatches = true;
                        e.first_char_recovered = true;
                        if (firstCharRecovered) (*firstCharRecovered)++;
                        break;
                    }
                }
            }
        }

        e.shortName = formatShortName(raw11, b.u8at(i + 12));
        if (deleted && !e.first_char_recovered && !e.shortName.empty())
            e.shortName = "_" + e.shortName.substr(e.shortName[0] == '\xE5' ? 1 : 0);

        if (lfnMatches && !longName.empty()) {
            e.name = longName;
            e.lfn_recovered = true;
            if (lfnRecovered) (*lfnRecovered)++;
        } else {
            e.name = e.shortName;
        }
        if (e.name.empty()) { flushLfn(); continue; }
        if (e.name == "." || e.name == "..") { flushLfn(); continue; }

        out.push_back(std::move(e));
        flushLfn();
        (void)lfnDeleted;
    }
}

}  // namespace

// ---------------------------------------------------------------------------

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;

    FatFs fs;
    fs.d = &disk;
    fs.volume = disk.size();

    std::string err;
    if (!fs.load(&err)) {
        // Try the FAT32 backup boot sector before giving up.
        bool ok = false;
        for (u16 sec : {6, 12}) {
            auto bk = disk.readBlock((u64)sec * 512, 512);
            if (bk.size() == 512 && Bytes(bk).u8at(510) == 0x55 && Bytes(bk).u8at(511) == 0xAA) {
                // Reload using the backup by pointing a temporary window at it
                // is not possible in-place, so parse the backup fields directly.
                Bytes b(bk);
                fs.bps = b.le16(11); fs.spc = b.u8at(13); fs.reserved = b.le16(14);
                fs.num_fats = b.u8at(16); fs.root_entries = b.le16(17);
                u16 ts16 = b.le16(19); u32 ts32 = b.le32(32);
                fs.total_sectors = ts16 ? ts16 : ts32;
                u16 f16 = b.le16(22); u32 f32 = b.le32(36);
                fs.fat_size = f16 ? f16 : f32;
                fs.root_cluster = b.le32(44);
                if (fs.bps >= 512 && fs.spc > 0 && fs.fat_size && fs.total_sectors) {
                    fs.root_dir_sectors = ((u64)fs.root_entries * 32 + fs.bps - 1) / fs.bps;
                    fs.data_start_sector = (u64)fs.reserved + (u64)fs.num_fats * fs.fat_size +
                                           fs.root_dir_sectors;
                    if (fs.data_start_sector < fs.total_sectors) {
                        fs.cluster_count = (fs.total_sectors - fs.data_start_sector) / fs.spc;
                        fs.bits = fs.cluster_count < 4085 ? 12 : (fs.cluster_count < 65525 ? 16 : 32);
                        fs.fat1 = disk.readBlock((u64)fs.reserved * fs.bps,
                                                 std::min<i64>((i64)fs.fat_size * fs.bps, 512LL << 20));
                        if (fs.num_fats > 1)
                            fs.fat2 = disk.readBlock((u64)(fs.reserved + fs.fat_size) * fs.bps,
                                                     std::min<i64>((i64)fs.fat_size * fs.bps, 512LL << 20));
                        res.technique("volume_boot_sector_backup_recovery");
                        res.bump("boot_sector_recovered_from_backup", 1);
                        ok = true;
                    }
                }
            }
            if (ok) break;
        }
        if (!ok) { res.ok = false; res.error = err; res.filesystem = "fat"; return res; }
    }

    res.ok           = true;
    res.filesystem   = fs.bits == 12 ? "fat12" : (fs.bits == 16 ? "fat16" : "fat32");
    res.label        = fs.label;
    res.uuid         = fs.serial;
    res.block_size   = fs.clusterSize();
    res.total_blocks = (i64)fs.cluster_count;
    res.free_blocks  = fs.free_clusters;
    res.volume_size  = fs.volume;
    res.bump("cluster_size", fs.clusterSize());
    res.bump("fat_copies", fs.num_fats);
    if (fs.boot_backup_ok) res.bump("boot_sector_backup_present", 1);
    if (fs.free_clusters >= 0) res.bump("fsinfo_free_clusters", fs.free_clusters);
    res.technique("fat_chain_walk");

    // ---- diff the two FAT copies -----------------------------------------
    // Where they disagree, the second copy may still describe a chain that the
    // first has already released.
    std::vector<u8>* altFat = nullptr;
    if (!fs.fat2.empty() && fs.fat2.size() == fs.fat1.size()) {
        i64 diffs = 0;
        for (size_t i = 0; i < fs.fat1.size(); i++)
            if (fs.fat1[i] != fs.fat2[i]) diffs++;
        if (diffs) {
            res.technique("fat1_fat2_diff");
            res.bump("fat_copy_differences", diffs);
            altFat = &fs.fat2;
        }
    }

    // ---- walk the directory tree ------------------------------------------
    prog.setPhase("walking directories");
    struct PendingDir {
        u64 cluster;      // 0 = fixed root area (FAT12/16)
        std::string path;
    };
    std::vector<PendingDir> queue;
    std::unordered_set<u64> visitedDirs;

    if (fs.bits == 32) queue.push_back({fs.root_cluster ? fs.root_cluster : 2, ""});
    else               queue.push_back({0, ""});

    i64 lfnRecovered = 0, firstCharRecovered = 0, slackEntries = 0, deletedCount = 0;
    std::unordered_set<u64> referencedClusters;
    i64 filesFound = 0;

    while (!queue.empty() && !prog.cancelled() && filesFound < opt.max_files) {
        PendingDir cur = queue.back();
        queue.pop_back();

        std::vector<u8> buf;
        if (cur.cluster == 0) {
            u64 off = (u64)(fs.reserved + (u64)fs.num_fats * fs.fat_size) * fs.bps;
            buf = disk.readBlock(off, (i64)fs.root_dir_sectors * fs.bps);
        } else {
            if (!visitedDirs.insert(cur.cluster).second) continue;
            auto cl = fs.chain(fs.fat1, cur.cluster, 65536);
            if (cl.empty()) cl.push_back(cur.cluster);
            for (u64 c : cl) {
                referencedClusters.insert(c);
                i64 off = fs.clusterOffset(c);
                if (off < 0) continue;
                auto part = disk.readBlock((u64)off, fs.clusterSize());
                buf.insert(buf.end(), part.begin(), part.end());
                if (buf.size() > 8u * 1024 * 1024) break;
            }
        }
        if (buf.empty()) continue;

        std::vector<DirEntry> ents;
        parseDirBuffer(buf, ents, true, opt.slack, &lfnRecovered, &firstCharRecovered);

        for (auto& e : ents) {
            if (filesFound >= opt.max_files) break;
            if (e.from_slack) slackEntries++;

            std::string path = cur.path + "/" + e.name;
            if (e.attr & kAttrDirectory) {
                if (!e.deleted && e.cluster >= 2 && e.cluster < fs.cluster_count + 2)
                    queue.push_back({e.cluster, path});
                if (!opt.include_live && !e.deleted) continue;
                RecoveredFile f;
                f.id = e.cluster;
                f.name = e.name;
                f.path = path;
                f.is_dir = true;
                f.kind = FileKind::Directory;
                f.is_deleted = e.deleted;
                f.mtime = e.mtime; f.ctime = e.ctime; f.atime = e.atime;
                f.method = e.deleted ? "0xe5_deleted_marker" : "directory_walk";
                finalizeFile(f, fs.volume);
                res.files.push_back(std::move(f));
                filesFound++;
                if (e.deleted) deletedCount++;
                continue;
            }

            if (!e.deleted && !opt.include_live) continue;

            RecoveredFile f;
            f.id = e.cluster;
            f.name = e.name;
            f.path = path;
            f.size = e.size;
            f.is_deleted = e.deleted;
            f.mtime = e.mtime; f.ctime = e.ctime; f.atime = e.atime;
            f.mode = (e.attr & kAttrReadOnly) ? 0444 : 0644;

            if (!e.deleted) {
                auto cl = fs.chain(fs.fat1, e.cluster, 1u << 22);
                for (u64 c : cl) referencedClusters.insert(c);
                f.extents = fs.clustersToExtents(cl);
                f.method = "fat_chain_walk";
            } else {
                // An unlink clears the chain, but if the first entry still links
                // onwards the whole chain survived — follow it rather than the
                // free-cluster heuristic.
                std::vector<u64> cl;
                if (e.size > 0) {
                    cl = fs.chain(fs.fat1, e.cluster, 1u << 22);
                    i64 bytes = (i64)cl.size() * fs.clusterSize();
                    if (!cl.empty() && bytes >= e.size &&
                        bytes < e.size + (i64)fs.clusterSize() * 2) {
                        f.method = "fat1_chain_walk";
                        f.confidence = 0.9;
                    } else {
                        cl.clear();
                    }
                }
                // Try the alternate FAT copy next — its chain may be intact.
                if (cl.empty() && altFat) {
                    cl = fs.chain(*altFat, e.cluster, 1u << 22);
                    i64 bytes = (i64)cl.size() * fs.clusterSize();
                    if (!cl.empty() && e.size > 0 && bytes >= e.size &&
                        bytes < e.size + (i64)fs.clusterSize() * 2) {
                        f.method = "fat1_fat2_diff";
                        f.confidence = 0.85;
                    } else {
                        cl.clear();
                    }
                }
                if (cl.empty()) {
                    bool fragmented = false;
                    cl = fs.rebuildDeletedChain(e.cluster, e.size, &fragmented);
                    f.method = fragmented ? "contiguous_run_heuristic_with_gaps"
                                          : "contiguous_run_heuristic";
                    f.confidence = fragmented ? 0.45 : 0.7;
                }
                f.extents = fs.clustersToExtents(cl);
                if (e.lfn_recovered) f.method += "+lfn_reassembly";
                if (e.first_char_recovered) f.method += "+lfn_checksum_first_char";
                deletedCount++;
            }
            if (e.from_slack) {
                f.method += "+directory_slack";
                f.confidence = std::min(f.confidence, 0.4);
            }

            finalizeFile(f, fs.volume);
            if (f.is_deleted && f.size > 0)
                f.confidence = std::min(f.confidence, (double)f.recoverable / (double)f.size);
            res.files.push_back(std::move(f));
            filesFound++;
        }
    }

    if (lfnRecovered) { res.technique("lfn_reassembly"); res.bump("lfn_names_reassembled", lfnRecovered); }
    if (firstCharRecovered) {
        res.technique("lfn_checksum_first_char_recovery");
        res.bump("deleted_first_chars_recovered", firstCharRecovered);
    }
    if (slackEntries) {
        res.technique("directory_slack_carving");
        res.bump("slack_space_entries", slackEntries);
    }
    res.technique("0xe5_deleted_marker");

    // ---- orphaned cluster chains ------------------------------------------
    // Clusters that the FAT marks allocated but that no directory entry points
    // at — the usual signature of a directory whose parent entry was destroyed.
    if (opt.orphans && !prog.cancelled() && filesFound < opt.max_files) {
        prog.setPhase("scanning for orphaned chains");
        std::unordered_set<u64> chainStarts;
        for (u64 c = 2; c < fs.cluster_count + 2 && (i64)chainStarts.size() < 200000; c++) {
            u32 e = fs.fatEntry(fs.fat1, c);
            if (e == 0 || fs.isBad(e)) continue;
            if (referencedClusters.count(c)) continue;
            chainStarts.insert(c);
        }
        // A start-of-chain cluster is one that nothing else points to.
        std::unordered_set<u64> pointedTo;
        for (u64 c : chainStarts) {
            u32 e = fs.fatEntry(fs.fat1, c);
            if (e >= 2 && !fs.isEof(e) && !fs.isBad(e)) pointedTo.insert(e);
        }
        i64 orphans = 0;
        i64 bad = 0;
        for (u64 c : chainStarts) {
            if (filesFound >= opt.max_files) break;
            if (pointedTo.count(c)) continue;
            auto cl = fs.chain(fs.fat1, c, 1u << 20);
            if (cl.empty()) continue;
            RecoveredFile f;
            f.id = c;
            f.name = "orphan_cluster_" + std::to_string(c);
            f.path = "/$orphans/" + f.name;
            f.extents = fs.clustersToExtents(cl);
            f.size = (i64)cl.size() * fs.clusterSize();
            f.is_deleted = true;
            f.method = "orphaned_cluster_scan";
            f.confidence = 0.35;
            finalizeFile(f, fs.volume);
            res.files.push_back(std::move(f));
            filesFound++;
            orphans++;
        }
        // A damaged FAT can claim billions of clusters; counting bad ones is
        // diagnostic only, so do not walk more than 2^26 of them.
        u64 badLimit = std::min(fs.cluster_count + 2, (u64)1 << 26);
        for (u64 c = 2; c < badLimit; c++)
            if (fs.isBad(fs.fatEntry(fs.fat1, c))) bad++;
        if (orphans) { res.technique("orphaned_cluster_scan"); res.bump("orphan_chains", orphans); }
        if (bad) res.bump("bad_clusters", bad);
    }

    res.bump("deleted_entries", deletedCount);
    prog.setFound((i64)res.files.size());
    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });
    return res;
}

}  // namespace fat
}  // namespace ghost
