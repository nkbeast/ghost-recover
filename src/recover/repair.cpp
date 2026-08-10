// GHOST//RECOVER — filesystem and partition-table repair.
//
// The previous repair functions only ever *reported* that a backup existed —
// every one of them returned "restoring to primary" without writing a byte, so
// nothing was ever repaired. These do the analysis and, when the caller
// explicitly opts in with apply=true, perform the write, after saving the
// original sectors so the change can be undone.
#include "ghost/recover.h"

#include "ghost/disk.h"
#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <fstream>

#include <fcntl.h>
#include <unistd.h>

namespace ghost {

namespace {

// Opens the same target read-write. Kept separate from DiskReader so the read
// path can never accidentally acquire write access.
class Writer {
public:
    Writer(const std::string& path, u64 base) : path_(path), base_(base) {}
    ~Writer() { if (fd_ >= 0) ::close(fd_); }

    bool open(std::string* err) {
        fd_ = ::open(path_.c_str(), O_RDWR | O_LARGEFILE);
        if (fd_ < 0) {
            if (err) *err = "cannot open " + path_ + " for writing: " + std::strerror(errno) +
                            " (repair needs root and the volume must not be mounted)";
            return false;
        }
        return true;
    }

    bool write(u64 offset, const u8* data, size_t len, std::string* err) {
        size_t done = 0;
        while (done < len) {
            ssize_t n = ::pwrite(fd_, data + done, len - done, (off_t)(base_ + offset + done));
            if (n <= 0) {
                if (errno == EINTR) continue;
                if (err) *err = std::string("write failed: ") + std::strerror(errno);
                return false;
            }
            done += (size_t)n;
        }
        ::fsync(fd_);
        return true;
    }

private:
    std::string path_;
    u64 base_;
    int fd_ = -1;
};

bool saveBackup(const RepairOptions& opt, const std::string& tag, u64 offset,
                const std::vector<u8>& data, RepairResult& res) {
    if (!opt.backup) return true;
    std::string dir = opt.backup_dir.empty() ? joinPath(defaultOutputRoot(), "repair-backups")
                                             : opt.backup_dir;
    if (!makeDirs(dir)) {
        res.error = "cannot create backup directory: " + dir;
        return false;
    }
    std::string path = uniquePath(dir, tag + "_" + std::to_string(offset) + ".bin");
    std::ofstream f(path, std::ios::binary);
    if (!f) {
        res.error = "cannot write backup file: " + path;
        return false;
    }
    f.write(reinterpret_cast<const char*>(data.data()), (std::streamsize)data.size());
    res.steps.push_back("saved original " + std::to_string(data.size()) + " bytes to " + path);
    return true;
}

}  // namespace

// ---------------------------------------------------------------------------
RepairResult repairExtSuperblock(DiskReader& disk, const RepairOptions& opt) {
    RepairResult r;
    r.action = "ext_superblock_restore";

    auto primary = disk.readBlock(1024, 1024);
    Bytes p(primary);
    if (primary.size() >= 1024 && p.le16(0x38) == 0xEF53) {
        r.ok = true;
        r.detail = "primary superblock is intact — no repair needed";
        return r;
    }
    r.steps.push_back("primary superblock at offset 1024 has no 0xEF53 magic");

    // Backups live at the start of block groups 1, 3, 5, 7, 9, 25, 27, 49, 81...
    std::vector<u64> offsets;
    for (u32 bs : {1024u, 2048u, 4096u, 8192u, 16384u, 32768u, 65536u}) {
        u32 bpg = bs * 8;
        auto push = [&](u64 group) {
            u64 blk = group * bpg + (bs == 1024 ? 1 : 0);
            offsets.push_back(blk * bs);
        };
        push(1);
        for (u64 v = 3; v < (1u << 20); v *= 3) push(v);
        for (u64 v = 5; v < (1u << 20); v *= 5) push(v);
        for (u64 v = 7; v < (1u << 20); v *= 7) push(v);
    }
    std::sort(offsets.begin(), offsets.end());
    offsets.erase(std::unique(offsets.begin(), offsets.end()), offsets.end());

    for (u64 off : offsets) {
        if ((i64)off + 1024 > disk.size()) break;
        auto backup = disk.readBlock(off, 1024);
        Bytes b(backup);
        if (backup.size() < 1024 || b.le16(0x38) != 0xEF53) continue;
        // A backup superblock records its own group number; group 0 would mean
        // we found the primary again.
        u16 groupNr = b.le16(0x5A);
        r.detail = "found a valid backup superblock at offset " + std::to_string(off) +
                   " (block group " + std::to_string(groupNr) + ")";
        r.steps.push_back(r.detail);

        if (!opt.apply) {
            r.ok = true;
            r.detail += " — run with apply=true to copy it over the primary";
            return r;
        }

        std::vector<u8> fixed = backup;
        // The primary must claim block group 0.
        fixed[0x5A] = 0;
        fixed[0x5B] = 0;
        if (!saveBackup(opt, "ext_primary_superblock", 1024, primary, r)) return r;

        Writer w(disk.path(), disk.base());
        std::string err;
        if (!w.open(&err)) { r.error = err; return r; }
        if (!w.write(1024, fixed.data(), fixed.size(), &err)) { r.error = err; return r; }
        r.applied = true;
        r.ok = true;
        r.steps.push_back("wrote 1024 bytes to offset 1024");
        r.detail += " — restored. Run 'e2fsck -f' on the volume before mounting it.";
        return r;
    }

    r.error = "no valid ext backup superblock found";
    return r;
}

// ---------------------------------------------------------------------------
RepairResult repairFatBootSector(DiskReader& disk, const RepairOptions& opt) {
    RepairResult r;
    r.action = "fat_boot_sector_restore";

    auto primary = disk.readBlock(0, 512);
    Bytes p(primary);
    bool primaryOk = primary.size() >= 512 && p.u8at(510) == 0x55 && p.u8at(511) == 0xAA &&
                     p.le16(11) >= 512 && p.u8at(13) != 0;
    if (primaryOk) {
        r.ok = true;
        r.detail = "primary boot sector is intact — no repair needed";
        return r;
    }
    r.steps.push_back("primary boot sector is missing or implausible");

    // FAT32 records the backup location at offset 50; it is almost always
    // sector 6.
    for (u16 sector : {6, 12, 1}) {
        auto backup = disk.readBlock((u64)sector * 512, 512);
        Bytes b(backup);
        if (backup.size() < 512) continue;
        if (b.u8at(510) != 0x55 || b.u8at(511) != 0xAA) continue;
        if (b.le16(11) < 512 || b.u8at(13) == 0) continue;
        r.detail = "found a valid backup boot sector at sector " + std::to_string(sector);
        r.steps.push_back(r.detail);

        if (!opt.apply) {
            r.ok = true;
            r.detail += " — run with apply=true to copy it to sector 0";
            return r;
        }
        if (!saveBackup(opt, "fat_boot_sector", 0, primary, r)) return r;
        Writer w(disk.path(), disk.base());
        std::string err;
        if (!w.open(&err)) { r.error = err; return r; }
        if (!w.write(0, backup.data(), backup.size(), &err)) { r.error = err; return r; }
        r.applied = true;
        r.ok = true;
        r.steps.push_back("wrote 512 bytes to sector 0");
        r.detail += " — restored. Run 'fsck.vfat -a' before mounting.";
        return r;
    }

    r.error = "no valid FAT backup boot sector found at sector 6, 12 or 1";
    return r;
}

// ---------------------------------------------------------------------------
RepairResult repairExfatBootRegion(DiskReader& disk, const RepairOptions& opt) {
    RepairResult r;
    r.action = "exfat_boot_region_restore";

    auto primary = disk.readBlock(0, 512);
    if (primary.size() >= 512 && Bytes(primary).eq(3, "EXFAT   ", 8)) {
        r.ok = true;
        r.detail = "primary exFAT boot region is intact";
        return r;
    }
    // exFAT mirrors the whole 12-sector boot region at sector 12.
    auto backup = disk.readBlock(12 * 512, 12 * 512);
    if (backup.size() < 12 * 512 || !Bytes(backup).eq(3, "EXFAT   ", 8)) {
        r.error = "backup exFAT boot region at sector 12 is also unusable";
        return r;
    }
    r.detail = "backup boot region at sector 12 is valid";
    r.steps.push_back(r.detail);
    if (!opt.apply) {
        r.ok = true;
        r.detail += " — run with apply=true to copy the 12-sector region to sector 0";
        return r;
    }
    auto original = disk.readBlock(0, 12 * 512);
    if (!saveBackup(opt, "exfat_boot_region", 0, original, r)) return r;
    Writer w(disk.path(), disk.base());
    std::string err;
    if (!w.open(&err)) { r.error = err; return r; }
    if (!w.write(0, backup.data(), backup.size(), &err)) { r.error = err; return r; }
    r.applied = true;
    r.ok = true;
    r.detail += " — restored.";
    return r;
}

// ---------------------------------------------------------------------------
RepairResult repairNtfsBootSector(DiskReader& disk, const RepairOptions& opt) {
    RepairResult r;
    r.action = "ntfs_boot_sector_restore";

    auto primary = disk.readBlock(0, 512);
    if (primary.size() >= 512 && Bytes(primary).eq(3, "NTFS    ", 8)) {
        r.ok = true;
        r.detail = "primary NTFS boot sector is intact";
        return r;
    }
    // NTFS keeps a copy in the last sector of the volume.
    i64 last = disk.size() - 512;
    if (last <= 0) {
        r.error = "volume is too small to hold a backup boot sector";
        return r;
    }
    auto backup = disk.readBlock((u64)last, 512);
    if (backup.size() < 512 || !Bytes(backup).eq(3, "NTFS    ", 8)) {
        r.error = "backup NTFS boot sector in the last sector is also unusable";
        return r;
    }
    r.detail = "backup boot sector found in the last sector of the volume";
    r.steps.push_back(r.detail);
    if (!opt.apply) {
        r.ok = true;
        r.detail += " — run with apply=true to copy it to sector 0";
        return r;
    }
    if (!saveBackup(opt, "ntfs_boot_sector", 0, primary, r)) return r;
    Writer w(disk.path(), disk.base());
    std::string err;
    if (!w.open(&err)) { r.error = err; return r; }
    if (!w.write(0, backup.data(), backup.size(), &err)) { r.error = err; return r; }
    r.applied = true;
    r.ok = true;
    r.detail += " — restored. Run 'chkdsk /f' from Windows before relying on the volume.";
    return r;
}

// ---------------------------------------------------------------------------
RepairResult repairIso9660(DiskReader& disk, const RepairOptions& opt) {
    RepairResult r;
    r.action = "iso9660_volume_descriptor_check";
    (void)opt;

    for (int sector = 16; sector < 40; sector++) {
        auto vd = disk.readBlock((u64)sector * 2048, 2048);
        Bytes b(vd);
        if (vd.size() < 8 || !b.eq(1, "CD001", 5)) continue;
        u8 type = b.u8at(0);
        if (type == 1) {
            r.ok = true;
            r.detail = "primary volume descriptor found at sector " + std::to_string(sector);
            r.steps.push_back(r.detail);
            auto svd = disk.readBlock((u64)(sector + 1) * 2048, 2048);
            if (svd.size() >= 8 && Bytes(svd).u8at(0) == 2 && Bytes(svd).eq(1, "CD001", 5))
                r.steps.push_back("supplementary (Joliet) descriptor present and readable");
            return r;
        }
    }
    r.error = "no ISO 9660 primary volume descriptor found in sectors 16-40. ISO images are "
              "read-only; recover the files with a scan or carve instead of repairing.";
    return r;
}

// ---------------------------------------------------------------------------
RepairResult repairGptTable(DiskReader& disk, const RepairOptions& opt) {
    RepairResult r;
    r.action = "gpt_table_restore";
    const i64 ss = disk.sectorSize() ? disk.sectorSize() : 512;
    const i64 totalSectors = disk.size() / ss;
    if (totalSectors < 4) {
        r.error = "device is too small to hold a GPT";
        return r;
    }

    auto readHeader = [&](i64 lba, bool& crcOk) -> std::vector<u8> {
        auto h = disk.readBlock((u64)lba * ss, std::max<i64>(512, ss));
        crcOk = false;
        Bytes b(h);
        if (h.size() < 92 || !b.eq(0, "EFI PART", 8)) return {};
        u32 hs = b.le32(12);
        if (hs < 92 || hs > h.size()) return {};
        std::vector<u8> copy(h.begin(), h.begin() + hs);
        u32 stored = b.le32(16);
        copy[16] = copy[17] = copy[18] = copy[19] = 0;
        crcOk = crc32(copy.data(), copy.size()) == stored;
        return h;
    };

    bool primaryOk = false, backupOk = false;
    auto primary = readHeader(1, primaryOk);
    auto backup = readHeader(totalSectors - 1, backupOk);

    if (primaryOk && backupOk) {
        r.ok = true;
        r.detail = "both GPT headers are present and their CRCs match — no repair needed";
        return r;
    }
    if (!primaryOk && !backupOk) {
        r.error = "neither the primary nor the backup GPT header is valid; the table cannot be "
                  "restored from a copy. Use the deleted-partition scan and rebuild the table "
                  "from the volumes it finds.";
        return r;
    }

    bool restoringPrimary = !primaryOk;
    const std::vector<u8>& good = restoringPrimary ? backup : primary;
    Bytes g(good);
    u64 entryLba = g.le64(72);
    u32 numEntries = g.le32(80);
    u32 entrySize = g.le32(84);
    if (entrySize < 128 || numEntries == 0 || numEntries > 8192) {
        r.error = "the surviving GPT header has an implausible entry array description";
        return r;
    }
    auto entries = disk.readBlock(entryLba * ss, (i64)numEntries * entrySize);
    if (entries.size() != (size_t)numEntries * entrySize) {
        r.error = "cannot read the partition entry array referenced by the surviving header";
        return r;
    }

    r.detail = std::string(restoringPrimary ? "primary" : "backup") +
               " GPT is damaged; the " + (restoringPrimary ? "backup" : "primary") +
               " copy is valid and can be used to rebuild it";
    r.steps.push_back(r.detail);
    if (!opt.apply) {
        r.ok = true;
        r.detail += " — run with apply=true to write it";
        return r;
    }

    // Rebuild the damaged header: swap my_lba/alternate_lba, point at the
    // correct entry array location and recompute both CRCs.
    std::vector<u8> hdr = good;
    u32 hs = g.le32(12);
    hdr.resize(std::max<size_t>(hs, 92));
    auto put64 = [&](size_t off, u64 v) { for (int i = 0; i < 8; i++) hdr[off + i] = (u8)(v >> (8 * i)); };
    auto put32 = [&](size_t off, u32 v) { for (int i = 0; i < 4; i++) hdr[off + i] = (u8)(v >> (8 * i)); };

    i64 targetLba = restoringPrimary ? 1 : totalSectors - 1;
    i64 otherLba  = restoringPrimary ? totalSectors - 1 : 1;
    i64 entryArrayLba = restoringPrimary ? 2 : (totalSectors - 1 - (i64)((numEntries * entrySize + ss - 1) / ss));

    put64(24, (u64)targetLba);
    put64(32, (u64)otherLba);
    put64(72, (u64)entryArrayLba);
    put32(88, crc32(entries.data(), entries.size()));
    put32(16, 0);
    put32(16, crc32(hdr.data(), hs));

    auto original = disk.readBlock((u64)targetLba * ss, std::max<i64>(512, ss));
    if (!saveBackup(opt, "gpt_header", (u64)targetLba * ss, original, r)) return r;

    Writer w(disk.path(), disk.base());
    std::string err;
    if (!w.open(&err)) { r.error = err; return r; }
    if (!w.write((u64)entryArrayLba * ss, entries.data(), entries.size(), &err)) {
        r.error = err;
        return r;
    }
    if (!w.write((u64)targetLba * ss, hdr.data(), hdr.size(), &err)) { r.error = err; return r; }
    r.applied = true;
    r.ok = true;
    r.steps.push_back("wrote the partition entry array to LBA " + std::to_string(entryArrayLba));
    r.steps.push_back("wrote the rebuilt header to LBA " + std::to_string(targetLba));
    r.detail += " — restored.";
    return r;
}

// ---------------------------------------------------------------------------
RepairResult repairPartitionTable(DiskReader& disk, const PartitionScanResult& scan,
                                  const RepairOptions& opt) {
    RepairResult r;
    r.action = "partition_table_rebuild";

    std::vector<const PartitionInfo*> recovered;
    for (const auto& p : scan.deleted_partitions)
        if (p.recovered) recovered.push_back(&p);

    if (recovered.empty()) {
        r.error = "no recovered partitions to write — run a deleted-partition scan first";
        return r;
    }
    if (recovered.size() > 4) {
        r.error = "found " + std::to_string(recovered.size()) +
                  " recovered partitions; writing more than four requires a GPT, which this "
                  "operation does not create. Note the offsets and rebuild the table manually.";
        return r;
    }

    r.detail = "can write an MBR describing " + std::to_string(recovered.size()) +
               " recovered partition(s)";
    for (const auto* p : recovered)
        r.steps.push_back("partition at " + humanSize(p->start_byte) + " (" + p->filesystem +
                          ", " + humanSize(p->size_bytes) + ")");

    if (!opt.apply) {
        r.ok = true;
        r.detail += " — run with apply=true to write the table. Image the disk first.";
        return r;
    }

    auto sector0 = disk.readBlock(0, 512);
    if (sector0.size() < 512) sector0.assign(512, 0);
    if (!saveBackup(opt, "mbr_sector0", 0, sector0, r)) return r;

    std::vector<u8> mbr = sector0;
    mbr.resize(512, 0);
    std::memset(mbr.data() + 0x1BE, 0, 64);
    const i64 ss = scan.sector_size ? scan.sector_size : 512;
    int slot = 0;
    for (const auto* p : recovered) {
        u8* e = mbr.data() + 0x1BE + slot * 16;
        u64 startLba = (u64)(p->start_byte / ss);
        u64 count    = (u64)(p->size_bytes / ss);
        if (startLba > 0xFFFFFFFFull || count > 0xFFFFFFFFull) {
            r.error = "a recovered partition is beyond the 2 TiB MBR limit; a GPT is required";
            return r;
        }
        e[0] = 0x00;
        e[4] = startsWith(p->filesystem, "ext") ? 0x83
             : (p->filesystem == "ntfs" || p->filesystem == "exfat") ? 0x07
             : (startsWith(p->filesystem, "fat") || p->filesystem == "vfat") ? 0x0C
             : 0x83;
        for (int i = 0; i < 4; i++) e[8 + i]  = (u8)(startLba >> (8 * i));
        for (int i = 0; i < 4; i++) e[12 + i] = (u8)(count >> (8 * i));
        slot++;
    }
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    Writer w(disk.path(), disk.base());
    std::string err;
    if (!w.open(&err)) { r.error = err; return r; }
    if (!w.write(0, mbr.data(), mbr.size(), &err)) { r.error = err; return r; }
    r.applied = true;
    r.ok = true;
    r.detail += " — written. Re-read the partition table (partprobe) and verify before mounting.";
    return r;
}

// ---------------------------------------------------------------------------
std::vector<std::string> availableRepairs(const std::string& fsId) {
    std::vector<std::string> out{"gpt_table_restore", "partition_table_rebuild"};
    if (startsWith(fsId, "ext")) out.insert(out.begin(), "ext_superblock_restore");
    else if (startsWith(fsId, "fat") || fsId == "vfat") out.insert(out.begin(), "fat_boot_sector_restore");
    else if (fsId == "exfat") out.insert(out.begin(), "exfat_boot_region_restore");
    else if (fsId == "ntfs") out.insert(out.begin(), "ntfs_boot_sector_restore");
    else if (fsId == "iso9660") out.insert(out.begin(), "iso9660_volume_descriptor_check");
    return out;
}

RepairResult repairVolume(DiskReader& disk, const std::string& action, const RepairOptions& opt) {
    std::string act = action;
    if (act.empty() || act == "auto") {
        DetectResult d = detectFilesystem(disk);
        auto avail = availableRepairs(d.filesystem);
        act = avail.empty() ? "" : avail.front();
    }
    if (act == "ext_superblock_restore")        return repairExtSuperblock(disk, opt);
    if (act == "fat_boot_sector_restore")       return repairFatBootSector(disk, opt);
    if (act == "exfat_boot_region_restore")     return repairExfatBootRegion(disk, opt);
    if (act == "ntfs_boot_sector_restore")      return repairNtfsBootSector(disk, opt);
    if (act == "iso9660_volume_descriptor_check") return repairIso9660(disk, opt);
    if (act == "gpt_table_restore")             return repairGptTable(disk, opt);
    if (act == "partition_table_rebuild") {
        PartitionOptions popt;
        popt.find_deleted = true;
        Progress p;
        auto scan = scanPartitions(disk, popt, p);
        return repairPartitionTable(disk, scan, opt);
    }
    RepairResult r;
    r.action = act;
    r.error = "unknown repair action: " + act;
    return r;
}

}  // namespace ghost
