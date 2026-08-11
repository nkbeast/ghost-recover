// GHOST//RECOVER — partition tables and deleted-partition recovery.
//
// Rewritten. The previous version:
//   * read only the four primary MBR slots, so every logical partition inside
//     an extended partition was invisible
//   * never validated the GPT CRCs and never looked at the backup GPT
//   * called a partition "deleted" whenever there was a gap between two
//     entries, which reports free space as a recovery target and finds nothing
//   * mutated the caller's DiskReader window while probing and did not restore
//     the size, so probes could read past the end of a partition
//
// Deleted-partition recovery is now what the name says: a signature sweep for
// filesystem superblocks and volume boot records that no table entry covers.
#include "ghost/disk.h"

#include "ghost/fs.h"
#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <map>

namespace ghost {

namespace {

struct GptTypeName { const char* guid; const char* name; };

const GptTypeName kGptTypes[] = {
    {"C12A7328-F81F-11D2-BA4B-00A0C93EC93B", "EFI System"},
    {"21686148-6449-6E6F-744E-656564454649", "BIOS boot"},
    {"0FC63DAF-8483-4772-8E79-3D69D8477DE4", "Linux filesystem"},
    {"0657FD6D-A4AB-43C4-84E5-0933C84B4F4F", "Linux swap"},
    {"E6D6D379-F507-44C2-A23C-238F2A3DF928", "Linux LVM"},
    {"A19D880F-05FC-4D3B-A006-743F0F84911E", "Linux RAID"},
    {"44479540-F297-41B2-9AF7-D131D5F0458A", "Linux root (x86)"},
    {"4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709", "Linux root (x86-64)"},
    {"933AC7E1-2EB4-4F13-B844-0E14E2AEF915", "Linux /home"},
    {"3B8F8425-20E0-4F3B-907F-1A25A76F98E8", "Linux /srv"},
    {"CA7D7CCB-63ED-4C53-861C-1742536059CC", "Linux LUKS"},
    {"EBD0A0A2-B9E5-4433-87C0-68B6B72699C7", "Microsoft basic data"},
    {"E3C9E316-0B5C-4DB8-817D-F92DF00215AE", "Microsoft reserved"},
    {"DE94BBA4-06D1-4D40-A16A-BFD50179D6AC", "Windows recovery"},
    {"5808C8AA-7E8F-42E0-85D2-E1E90434CFB3", "Windows LDM metadata"},
    {"AF9B60A0-1431-4F62-BC68-3311714A69AD", "Windows LDM data"},
    {"48465300-0000-11AA-AA11-00306543ECAC", "Apple HFS+"},
    {"7C3457EF-0000-11AA-AA11-00306543ECAC", "Apple APFS"},
    {"426F6F74-0000-11AA-AA11-00306543ECAC", "Apple boot"},
    {"52414944-0000-11AA-AA11-00306543ECAC", "Apple RAID"},
    {"516E7CB4-6ECF-11D6-8FF8-00022D09712B", "FreeBSD data"},
    {"516E7CB5-6ECF-11D6-8FF8-00022D09712B", "FreeBSD swap"},
    {"516E7CB6-6ECF-11D6-8FF8-00022D09712B", "FreeBSD UFS"},
    {"516E7CBA-6ECF-11D6-8FF8-00022D09712B", "FreeBSD ZFS"},
    {"6A898CC3-1DD2-11B2-99A6-080020736631", "Solaris /usr or Apple ZFS"},
    {"BC13C2FF-59E6-4262-A352-B275FD6F7172", "Extended boot (XBOOTLDR)"},
};

std::string gptTypeName(const std::string& guid) {
    for (const auto& t : kGptTypes)
        if (guid == t.guid) return t.name;
    return "GPT partition";
}

const char* mbrTypeName(u8 t) {
    switch (t) {
        case 0x00: return "empty";
        case 0x01: return "FAT12";
        case 0x04: case 0x06: case 0x0E: return "FAT16";
        case 0x05: case 0x0F: case 0x85: return "Extended";
        case 0x07: return "NTFS / exFAT / HPFS";
        case 0x0B: case 0x0C: return "FAT32";
        case 0x11: case 0x14: case 0x16: case 0x17: case 0x1B: case 0x1C: case 0x1E:
            return "Hidden FAT/NTFS";
        case 0x27: return "Windows recovery";
        case 0x39: return "Plan 9";
        case 0x42: return "Windows dynamic (LDM)";
        case 0x82: return "Linux swap / Solaris";
        case 0x83: return "Linux";
        case 0x86: return "Legacy FAT16 (mirrored)";
        case 0x8E: return "Linux LVM";
        case 0xA0: return "Hibernation";
        case 0xA5: return "FreeBSD";
        case 0xA6: return "OpenBSD";
        case 0xA8: return "macOS UFS";
        case 0xA9: return "NetBSD";
        case 0xAB: return "macOS boot";
        case 0xAF: return "macOS HFS+";
        case 0xBF: return "Solaris";
        case 0xEE: return "GPT protective";
        case 0xEF: return "EFI System";
        case 0xFD: return "Linux RAID autodetect";
        default: return nullptr;
    }
}

bool isExtended(u8 t) { return t == 0x05 || t == 0x0F || t == 0x85; }

// Probe a candidate volume start without disturbing the caller's window.
DetectResult probeAt(DiskReader& disk, i64 start, i64 length) {
    u64 savedBase = disk.base();
    i64 savedSize = disk.size();
    disk.setWindow((u64)start, length);
    DetectResult d = detectFilesystem(disk);
    disk.setWindow(savedBase, savedSize);
    return d;
}

// Volume size implied by a filesystem's own superblock. Used to size recovered
// partitions that have no table entry.
i64 volumeSizeFromFs(DiskReader& disk, i64 start, const std::string& fs) {
    u64 savedBase = disk.base();
    i64 savedSize = disk.size();
    disk.setWindow((u64)start, 0);
    i64 size = 0;
    if (startsWith(fs, "ext")) {
        auto sb = disk.readBlock(1024, 1024);
        Bytes b(sb);
        u32 logBs = b.le32(0x18);
        if (logBs <= 6) {
            u64 blocks = b.le32(0x04);
            u32 incompat = b.le32(0x60);
            if (incompat & 0x80) blocks |= ((u64)b.le32(0x150)) << 32;
            size = (i64)(blocks * (1024ull << logBs));
        }
    } else if (fs == "ntfs") {
        auto b0 = disk.readBlock(0, 512);
        Bytes b(b0);
        u16 bps = b.le16(0x0B);
        u64 sectors = b.le64(0x28);
        // NTFS records one sector fewer than the partition holds (the last one
        // carries the boot-sector backup).
        if (bps) size = (i64)((sectors + 1) * bps);
    } else if (startsWith(fs, "fat") || fs == "vfat") {
        auto b0 = disk.readBlock(0, 512);
        Bytes b(b0);
        u16 bps = b.le16(11);
        u32 total = b.le16(19) ? b.le16(19) : b.le32(32);
        size = (i64)total * bps;
    } else if (fs == "exfat") {
        auto b0 = disk.readBlock(0, 512);
        Bytes b(b0);
        u8 shift = b.u8at(0x6C);
        if (shift >= 9 && shift <= 12) size = (i64)(b.le64(0x48) * ((u64)1 << shift));
    } else if (fs == "xfs") {
        auto b0 = disk.readBlock(0, 512);
        Bytes b(b0);
        size = (i64)(b.be64(0x08) * b.be32(0x04));
    } else if (fs == "btrfs") {
        auto b0 = disk.readBlock(0x10000, 4096);
        size = (i64)Bytes(b0).le64(0x70);
    }
    disk.setWindow(savedBase, savedSize);
    return size;
}

void fillFsInfo(DiskReader& disk, PartitionInfo& p, bool detect) {
    if (!detect || p.size_bytes < 64 * 1024) {
        p.fs_status = "unknown";
        return;
    }
    DetectResult d = probeAt(disk, p.start_byte, p.size_bytes);
    p.filesystem = d.filesystem;
    p.label = d.label;
    p.fs_uuid = d.uuid;
    if (d.is_container && !d.detected) {
        p.fs_status = "unknown";
        if (!d.note.empty()) p.note = d.note;
    } else if (d.detected) {
        p.fs_status = "healthy";
        if (d.is_container) p.note = d.note;
    } else {
        p.fs_status = "damaged";
    }
}

}  // namespace

// ---------------------------------------------------------------------------

PartitionScanResult scanPartitions(DiskReader& disk, const PartitionOptions& opt, Progress& prog) {
    PartitionScanResult res;
    res.image_size = disk.size();
    res.sector_size = disk.sectorSize() ? disk.sectorSize() : 512;
    res.total_sectors = res.image_size / res.sector_size;
    const i64 ss = res.sector_size;

    prog.setPhase("reading partition tables");

    // ---- MBR -------------------------------------------------------------
    auto sector0 = disk.readBlock(0, 512);
    Bytes m(sector0);
    bool mbrSig = sector0.size() >= 512 && m.u8at(510) == 0x55 && m.u8at(511) == 0xAA;
    bool protective = false;

    if (mbrSig) {
        res.mbr_ok = true;
        for (int i = 0; i < 4; i++) {
            size_t e = 0x1BE + (size_t)i * 16;
            u8 type = m.u8at(e + 4);
            if (type == 0xEE) protective = true;
        }
    }

    if (mbrSig && !protective) {
        res.partition_table = "mbr";
        std::vector<std::pair<i64, i64>> extendedChains;   // (start, size) in sectors
        for (int i = 0; i < 4; i++) {
            size_t e = 0x1BE + (size_t)i * 16;
            u8 status = m.u8at(e);
            u8 type   = m.u8at(e + 4);
            u32 lba   = m.le32(e + 8);
            u32 count = m.le32(e + 12);
            if (type == 0 || count == 0) continue;
            if ((i64)lba * ss >= res.image_size) {
                res.warnings.push_back("MBR entry " + std::to_string(i + 1) +
                                       " starts past the end of the device");
                continue;
            }

            PartitionInfo p;
            p.table = "mbr";
            p.entry = i + 1;
            p.start_lba = lba;
            p.size_lba = count;
            p.start_byte = (i64)lba * ss;
            p.size_bytes = (i64)count * ss;
            if (p.start_byte + p.size_bytes > res.image_size) {
                p.size_bytes = res.image_size - p.start_byte;
                p.size_lba = p.size_bytes / ss;
                res.warnings.push_back("MBR entry " + std::to_string(i + 1) +
                                       " extends past the end of the device; truncated");
            }
            p.size_mb = p.size_bytes / 1048576.0;
            const char* tn = mbrTypeName(type);
            char buf[40];
            snprintf(buf, sizeof(buf), "0x%02X", type);
            p.type_guid = buf;
            p.type = tn ? tn : (std::string("Unknown (") + buf + ")");
            p.bootable = (status == 0x80);
            p.status = p.bootable ? "active" : "inactive";

            if (isExtended(type)) {
                p.note = "extended partition container";
                extendedChains.emplace_back(lba, count);
                p.fs_status = "unallocated";
                res.partitions.push_back(p);
                continue;
            }
            fillFsInfo(disk, p, opt.detect_filesystems);
            res.partitions.push_back(p);
        }

        // ---- EBR chain: logical partitions -------------------------------
        int logicalIndex = 5;
        for (const auto& [extStart, extSize] : extendedChains) {
            i64 ebr = extStart;
            int guard = 0;
            while (ebr && guard++ < 128 && !prog.cancelled()) {
                auto raw = disk.readBlock((u64)ebr * ss, 512);
                Bytes b(raw);
                if (raw.size() < 512 || b.u8at(510) != 0x55 || b.u8at(511) != 0xAA) break;

                // First entry describes the logical partition, relative to this EBR.
                u8  type1  = b.u8at(0x1BE + 4);
                u32 lba1   = b.le32(0x1BE + 8);
                u32 count1 = b.le32(0x1BE + 12);
                if (type1 && count1) {
                    PartitionInfo p;
                    p.table = "mbr";
                    p.entry = logicalIndex++;
                    p.start_lba = ebr + lba1;
                    p.size_lba = count1;
                    p.start_byte = p.start_lba * ss;
                    p.size_bytes = (i64)count1 * ss;
                    p.size_mb = p.size_bytes / 1048576.0;
                    const char* tn = mbrTypeName(type1);
                    char buf[40];
                    snprintf(buf, sizeof(buf), "0x%02X", type1);
                    p.type_guid = buf;
                    p.type = tn ? tn : (std::string("Unknown (") + buf + ")");
                    p.status = "logical";
                    p.note = "logical partition";
                    p.bootable = b.u8at(0x1BE) == 0x80;
                    if (p.start_byte >= 0 && p.start_byte + p.size_bytes <= res.image_size) {
                        fillFsInfo(disk, p, opt.detect_filesystems);
                        res.partitions.push_back(p);
                    }
                }

                // Second entry points at the next EBR, relative to the start of
                // the whole extended partition.
                u8  type2 = b.u8at(0x1CE + 4);
                u32 lba2  = b.le32(0x1CE + 8);
                if (!type2 || !lba2) break;
                i64 next = extStart + lba2;
                if (next == ebr || next < extStart || next >= extStart + extSize) break;
                ebr = next;
            }
        }
        res.ok = !res.partitions.empty();
    }

    // ---- GPT --------------------------------------------------------------
    auto readGpt = [&](i64 headerLba, bool primary) -> bool {
        auto hdr = disk.readBlock((u64)headerLba * ss, (i64)std::max<i64>(512, ss));
        Bytes h(hdr);
        if (hdr.size() < 92 || !h.eq(0, "EFI PART", 8)) return false;

        u32 headerSize = h.le32(12);
        u32 storedCrc  = h.le32(16);
        if (headerSize < 92 || headerSize > (u32)hdr.size()) headerSize = 92;
        std::vector<u8> hcopy(hdr.begin(), hdr.begin() + headerSize);
        hcopy[16] = hcopy[17] = hcopy[18] = hcopy[19] = 0;
        bool headerCrcOk = crc32(hcopy.data(), hcopy.size()) == storedCrc;

        u64 entryLba  = h.le64(72);
        u32 numEntries = h.le32(80);
        u32 entrySize  = h.le32(84);
        u32 entriesCrc = h.le32(88);
        if (entrySize < 128 || entrySize > 4096 || numEntries == 0 || numEntries > 8192) return false;

        auto entries = disk.readBlock(entryLba * ss, (i64)numEntries * entrySize);
        bool entriesCrcOk = entries.size() == (size_t)numEntries * entrySize &&
                            crc32(entries.data(), entries.size()) == entriesCrc;

        if (primary) { res.gpt_primary_ok = headerCrcOk && entriesCrcOk; }
        else         { res.gpt_backup_ok  = headerCrcOk && entriesCrcOk; }
        if (!headerCrcOk)
            res.warnings.push_back(std::string(primary ? "primary" : "backup") +
                                   " GPT header CRC does not match");
        if (!entriesCrcOk)
            res.warnings.push_back(std::string(primary ? "primary" : "backup") +
                                   " GPT partition entry array CRC does not match");

        if (hdr.size() >= 72) res.disk_guid = guidToString(hdr.data() + 56);

        Bytes eb(entries);
        std::vector<PartitionInfo> parsed;
        for (u32 i = 0; i < numEntries; i++) {
            size_t e = (size_t)i * entrySize;
            if (!eb.has(e, 128)) break;
            bool used = false;
            for (int k = 0; k < 16; k++) if (eb.u8at(e + k)) { used = true; break; }
            if (!used) continue;

            PartitionInfo p;
            p.table = "gpt";
            p.entry = (int)i + 1;
            p.type_guid = guidToString(entries.data() + e);
            p.uuid = guidToString(entries.data() + e + 16);
            u64 first = eb.le64(e + 32);
            u64 last  = eb.le64(e + 40);
            if (last < first) continue;
            p.start_lba = (i64)first;
            p.size_lba  = (i64)(last - first + 1);
            p.start_byte = (i64)(first * (u64)ss);
            p.size_bytes = p.size_lba * ss;
            if (p.start_byte >= res.image_size) continue;
            if (p.start_byte + p.size_bytes > res.image_size) {
                p.size_bytes = res.image_size - p.start_byte;
                p.size_lba = p.size_bytes / ss;
            }
            p.size_mb = p.size_bytes / 1048576.0;
            p.type = gptTypeName(p.type_guid);
            u64 attrs = eb.le64(e + 48);
            p.bootable = (attrs & (1ull << 2)) != 0;
            p.status = "active";
            p.name = utf16leToUtf8(entries.data() + e + 56, 72);
            fillFsInfo(disk, p, opt.detect_filesystems);
            parsed.push_back(std::move(p));
        }
        if (parsed.empty()) return false;
        res.partition_table = "gpt";
        res.partitions = std::move(parsed);
        res.ok = true;
        return true;
    };

    if (protective || !res.ok) {
        bool gotPrimary = readGpt(1, true);
        // Always check the backup as well, so the reported health of each copy
        // is accurate rather than "unknown means damaged".
        i64 lastLba = res.total_sectors - 1;
        if (lastLba > 1) {
            auto saved = res.partitions;
            bool gotBackup = readGpt(lastLba, false);
            if (gotPrimary && res.gpt_primary_ok) {
                // Keep the primary's list; the backup read was only a health check.
                res.partitions = saved;
            } else if (gotBackup) {
                res.warnings.push_back(
                    "primary GPT is unreadable or its CRC does not match; the partition list "
                    "was recovered from the backup GPT at the end of the disk");
            } else if (gotPrimary) {
                res.partitions = saved;
            }
        }
    }

    if (res.partitions.empty() && !res.ok) {
        // Not partitioned, or the table is gone. Say which.
        DetectResult d = probeAt(disk, 0, res.image_size);
        if (d.detected && !d.is_container) {
            res.partition_table = "none";
            res.error = "no partition table — this looks like a single " + d.filesystem +
                        " volume, so scan it directly";
        } else {
            res.partition_table = "unknown";
            res.error = "no readable partition table found";
        }
    }

    std::sort(res.partitions.begin(), res.partitions.end(),
              [](const PartitionInfo& a, const PartitionInfo& b) {
                  return a.start_byte < b.start_byte;
              });
    res.count = (int)res.partitions.size();

    // ---- recover partitions missing from the table -------------------------
    if (opt.find_deleted && !prog.cancelled()) {
        prog.setPhase("scanning for deleted partitions");

        auto covered = [&](i64 off) {
            for (const auto& p : res.partitions)
                if (off >= p.start_byte && off < p.start_byte + p.size_bytes) return true;
            return false;
        };

        i64 limit = opt.deleted_scan_limit > 0 ? std::min(opt.deleted_scan_limit, res.image_size)
                                               : std::min<i64>(res.image_size, 64LL << 30);
        // Partitions are aligned to at least 1 MiB on anything made this century,
        // and to a cylinder boundary on older disks; probe both.
        const i64 kStride = 1 << 20;
        prog.set(0, limit);
        int found = 0;
        for (i64 off = 0; off < limit && found < 64 && !prog.cancelled(); off += kStride) {
            if ((off & ((256 << 20) - 1)) == 0) prog.set(off, limit);
            if (covered(off)) continue;
            if (off == 0) continue;                       // the table itself lives here

            DetectResult d = probeAt(disk, off, 0);
            if (!d.detected || d.is_container) continue;
            if (d.filesystem == "swap") continue;

            // An ext backup superblock looks exactly like the start of a
            // filesystem. It records which block group it belongs to, so use
            // that to work back to the volume's real start instead of
            // reporting one phantom partition per backup.
            i64 realStart = off;
            if (startsWith(d.filesystem, "ext")) {
                u64 savedBase = disk.base();
                i64 savedSize = disk.size();
                disk.setWindow((u64)off, 0);
                auto sb = disk.readBlock(1024, 1024);
                Bytes sbb(sb);
                u16 groupNr = sbb.le16(0x5A);
                u32 logBs = sbb.le32(0x18);
                u32 bpg = sbb.le32(0x20);
                disk.setWindow(savedBase, savedSize);
                if (groupNr != 0 && logBs <= 6 && bpg) {
                    i64 bs = 1024LL << logBs;
                    realStart = off - (i64)groupNr * bpg * bs - (bs == 1024 ? 1024 : 0);
                    if (realStart < 0) continue;
                }
            }
            off = realStart;
            if (covered(off)) continue;

            // Do not report the same volume twice when several of its backup
            // superblocks are hit.
            bool already = false;
            for (const auto& r : res.deleted_partitions)
                if (r.recovered && r.start_byte == off) { already = true; break; }
            if (already) continue;

            i64 size = volumeSizeFromFs(disk, off, d.filesystem);
            if (size <= 0) size = std::min<i64>(res.image_size - off, 1 << 30);
            if (off + size > res.image_size) size = res.image_size - off;
            if (size < 1 << 20) continue;

            // Reject a hit that lands inside a partition we already know about —
            // from the table, or from an earlier recovery in this same sweep.
            bool overlapsKnown = false;
            for (const auto& p : res.partitions) {
                i64 aEnd = off + size, bEnd = p.start_byte + p.size_bytes;
                if (off < bEnd && p.start_byte < aEnd) { overlapsKnown = true; break; }
            }
            for (const auto& p : res.deleted_partitions) {
                if (!p.recovered) continue;
                i64 aEnd = off + size, bEnd = p.start_byte + p.size_bytes;
                if (off < bEnd && p.start_byte < aEnd) { overlapsKnown = true; break; }
            }
            if (overlapsKnown) continue;

            PartitionInfo p;
            p.table = "recovered";
            p.entry = -1;
            p.start_byte = off;
            p.size_bytes = size;
            p.size_mb = size / 1048576.0;
            p.start_lba = off / ss;
            p.size_lba = size / ss;
            p.filesystem = d.filesystem;
            p.label = d.label;
            p.fs_uuid = d.uuid;
            p.type = d.filesystem;
            p.status = "deleted";
            p.fs_status = "healthy";
            p.recovered = true;
            p.confidence = d.confidence;
            p.note = "recovered by filesystem signature scan — not present in the partition table";
            res.deleted_partitions.push_back(std::move(p));
            found++;
        }
        if (limit < res.image_size)
            res.warnings.push_back("deleted-partition scan covered the first " + humanSize(limit) +
                                   " of the device");
    }

    // ---- unallocated regions (reported separately from recovered ones) -----
    {
        i64 prevEnd = 1 << 20;   // skip the table area at the start of the disk
        std::vector<PartitionInfo> gaps;
        std::vector<PartitionInfo> occupied = res.partitions;
        for (const auto& p : res.deleted_partitions)
            if (p.recovered) occupied.push_back(p);
        std::sort(occupied.begin(), occupied.end(),
                  [](const PartitionInfo& a, const PartitionInfo& b) {
                      return a.start_byte < b.start_byte;
                  });
        for (const auto& p : occupied) {
            if (p.start_byte > prevEnd + (1 << 20)) {
                PartitionInfo g;
                g.table = res.partition_table;
                g.entry = -1;
                g.type = "Unallocated";
                g.status = "unallocated";
                g.fs_status = "unallocated";
                g.start_byte = prevEnd;
                g.size_bytes = p.start_byte - prevEnd;
                g.size_mb = g.size_bytes / 1048576.0;
                g.start_lba = prevEnd / ss;
                g.size_lba = g.size_bytes / ss;
                g.note = "free space — carve it to recover deleted files";
                gaps.push_back(std::move(g));
            }
            prevEnd = std::max(prevEnd, p.start_byte + p.size_bytes);
        }
        if (prevEnd + (1 << 20) < res.image_size) {
            PartitionInfo g;
            g.table = res.partition_table;
            g.entry = -1;
            g.type = "Unallocated";
            g.status = "unallocated";
            g.fs_status = "unallocated";
            g.start_byte = prevEnd;
            g.size_bytes = res.image_size - prevEnd;
            g.size_mb = g.size_bytes / 1048576.0;
            g.start_lba = prevEnd / ss;
            g.size_lba = g.size_bytes / ss;
            g.note = "trailing free space";
            gaps.push_back(std::move(g));
        }
        for (auto& g : gaps) res.deleted_partitions.push_back(std::move(g));
    }

    std::sort(res.deleted_partitions.begin(), res.deleted_partitions.end(),
              [](const PartitionInfo& a, const PartitionInfo& b) {
                  return a.start_byte < b.start_byte;
              });
    res.deleted_count = (int)res.deleted_partitions.size();
    res.disk_type = disk.isRawDevice() ? "device" : "image";
    return res;
}

PartitionScanResult scanPartitions(DiskReader& disk) {
    PartitionOptions opt;
    opt.find_deleted = false;      // the default read is fast; deep scan is opt-in
    return scanPartitions(disk, opt, nullProgress());
}

// ---------------------------------------------------------------------------
// Free-space maps
// ---------------------------------------------------------------------------
namespace {

void mergeExtents(std::vector<Extent>& v) {
    if (v.empty()) return;
    std::sort(v.begin(), v.end(),
              [](const Extent& a, const Extent& b) { return a.offset < b.offset; });
    std::vector<Extent> out;
    out.push_back(v[0]);
    for (size_t i = 1; i < v.size(); i++) {
        Extent& last = out.back();
        if (v[i].offset <= last.offset + last.length)
            last.length = std::max(last.length, v[i].offset + v[i].length - last.offset);
        else
            out.push_back(v[i]);
    }
    v.swap(out);
}

std::vector<Extent> extFree(DiskReader& disk, Progress& prog) {
    std::vector<Extent> free;
    auto sb = disk.readBlock(1024, 1024);
    Bytes s(sb);
    if (s.le16(0x38) != 0xEF53) return free;
    u32 logBs = s.le32(0x18);
    if (logBs > 6) return free;
    u32 bs = 1024u << logBs;
    u64 blocksCount = s.le32(0x04);
    u32 firstData = s.le32(0x14);
    u32 blocksPerGroup = s.le32(0x20);
    u32 incompat = s.le32(0x60);
    u16 descSize = (incompat & 0x80) ? std::max<u16>(64, s.le16(0xFE)) : 32;
    if (incompat & 0x80) blocksCount |= ((u64)s.le32(0x150)) << 32;
    if (!blocksPerGroup || !blocksCount) return free;

    u32 groups = (u32)((blocksCount - firstData + blocksPerGroup - 1) / blocksPerGroup);
    auto gd = disk.readBlock((u64)(firstData + 1) * bs, (i64)groups * descSize);
    Bytes g(gd);
    for (u32 i = 0; i < groups && !prog.cancelled(); i++) {
        size_t o = (size_t)i * descSize;
        if (!g.has(o, 12)) break;
        u64 bitmapBlock = g.le32(o);
        if (descSize >= 64) bitmapBlock |= ((u64)g.le32(o + 0x20)) << 32;
        if (!bitmapBlock) continue;
        auto bm = disk.readBlock(bitmapBlock * bs, bs);
        if (bm.empty()) continue;
        // One bitmap block can describe at most bs*8 blocks. A crafted superblock
        // may claim more blocks per group; index only the bits we actually read.
        u32 bMax = std::min(blocksPerGroup, (u32)bm.size() * 8u);
        u64 groupFirst = firstData + (u64)i * blocksPerGroup;
        for (u32 b = 0; b < bMax; b++) {
            if (groupFirst + b >= blocksCount) break;
            if ((bm[b / 8] >> (b % 8)) & 1) continue;      // allocated
            i64 off = (i64)((groupFirst + b) * bs);
            if (!free.empty() && free.back().offset + free.back().length == off)
                free.back().length += bs;
            else
                free.push_back(Extent(off, bs));
        }
    }
    return free;
}

std::vector<Extent> fatFree(DiskReader& disk, Progress& prog) {
    std::vector<Extent> free;
    auto b0 = disk.readBlock(0, 512);
    Bytes b(b0);
    u16 bps = b.le16(11);
    u8 spc = b.u8at(13);
    u16 reserved = b.le16(14);
    u8 numFats = b.u8at(16);
    u16 rootEntries = b.le16(17);
    u32 total = b.le16(19) ? b.le16(19) : b.le32(32);
    u32 fatSize = b.le16(22) ? b.le16(22) : b.le32(36);
    if (!bps || !spc || !fatSize || !total) return free;
    u64 rootSectors = ((u64)rootEntries * 32 + bps - 1) / bps;
    u64 dataStart = reserved + (u64)numFats * fatSize + rootSectors;
    if (dataStart >= total) return free;
    u64 clusters = (total - dataStart) / spc;
    int bits = clusters < 4085 ? 12 : (clusters < 65525 ? 16 : 32);
    auto fat = disk.readBlock((u64)reserved * bps,
                              std::min<i64>((i64)fatSize * bps, 256LL << 20));
    Bytes f(fat);
    for (u64 c = 2; c < clusters + 2 && !prog.cancelled(); c++) {
        u32 v;
        if (bits == 12) {
            u64 o = c + (c / 2);
            u16 raw = f.le16(o);
            v = (c & 1) ? (u32)(raw >> 4) : (u32)(raw & 0x0FFF);
        } else if (bits == 16) v = f.le16(c * 2);
        else v = f.le32(c * 4) & 0x0FFFFFFF;
        if (v != 0) continue;
        i64 off = (i64)((dataStart + (c - 2) * spc) * bps);
        i64 len = (i64)spc * bps;
        if (!free.empty() && free.back().offset + free.back().length == off)
            free.back().length += len;
        else free.push_back(Extent(off, len));
    }
    return free;
}

std::vector<Extent> ntfsFree(DiskReader& disk, Progress& prog) {
    // $Bitmap is MFT record 6; each bit is one cluster.
    std::vector<Extent> free;
    auto b0 = disk.readBlock(0, 512);
    Bytes b(b0);
    if (!b.eq(3, "NTFS    ", 8)) return free;
    u16 bps = b.le16(0x0B);
    u8 spcRaw = b.u8at(0x0D);
    // Corrupt counts would shift by up to 127 on a u32.
    u32 spc = (spcRaw > 0x80) ? (1u << std::min<unsigned>(31, 0x100u - spcRaw)) : spcRaw;
    if (!bps || !spc) return free;
    u32 clusterSize = bps * spc;
    u64 mftLcn = b.le64(0x30);
    i8 cpr = (i8)b.u8at(0x40);
    u32 recSize = (cpr < 0) ? (1u << (u32)(-cpr)) : (u32)cpr * clusterSize;
    if (recSize < 256 || recSize > 65536) recSize = 1024;

    // Read $Bitmap's record directly; it lives 6 records into the MFT.
    i64 recOff = (i64)(mftLcn * clusterSize) + (i64)6 * recSize;
    auto rec = disk.readBlock((u64)recOff, recSize);
    Bytes r(rec);
    if (rec.size() < 48 || !r.eq(0, "FILE", 4)) return free;

    size_t p = r.le16(0x14);
    std::vector<u8> bitmap;
    i64 bitmapLen = 0;
    while (p + 16 < rec.size()) {
        u32 type = r.le32(p);
        if (type == 0xFFFFFFFF) break;
        u32 len = r.le32(p + 4);
        if (len < 16 || p + len > rec.size()) break;
        if (type == 0x80 && r.u8at(p + 8) == 1) {          // non-resident $DATA
            u16 runOff = r.le16(p + 0x20);
            bitmapLen = (i64)r.le64(p + 0x30);
            i64 lcn = 0;
            size_t q = p + runOff;
            while (q < p + len && bitmap.size() < 64u * 1024 * 1024) {
                u8 head = r.u8at(q);
                if (!head) break;
                int lenLen = head & 0xF, offLen = (head >> 4) & 0xF;
                if (!lenLen || lenLen > 8 || offLen > 8) break;
                q++;
                i64 clusters = (i64)r.ule(q, lenLen);
                q += lenLen;
                if (offLen) {
                    lcn += r.sle(q, offLen);
                    q += offLen;
                    auto part = disk.readBlock((u64)(lcn * clusterSize),
                                               clusters * (i64)clusterSize);
                    bitmap.insert(bitmap.end(), part.begin(), part.end());
                } else {
                    q += 0;
                }
                if (prog.cancelled()) break;
            }
            break;
        }
        p += len;
    }
    if (bitmap.empty()) return free;
    if (bitmapLen > 0 && (i64)bitmap.size() > bitmapLen) bitmap.resize((size_t)bitmapLen);

    i64 volume = disk.size();
    u64 totalClusters = (u64)(volume / clusterSize);
    for (u64 c = 0; c < totalClusters && c / 8 < bitmap.size(); c++) {
        if ((bitmap[c / 8] >> (c % 8)) & 1) continue;
        i64 off = (i64)(c * clusterSize);
        if (!free.empty() && free.back().offset + free.back().length == off)
            free.back().length += clusterSize;
        else free.push_back(Extent(off, clusterSize));
        if (prog.cancelled()) break;
    }
    return free;
}

std::vector<Extent> exfatFree(DiskReader& disk, Progress& prog) {
    std::vector<Extent> free;
    auto b0 = disk.readBlock(0, 512);
    Bytes b(b0);
    if (!b.eq(3, "EXFAT   ", 8)) return free;
    u8 bpsShift = b.u8at(0x6C), spcShift = b.u8at(0x6D);
    if (bpsShift < 9 || bpsShift > 12 || spcShift < 1 || spcShift > 25 - bpsShift) return free;
    u64 bps = 1ull << bpsShift;
    u64 spc = 1ull << spcShift;
    u64 clusterSize = bps * spc;
    u32 heapOff = b.le32(0x58);
    u32 clusterCount = b.le32(0x5C);
    u32 rootCluster = b.le32(0x60);
    u32 fatOff = b.le32(0x50);
    u32 fatLen = b.le32(0x54);
    if (!clusterCount || rootCluster < 2) return free;

    auto clusterOffset = [&](u64 c) -> i64 {
        return (i64)(((u64)heapOff + (c - 2) * spc) * bps);
    };
    auto fat = disk.readBlock((u64)fatOff * bps, std::min<i64>((i64)fatLen * bps, 256LL << 20));
    Bytes fb(fat);

    // Find the allocation bitmap entry in the root directory.
    std::vector<u8> bitmap;
    {
        u64 c = rootCluster;
        std::vector<u8> dirBuf;
        for (int i = 0; i < 64 && c >= 2 && c < clusterCount + 2; i++) {
            auto part = disk.readBlock((u64)clusterOffset(c), clusterSize);
            dirBuf.insert(dirBuf.end(), part.begin(), part.end());
            u32 next = fb.le32(c * 4);
            if (next < 2 || next == 0xFFFFFFFF) break;
            c = next;
        }
        Bytes db(dirBuf);
        for (size_t i = 0; i + 32 <= db.size(); i += 32) {
            if (db.u8at(i) == 0) break;
            if (db.u8at(i) != 0x81) continue;
            u32 first = db.le32(i + 20);
            u64 len = db.le64(i + 24);
            if (first < 2 || len == 0 || len > 512ull * 1024 * 1024) break;
            u64 bc = first;
            while (bitmap.size() < len && bc >= 2 && bc < clusterCount + 2) {
                auto part = disk.readBlock((u64)clusterOffset(bc), clusterSize);
                bitmap.insert(bitmap.end(), part.begin(), part.end());
                u32 next = fb.le32(bc * 4);
                if (next < 2 || next == 0xFFFFFFFF) break;
                bc = next;
            }
            bitmap.resize(std::min<size_t>(bitmap.size(), (size_t)len));
            break;
        }
    }
    if (bitmap.empty()) return free;
    for (u64 c = 0; c < clusterCount && c / 8 < bitmap.size(); c++) {
        if ((bitmap[c / 8] >> (c % 8)) & 1) continue;
        i64 off = clusterOffset(c + 2);
        if (!free.empty() && free.back().offset + free.back().length == off)
            free.back().length += clusterSize;
        else free.push_back(Extent(off, clusterSize));
        if (prog.cancelled()) break;
    }
    return free;
}

}  // namespace

std::vector<Extent> unallocatedRegions(DiskReader& disk, const std::string& fsId, Progress& prog) {
    std::string fs = fsId;
    if (fs.empty()) {
        DetectResult d = detectFilesystem(disk);
        fs = d.filesystem;
    }
    prog.setPhase("reading free-space map");

    std::vector<Extent> free;
    if (startsWith(fs, "ext"))                       free = extFree(disk, prog);
    else if (fs == "ntfs")                           free = ntfsFree(disk, prog);
    else if (startsWith(fs, "fat") || fs == "vfat")  free = fatFree(disk, prog);
    else if (fs == "exfat")                          free = exfatFree(disk, prog);

    mergeExtents(free);
    if (free.empty()) {
        // No free-space map available: carve the whole volume rather than
        // silently skipping it.
        free.push_back(Extent(0, disk.size()));
    }
    return free;
}

}  // namespace ghost
