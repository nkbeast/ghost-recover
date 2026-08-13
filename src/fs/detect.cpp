// GHOST//RECOVER — filesystem identification.
//
// Ordering matters here. The previous implementation tested FAT before NTFS,
// and because an NTFS boot sector also ends in 0x55AA it parsed NTFS volumes as
// FAT, computed nonsense cluster counts from NTFS fields and reported "fat16".
// Every NTFS volume was therefore handed to the FAT driver. Signatures are now
// checked most-specific first, and each candidate must pass a structural
// plausibility test rather than just a magic-number compare.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>

namespace ghost {

namespace {

bool isPow2(u64 v) { return v && !(v & (v - 1)); }

// ---- FAT / NTFS / exFAT share a BIOS Parameter Block layout at offset 0 ----
struct Bpb {
    u16 bytes_per_sector   = 0;
    u8  sectors_per_cluster = 0;
    u16 reserved_sectors   = 0;
    u8  num_fats           = 0;
    u16 root_entries       = 0;
    u32 total_sectors      = 0;
    u32 fat_size           = 0;
    u8  media              = 0;
};

Bpb readBpb(const Bytes& b) {
    Bpb p;
    p.bytes_per_sector    = b.le16(11);
    p.sectors_per_cluster = b.u8at(13);
    p.reserved_sectors    = b.le16(14);
    p.num_fats            = b.u8at(16);
    p.root_entries        = b.le16(17);
    u16 ts16              = b.le16(19);
    u32 ts32              = b.le32(32);
    p.total_sectors       = ts16 ? ts16 : ts32;
    u16 fs16              = b.le16(22);
    u32 fs32              = b.le32(36);
    p.fat_size            = fs16 ? fs16 : fs32;
    p.media               = b.u8at(21);
    return p;
}

// A real FAT BPB has strict constraints. Random data that happens to end in
// 0x55AA fails these, which is what stops the FAT branch from swallowing NTFS,
// exFAT and plain MBR sectors.
bool bpbPlausible(const Bpb& p) {
    if (!isPow2(p.bytes_per_sector) || p.bytes_per_sector < 512 || p.bytes_per_sector > 4096)
        return false;
    if (!isPow2(p.sectors_per_cluster) || p.sectors_per_cluster == 0 || p.sectors_per_cluster > 128)
        return false;
    if (p.reserved_sectors == 0) return false;
    if (p.num_fats == 0 || p.num_fats > 4) return false;
    if (p.total_sectors == 0) return false;
    if (p.fat_size == 0) return false;
    if (p.media != 0xF0 && p.media < 0xF8) return false;
    return true;
}

std::string fatFlavour(const Bpb& p, u32* clustersOut) {
    u32 root_dir_sectors = ((u32)p.root_entries * 32 + (p.bytes_per_sector - 1)) / p.bytes_per_sector;
    u64 meta = (u64)p.reserved_sectors + (u64)p.num_fats * p.fat_size + root_dir_sectors;
    if (meta >= p.total_sectors) { if (clustersOut) *clustersOut = 0; return "fat16"; }
    u32 data_sectors  = (u32)(p.total_sectors - meta);
    u32 total_clusters = data_sectors / p.sectors_per_cluster;
    if (clustersOut) *clustersOut = total_clusters;
    if (total_clusters < 4085)  return "fat12";
    if (total_clusters < 65525) return "fat16";
    return "fat32";
}

// FAT is "VFAT" in practice whenever long filenames are present.
bool rootHasLfn(DiskReader& d, const Bpb& p, const std::string& flavour, const Bytes& boot) {
    u32 root_dir_sectors = ((u32)p.root_entries * 32 + (p.bytes_per_sector - 1)) / p.bytes_per_sector;
    u64 off = 0;
    u32 bytes = 0;
    if (flavour == "fat32") {
        u32 root_cluster = boot.le32(44);
        if (root_cluster < 2) return false;
        u64 data_start = ((u64)p.reserved_sectors + (u64)p.num_fats * p.fat_size + root_dir_sectors)
                         * p.bytes_per_sector;
        off   = data_start + (u64)(root_cluster - 2) * p.sectors_per_cluster * p.bytes_per_sector;
        bytes = (u32)p.sectors_per_cluster * p.bytes_per_sector;
    } else {
        off   = ((u64)p.reserved_sectors + (u64)p.num_fats * p.fat_size) * p.bytes_per_sector;
        bytes = (u32)p.root_entries * 32;
    }
    if (bytes == 0 || bytes > 65536) bytes = std::min<u32>(bytes, 65536);
    auto dir = d.readBlock(off, bytes);
    Bytes db(dir);
    for (size_t i = 0; i + 32 <= db.size(); i += 32) {
        u8 first = db.u8at(i);
        if (first == 0x00) break;
        if (first == 0xE5) continue;
        if (db.u8at(i + 11) == 0x0F && db.u8at(i + 12) == 0) return true;
    }
    return false;
}

std::string fatLabel(DiskReader& d, const Bpb& p, const std::string& flavour, const Bytes& boot) {
    // The boot-sector label is often stale; the volume-label directory entry is
    // authoritative. Try the directory first, fall back to the BPB field.
    u32 root_dir_sectors = ((u32)p.root_entries * 32 + (p.bytes_per_sector - 1)) / p.bytes_per_sector;
    u64 off = 0;
    u32 bytes = 0;
    if (flavour == "fat32") {
        u32 rc = boot.le32(44);
        if (rc >= 2) {
            u64 data_start = ((u64)p.reserved_sectors + (u64)p.num_fats * p.fat_size + root_dir_sectors)
                             * p.bytes_per_sector;
            off   = data_start + (u64)(rc - 2) * p.sectors_per_cluster * p.bytes_per_sector;
            bytes = (u32)p.sectors_per_cluster * p.bytes_per_sector;
        }
    } else {
        off   = ((u64)p.reserved_sectors + (u64)p.num_fats * p.fat_size) * p.bytes_per_sector;
        bytes = (u32)p.root_entries * 32;
    }
    if (bytes) {
        auto dir = d.readBlock(off, std::min<u32>(bytes, 65536));
        Bytes db(dir);
        for (size_t i = 0; i + 32 <= db.size(); i += 32) {
            u8 first = db.u8at(i);
            if (first == 0x00) break;
            if (first == 0xE5) continue;
            u8 attr = db.u8at(i + 11);
            if ((attr & 0x08) && !(attr & 0x10) && attr != 0x0F) {
                std::string l = db.trimmed(i, 11);
                if (!l.empty()) return l;
            }
        }
    }
    std::string l = (flavour == "fat32") ? boot.trimmed(71, 11) : boot.trimmed(43, 11);
    if (l == "NO NAME") l.clear();
    return l;
}

std::string serialToUuid(u32 serial) {
    char buf[16];
    snprintf(buf, sizeof(buf), "%04X-%04X", (serial >> 16) & 0xFFFF, serial & 0xFFFF);
    return buf;
}

}  // namespace

// ---------------------------------------------------------------------------

std::vector<FsEntry> filesystemRegistry() {
    // supported = has a real metadata driver; the rest are identified and
    // handed to the carver.
    return {
        {"ext2",     "ext2",           "ext",      "Linux Native",     "0xEF53",        false, true},
        {"ext3",     "ext3",           "ext",      "Linux Native",     "0xEF53",        false, true},
        {"ext4",     "ext4",           "ext",      "Linux Native",     "0xEF53",        false, true},
        {"ntfs",     "NTFS",           "ntfs",     "Windows",          "NTFS    ",      false, true},
        {"fat12",    "FAT12",          "fat",      "Cross-Platform",   "BPB",           false, true},
        {"fat16",    "FAT16",          "fat",      "Cross-Platform",   "BPB",           false, true},
        {"fat32",    "FAT32",          "fat",      "Cross-Platform",   "BPB",           false, true},
        {"vfat",     "VFAT",           "fat",      "Cross-Platform",   "LFN",           false, true},
        {"exfat",    "exFAT",          "exfat",    "Cross-Platform",   "EXFAT   ",      false, true},
        {"xfs",      "XFS",            "xfs",      "Linux Native",     "XFSB",          false, true},
        {"btrfs",    "Btrfs",          "btrfs",    "CoW / Next-Gen",   "_BHRfS_M",      false, true},
        {"f2fs",     "F2FS",           "f2fs",     "Flash-Optimised",  "0xF2F52010",    false, true},
        {"hfsplus",  "HFS+",           "hfs",      "Apple",            "H+",            false, true},
        {"hfsx",     "HFSX",           "hfs",      "Apple",            "HX",            false, true},
        {"hfs",      "HFS",            "hfs",      "Apple",            "BD",            true,  true},
        {"apfs",     "APFS",           "apfs",     "Apple",            "NXSB",          true,  true},
        {"iso9660",  "ISO 9660",       "iso",      "Optical",          "CD001",         true,  true},
        {"udf",      "UDF",            "udf",      "Optical",          "NSR0",          true,  true},
        {"squashfs", "SquashFS",       "squashfs", "Read-Only",        "hsqs",          true,  true},
        {"cramfs",   "cramfs",         "cramfs",   "Read-Only",        "0x28CD3D45",    true,  true},
        {"romfs",    "romfs",          "romfs",    "Read-Only",        "-rom1fs-",      true,  true},
        {"minix",    "MINIX",          "minix",    "UNIX Legacy",      "0x137F/0x138F", true,  true},
        {"jffs2",    "JFFS2",          "jffs2",    "Flash-Optimised",  "0x1985",        true,  true},
        {"ufs",      "UFS/FFS",        "ufs",      "UNIX Legacy",      "0x00011954",    true,  true},
        {"ufs2",     "UFS2",           "ufs",      "UNIX Legacy",      "0x19540119",    true,  true},
        {"reiserfs", "ReiserFS",       "reiserfs", "Journaling",       "ReIsEr2Fs",     true,  true},
        {"jfs",      "JFS",            "jfs",      "Journaling",       "JFS1",          true,  true},
        {"zfs",      "ZFS",            "zfs",      "CoW / Next-Gen",   "0x00BAB10C",    true,  true},
        {"bcachefs", "bcachefs",       "bcachefs", "CoW / Next-Gen",   "bcachefs",      true,  false},
        {"nilfs2",   "NILFS2",         "nilfs2",   "CoW / Next-Gen",   "0x3434",        true,  false},
        {"erofs",    "EROFS",          "erofs",    "Read-Only",        "0xE0F5E1E2",    true,  false},
        {"ubifs",    "UBIFS",          "ubifs",    "Flash-Optimised",  "0x06101831",    true,  false},
        {"yaffs2",   "YAFFS2",         "yaffs2",   "Flash-Optimised",  "YAFFS",         true,  false},
        {"ocfs2",    "OCFS2",          "ocfs2",    "Cluster",          "OCFSV2",        true,  false},
        {"gfs2",     "GFS2",           "gfs2",     "Cluster",          "0x01161970",    true,  false},
        {"sysv",     "SysV",           "sysv",     "UNIX Legacy",      "0x012FF7B7",    true,  false},
        {"xiafs",    "Xiafs",          "xiafs",    "UNIX Legacy",      "0x012FD528",    true,  false},
        {"reiser4",  "Reiser4",        "reiser4",  "Journaling",       "ReIsEr4",       true,  false},
        {"swap",     "Linux Swap",     "swap",     "Container",        "SWAPSPACE2",    true,  false},
        {"luks",     "LUKS",           "luks",     "Container",        "LUKS\xBA\xBE",  true,  false},
        {"lvm2",     "LVM2 PV",        "lvm",      "Container",        "LABELONE",      true,  false},
        {"mdraid",   "Linux MD RAID",  "mdraid",   "Container",        "0xA92B4EFC",    true,  false},
        {"vmfs",     "VMFS",           "vmfs",     "Cluster",          "0xC001D00D",    true,  false},
        {"refs",     "ReFS",           "refs",     "Windows",          "ReFS",          true,  false},
    };
}

// ---------------------------------------------------------------------------

DetectResult detectFilesystem(DiskReader& disk) {
    DetectResult r;
    r.size_bytes = disk.size();
    r.size_mb    = r.size_bytes / 1048576.0;

    auto boot0 = disk.readBlock(0, 4096);
    Bytes b0(boot0);

    // ---- NTFS ------------------------------------------------------------
    // Must precede FAT: NTFS boot sectors also carry the 0x55AA signature.
    if (b0.eq(3, "NTFS    ", 8)) {
        u16 bps = b0.le16(11);
        u8  spc = b0.u8at(13);
        if (isPow2(bps) && bps >= 256 && bps <= 4096 && (isPow2(spc) || spc >= 0xF0)) {
            r.detected   = true;
            r.filesystem = "ntfs";
            r.family     = "ntfs";
            r.block_size = (i64)bps * (spc >= 0xF0 ? (1 << (0x100 - spc)) : spc);
            r.confidence = 1.0;
            r.uuid       = toHex(boot0.data() + 0x48, 8);
            return r;
        }
    }

    // ---- exFAT -----------------------------------------------------------
    if (b0.eq(3, "EXFAT   ", 8)) {
        r.detected   = true;
        r.filesystem = "exfat";
        r.family     = "exfat";
        u8 bpsShift  = b0.u8at(108);
        u8 spcShift  = b0.u8at(109);
        if (bpsShift <= 12 && spcShift <= 25) r.block_size = (i64)1 << (bpsShift + spcShift);
        r.confidence = 1.0;
        r.uuid       = serialToUuid(b0.le32(100));
        return r;
    }

    // ---- ext2/3/4 --------------------------------------------------------
    auto extSb = disk.readBlock(1024, 1024);
    Bytes es(extSb);
    if (es.le16(0x38) == 0xEF53) {
        u32 compat    = es.le32(0x5C);
        u32 incompat  = es.le32(0x60);
        u32 ro_compat = es.le32(0x64);
        u32 log_bs    = es.le32(0x18);
        if (log_bs <= 6) {
            r.block_size = 1024LL << log_bs;
            // EXTENTS(0x40) | 64BIT(0x80) | FLEX_BG(0x200) | META_BG(0x10)
            const u32 kExt4Incompat  = 0x40 | 0x80 | 0x200;
            const u32 kExt4RoCompat  = 0x8 | 0x10 | 0x40 | 0x80;  // huge_file, gdt_csum, ...
            if ((incompat & kExt4Incompat) || (ro_compat & kExt4RoCompat)) r.filesystem = "ext4";
            else if (compat & 0x4)                                          r.filesystem = "ext3";
            else                                                            r.filesystem = "ext2";
            r.detected   = true;
            r.family     = "ext";
            r.confidence = 1.0;
            r.label      = es.trimmed(0x78, 16);
            if (extSb.size() >= 0x68 + 16) {
                u8 uuidRaw[16];
                std::memcpy(uuidRaw, extSb.data() + 0x68, 16);
                char buf[40];
                snprintf(buf, sizeof(buf),
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         uuidRaw[0], uuidRaw[1], uuidRaw[2], uuidRaw[3], uuidRaw[4], uuidRaw[5],
                         uuidRaw[6], uuidRaw[7], uuidRaw[8], uuidRaw[9], uuidRaw[10], uuidRaw[11],
                         uuidRaw[12], uuidRaw[13], uuidRaw[14], uuidRaw[15]);
                r.uuid = buf;
            }
            return r;
        }
    }

    // ---- FAT12/16/32 -----------------------------------------------------
    {
        Bpb p = readBpb(b0);
        bool sig = b0.u8at(510) == 0x55 && b0.u8at(511) == 0xAA;
        if (bpbPlausible(p) && (sig || b0.eq(54, "FAT", 3) || b0.eq(82, "FAT32", 5))) {
            u32 clusters = 0;
            std::string flavour = fatFlavour(p, &clusters);
            r.detected   = true;
            r.family     = "fat";
            r.block_size = (i64)p.bytes_per_sector * p.sectors_per_cluster;
            r.confidence = sig ? 1.0 : 0.8;
            r.label      = fatLabel(disk, p, flavour, b0);
            r.uuid       = serialToUuid(flavour == "fat32" ? b0.le32(67) : b0.le32(39));
            r.filesystem = rootHasLfn(disk, p, flavour, b0) ? "vfat" : flavour;
            if (r.filesystem == "vfat") r.note = "FAT volume with long filenames (" + flavour + ")";
            return r;
        }
    }

    // ---- Apple -----------------------------------------------------------
    {
        auto hfs = disk.readBlock(1024, 512);
        Bytes h(hfs);
        u16 sig = h.be16(0);
        if (sig == 0x482B || sig == 0x4858) {         // 'H+' / 'HX'
            r.detected   = true;
            r.filesystem = (sig == 0x482B) ? "hfsplus" : "hfsx";
            r.family     = "hfs";
            r.block_size = h.be32(40);
            r.confidence = 1.0;
            return r;
        }
        if (sig == 0x4244) {                          // 'BD' — classic HFS
            r.detected = true; r.filesystem = "hfs"; r.family = "hfs"; r.confidence = 0.9;
            return r;
        }
    }
    if (b0.eq(32, "NXSB", 4)) {
        r.detected   = true;
        r.filesystem = "apfs";
        r.family     = "apfs";
        r.block_size = b0.le32(36);
        r.confidence = 1.0;
        return r;
    }

    // ---- Modern Linux ----------------------------------------------------
    {
        auto btr = disk.readBlock(0x10000, 0x1000);
        Bytes bs(btr);
        if (bs.eq(0x40, "_BHRfS_M", 8)) {
            r.detected   = true;
            r.filesystem = "btrfs";
            r.family     = "btrfs";
            r.block_size = bs.le32(0x90);
            r.label      = bs.trimmed(0x12B, 256);
            r.confidence = 1.0;
            if (btr.size() >= 0x20 + 16) {
                u8 g[16];
                std::memcpy(g, btr.data() + 0x20, 16);
                char buf[40];
                snprintf(buf, sizeof(buf),
                         "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                         g[0],g[1],g[2],g[3],g[4],g[5],g[6],g[7],g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
                r.uuid = buf;
            }
            return r;
        }
    }
    if (b0.eq(0, "XFSB", 4)) {
        r.detected   = true;
        r.filesystem = "xfs";
        r.family     = "xfs";
        r.block_size = b0.be32(4);
        r.label      = b0.trimmed(0x6C, 12);
        if (boot0.size() >= 0x20 + 16) {
            u8 g[16];
            std::memcpy(g, boot0.data() + 0x20, 16);
            char buf[40];
            snprintf(buf, sizeof(buf),
                     "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                     g[0],g[1],g[2],g[3],g[4],g[5],g[6],g[7],g[8],g[9],g[10],g[11],g[12],g[13],g[14],g[15]);
            r.uuid = buf;
        }
        r.confidence = 1.0;
        return r;
    }
    {
        auto f2 = disk.readBlock(1024, 512);
        Bytes fb(f2);
        if (fb.le32(0) == 0xF2F52010) {
            r.detected   = true;
            r.filesystem = "f2fs";
            r.family     = "f2fs";
            // log_blocksize lives at 0x10; 0x08 is log_sectorsize, which is
            // always 9 and made the reported block size 512 on every volume.
            u32 logBlockSize = fb.le32(0x10);
            if (logBlockSize <= 16) r.block_size = 1024LL << logBlockSize;
            r.confidence = 1.0;
            return r;
        }
    }

    // ---- ZFS (uberblock in vdev label) -----------------------------------
    for (u64 lbl : {0x0ull, 0x40000ull}) {
        for (int i = 0; i < 4; i++) {
            auto ub = disk.readBlock(lbl + 0x20000 + (u64)i * 1024, 16);
            Bytes u(ub);
            if (u.le64(0) == 0x00bab10cULL || u.be64(0) == 0x00bab10cULL) {
                r.detected = true; r.filesystem = "zfs"; r.family = "zfs"; r.confidence = 0.95;
                return r;
            }
        }
    }

    // ---- Journaling legacy ------------------------------------------------
    {
        auto jfsSb = disk.readBlock(32768, 512);
        if (Bytes(jfsSb).eq(0, "JFS1", 4)) {
            r.detected = true; r.filesystem = "jfs"; r.family = "jfs";
            r.block_size = Bytes(jfsSb).le32(24);
            r.label = Bytes(jfsSb).trimmed(101, 16);
            r.confidence = 1.0;
            return r;
        }
    }
    for (u64 off : {0x10000ull, 0x20000ull, 0x30000ull}) {
        auto rs = disk.readBlock(off + 52, 16);
        Bytes rb(rs);
        if (rb.eq(0, "ReIsErFs", 8) || rb.eq(0, "ReIsEr2Fs", 9) || rb.eq(0, "ReIsEr3Fs", 9)) {
            r.detected = true; r.filesystem = "reiserfs"; r.family = "reiserfs"; r.confidence = 1.0;
            return r;
        }
    }
    {
        auto r4 = disk.readBlock(0x10000 + 52, 8);
        if (Bytes(r4).eq(0, "ReIsEr4", 7)) {
            r.detected = true; r.filesystem = "reiser4"; r.family = "reiser4"; r.confidence = 1.0;
            return r;
        }
    }

    // ---- UFS / FFS --------------------------------------------------------
    for (auto [sbOff, magicOff] : {std::pair<u64,u64>{8192, 0x55C}, std::pair<u64,u64>{65536, 0x55C},
                                   std::pair<u64,u64>{262144, 0x55C}}) {
        auto sb = disk.readBlock(sbOff, 0x600);
        Bytes u(sb);
        u32 m = u.le32(magicOff);
        if (m == 0x00011954) { r.detected = true; r.filesystem = "ufs";  r.family = "ufs"; r.confidence = 0.95; return r; }
        if (m == 0x19540119) { r.detected = true; r.filesystem = "ufs2"; r.family = "ufs"; r.confidence = 0.95; return r; }
    }

    // ---- Read-only / embedded ---------------------------------------------
    if (b0.eq(0, "hsqs", 4) || b0.eq(0, "sqsh", 4)) {
        r.detected = true; r.filesystem = "squashfs"; r.family = "squashfs";
        r.block_size = b0.le32(12); r.confidence = 1.0;
        return r;
    }
    if (b0.le32(0) == 0x28CD3D45) {
        r.detected = true; r.filesystem = "cramfs"; r.family = "cramfs";
        r.label = b0.trimmed(48, 16); r.confidence = 1.0;
        return r;
    }
    if (b0.eq(0, "-rom1fs-", 8)) {
        r.detected = true; r.filesystem = "romfs"; r.family = "romfs"; r.confidence = 1.0;
        return r;
    }
    if (b0.le32(0) == 0xE0F5E1E2) {
        r.detected = true; r.filesystem = "erofs"; r.family = "erofs"; r.confidence = 1.0;
        return r;
    }
    if (b0.le16(0) == 0x1985) {
        r.detected = true; r.filesystem = "jffs2"; r.family = "jffs2"; r.confidence = 0.85;
        return r;
    }
    if (b0.le32(0) == 0x06101831) {
        r.detected = true; r.filesystem = "ubifs"; r.family = "ubifs"; r.confidence = 1.0;
        return r;
    }
    if (b0.eq(0, "YAFFS", 5)) {
        r.detected = true; r.filesystem = "yaffs2"; r.family = "yaffs2"; r.confidence = 0.8;
        return r;
    }
    {
        auto mx = disk.readBlock(1024, 64);
        Bytes m(mx);
        u16 magic = m.le16(0x10);
        if (magic == 0x137F || magic == 0x138F || magic == 0x2468 || magic == 0x2478) {
            r.detected = true; r.filesystem = "minix"; r.family = "minix"; r.confidence = 0.9;
            return r;
        }
        u16 magic3 = m.le16(0x18);   // MINIX v3 superblock
        if (magic3 == 0x4D5A) {
            r.detected = true; r.filesystem = "minix"; r.family = "minix"; r.confidence = 0.9;
            return r;
        }
    }

    // ---- Optical ----------------------------------------------------------
    for (int sector = 16; sector < 20; sector++) {
        auto vd = disk.readBlock((u64)sector * 2048, 8);
        Bytes v(vd);
        if (v.eq(1, "CD001", 5)) {
            // Bridge media ("genisoimage -udf") carry a UDF tree whose
            // File Identifiers hold the real long names; prefer it over the
            // 8.3-abbreviated ISO side when a valid anchor is present.
            auto avdp = disk.readBlock(0x80000ull, 16);
            Bytes a(avdp);
            if (a.le16(0) == 2 && a.le16(2) >= 1 && a.le16(2) <= 3) {
                r.detected = true; r.filesystem = "udf"; r.family = "udf"; r.confidence = 0.95;
                return r;
            }
            r.detected = true; r.filesystem = "iso9660"; r.family = "iso"; r.confidence = 1.0;
            auto pvd = disk.readBlock(0x8000, 2048);
            r.label = Bytes(pvd).trimmed(40, 32);
            return r;
        }
        if (v.eq(1, "BEA01", 5) || v.eq(1, "NSR02", 5) || v.eq(1, "NSR03", 5)) {
            r.detected = true; r.filesystem = "udf"; r.family = "udf"; r.confidence = 1.0;
            return r;
        }
    }
    for (u64 off : {0x80000ull, 0x100000ull, 0x200000ull}) {
        auto avdp = disk.readBlock(off, 16);
        Bytes a(avdp);
        if (a.le16(0) == 2 && a.le16(4) >= 1 && a.le16(4) <= 3) {
            r.detected = true; r.filesystem = "udf"; r.family = "udf"; r.confidence = 0.9;
            return r;
        }
    }

    // ---- Cluster ----------------------------------------------------------
    if (b0.eq(0, "OCFSV2", 6)) { r.detected = true; r.filesystem = "ocfs2"; r.family = "ocfs2"; r.confidence = 1.0; return r; }
    {
        auto g = disk.readBlock(0x10000, 32);
        if (Bytes(g).be32(0) == 0x01161970) {
            r.detected = true; r.filesystem = "gfs2"; r.family = "gfs2"; r.confidence = 1.0;
            return r;
        }
    }
    {
        auto v = disk.readBlock(0x100000, 16);
        if (Bytes(v).le32(0) == 0xC001D00D) {
            r.detected = true; r.filesystem = "vmfs"; r.family = "vmfs"; r.confidence = 0.9;
            return r;
        }
    }
    if (b0.eq(3, "ReFS", 4) || b0.eq(0, "ReFS", 4)) {
        r.detected = true; r.filesystem = "refs"; r.family = "refs"; r.confidence = 0.85;
        return r;
    }
    {
        auto nl = disk.readBlock(1024, 64);
        if (Bytes(nl).le16(0x38) == 0x3434) {
            r.detected = true; r.filesystem = "nilfs2"; r.family = "nilfs2"; r.confidence = 0.9;
            return r;
        }
    }
    {
        auto bc = disk.readBlock(4096, 64);
        Bytes bcb(bc);
        // bcachefs magic: c68573f6-4e1a-45ca-8265-f57f48ba6d81 at sb+24
        static const u8 kBcache[16] = {0xc6,0x85,0x73,0xf6,0x4e,0x1a,0x45,0xca,
                                       0x82,0x65,0xf5,0x7f,0x48,0xba,0x6d,0x81};
        if (bc.size() >= 40 && std::memcmp(bc.data() + 24, kBcache, 16) == 0) {
            r.detected = true; r.filesystem = "bcachefs"; r.family = "bcachefs"; r.confidence = 1.0;
            return r;
        }
    }
    {
        auto sv = disk.readBlock(0x200 + 0x3F8, 8);
        if (Bytes(sv).le32(0) == 0x012FF7B7) {
            r.detected = true; r.filesystem = "sysv"; r.family = "sysv"; r.confidence = 0.8;
            return r;
        }
        auto xi = disk.readBlock(1024 + 0x10, 8);
        if (Bytes(xi).le32(0) == 0x012FD528) {
            r.detected = true; r.filesystem = "xiafs"; r.family = "xiafs"; r.confidence = 0.8;
            return r;
        }
    }

    // ---- Containers -------------------------------------------------------
    // Not filesystems, but knowing what a volume actually is prevents a
    // pointless "unknown — carving only" and tells the user the next step.
    if (b0.eq(0, "LUKS\xBA\xBE", 6)) {
        r.filesystem   = "luks";
        r.family       = "luks";
        r.is_container = true;
        r.container    = "luks";
        r.note = "LUKS-encrypted volume — unlock it with cryptsetup, then point the engine at "
                 "/dev/mapper/<name>. Carving the ciphertext will not produce files.";
        r.detected = true;
        return r;
    }
    for (u64 off : {512ull, 0ull, 1536ull, 2048ull}) {
        auto lv = disk.readBlock(off, 64);
        Bytes l(lv);
        if (l.eq(0, "LABELONE", 8) && l.eq(24, "LVM2 001", 8)) {
            r.filesystem   = "lvm2";
            r.family       = "lvm";
            r.is_container = true;
            r.container    = "lvm2";
            r.note = "LVM2 physical volume — activate the volume group (vgchange -ay) and scan "
                     "/dev/<vg>/<lv> instead.";
            r.detected = true;
            return r;
        }
    }
    {
        auto md = disk.readBlock(4096, 8);
        if (Bytes(md).le32(0) == 0xA92B4EFC) {
            r.filesystem   = "mdraid";
            r.family       = "mdraid";
            r.is_container = true;
            r.container    = "mdraid";
            r.note = "Linux MD RAID member (superblock 1.x) — use the RAID tab to assemble the "
                     "array before recovering.";
            r.detected = true;
            return r;
        }
    }
    for (u64 pagesz : {4096ull, 8192ull, 16384ull, 65536ull}) {
        if ((i64)pagesz > disk.size()) break;
        auto sw = disk.readBlock(pagesz - 10, 10);
        Bytes s(sw);
        if (s.eq(0, "SWAPSPACE2", 10) || s.eq(0, "SWAP-SPACE", 10)) {
            r.filesystem   = "swap";
            r.family       = "swap";
            r.is_container = true;
            r.container    = "swap";
            r.note = "Linux swap area — no filesystem, but carving can still recover fragments "
                     "of documents and keys that were paged out.";
            r.detected = true;
            return r;
        }
    }

    // ---- Partition tables --------------------------------------------------
    {
        auto gpt = disk.readBlock(512, 16);
        if (Bytes(gpt).eq(0, "EFI PART", 8)) {
            r.is_container = true;
            r.container    = "gpt";
            r.note = "whole disk with a GPT partition table — choose a partition to scan";
            r.error = r.note;
            return r;
        }
        if (b0.u8at(510) == 0x55 && b0.u8at(511) == 0xAA) {
            bool anyEntry = false;
            for (int i = 0; i < 4; i++)
                if (b0.u8at(0x1BE + i * 16 + 4) != 0) anyEntry = true;
            if (anyEntry) {
                r.is_container = true;
                r.container    = "mbr";
                r.note = "whole disk with an MBR partition table — choose a partition to scan";
                r.error = r.note;
                return r;
            }
        }
    }

    r.detected = false;
    r.error = "no recognised filesystem — the volume may be encrypted, badly damaged, or "
              "formatted with an unsupported type. Signature carving will still work.";
    return r;
}

// ---------------------------------------------------------------------------
// Driver dispatch
// ---------------------------------------------------------------------------
std::vector<FsDriver> allDrivers() {
    return {
        {"ext2",     "ext2",     "ext",      ext::scan},
        {"ext3",     "ext3",     "ext",      ext::scan},
        {"ext4",     "ext4",     "ext",      ext::scan},
        {"ntfs",     "NTFS",     "ntfs",     ntfs::scan},
        {"fat12",    "FAT12",    "fat",      fat::scan},
        {"fat16",    "FAT16",    "fat",      fat::scan},
        {"fat32",    "FAT32",    "fat",      fat::scan},
        {"vfat",     "VFAT",     "fat",      fat::scan},
        {"exfat",    "exFAT",    "exfat",    exfat::scan},
        {"xfs",      "XFS",      "xfs",      xfs::scan},
        {"btrfs",    "Btrfs",    "btrfs",    btrfs::scan},
        {"f2fs",     "F2FS",     "f2fs",     f2fs::scan},
        {"hfsplus",  "HFS+",     "hfs",      hfs::scan},
        {"hfsx",     "HFSX",     "hfs",      hfs::scan},
        {"hfs",      "HFS",      "hfs",      hfs::scan},
        {"apfs",     "APFS",     "apfs",     apfs::scan},
        {"iso9660",  "ISO 9660", "iso",      iso9660::scan},
        {"udf",      "UDF",      "udf",      udf::scan},
        {"squashfs", "SquashFS", "squashfs", squashfs::scan},
        {"cramfs",   "cramfs",   "cramfs",   cramfs::scan},
        {"romfs",    "romfs",    "romfs",    romfs::scan},
        {"minix",    "MINIX",    "minix",    minixfs::scan},
        {"jffs2",    "JFFS2",    "jffs2",    jffs2::scan},
        {"ufs",      "UFS",      "ufs",      ufs::scan},
        {"ufs2",     "UFS2",     "ufs",      ufs::scan},
        {"reiserfs", "ReiserFS", "reiserfs", reiserfs::scan},
        {"jfs",      "JFS",      "jfs",      jfs::scan},
        {"zfs",      "ZFS",      "zfs",      zfs::scan},
    };
}

const FsDriver* findDriver(const std::string& fsId) {
    static const std::vector<FsDriver> drivers = allDrivers();
    for (const auto& d : drivers)
        if (fsId == d.id) return &d;
    return nullptr;
}

ScanResult scanVolume(DiskReader& disk, const std::string& fsId, const ScanOptions& opt,
                      Progress& prog) {
    ScanResult res;
    std::string fs = fsId;

    if (fs.empty()) {
        prog.setPhase("identifying filesystem");
        DetectResult d = detectFilesystem(disk);
        if (!d.detected || d.is_container) {
            res.ok = false;
            res.filesystem = d.filesystem;
            res.error = d.error.empty()
                            ? (d.note.empty() ? "no filesystem detected on this volume" : d.note)
                            : d.error;
            return res;
        }
        fs = d.filesystem;
        res.label = d.label;
        res.uuid  = d.uuid;
    }

    const FsDriver* drv = findDriver(fs);
    if (!drv) {
        res.ok = false;
        res.filesystem = fs;
        res.error = "no metadata driver for '" + fs + "' — use signature carving on this volume";
        return res;
    }

    prog.setPhase(std::string("scanning ") + drv->name);
    std::string label = res.label, uuid = res.uuid;
    res = drv->scan(disk, opt, prog);
    if (res.filesystem.empty()) res.filesystem = fs;
    if (res.label.empty()) res.label = label;
    if (res.uuid.empty())  res.uuid  = uuid;
    res.volume_size = disk.size();

    // Drivers report the deleted count themselves, but recompute so the number
    // in the UI always matches the rows in the table.
    i64 del = 0;
    for (const auto& f : res.files) if (f.is_deleted) del++;
    res.deleted_found = del;
    return res;
}

// ---------------------------------------------------------------------------
void finalizeFile(RecoveredFile& f, i64 volumeSize) {
    std::vector<Extent> keep;
    keep.reserve(f.extents.size());
    i64 total = 0;
    for (auto e : f.extents) {
        if (e.length <= 0) continue;
        if (e.sparse) {
            // A hole holds no recoverable data; keep it so the extent list
            // still describes the file, but never count it as recoverable.
            keep.push_back(e);
            continue;
        }
        if (e.offset < 0 || e.offset >= volumeSize) continue;
        if (e.offset + e.length > volumeSize) e.length = volumeSize - e.offset;
        if (e.length <= 0) continue;
        keep.push_back(e);
        total += e.length;
    }
    f.extents = std::move(keep);

    if (!f.resident.empty()) {
        f.recoverable = (i64)f.resident.size();
        if (f.size <= 0) f.size = f.recoverable;
        return;
    }
    // Extents that hold compressed blocks are shorter or longer than the logical
    // size by definition, and the last one may be a shared fragment. Trimming
    // them to f.size would cut the compressed stream in half.
    if (!f.codec.empty() || f.fragment_offset >= 0) {
        f.recoverable = f.size > 0 ? f.size : total;
        if (f.alloc_size <= 0) f.alloc_size = total;
        return;
    }
    // Trim the tail of the last extent down to the logical size — cluster runs
    // are allocation-granular and would otherwise pad every file with slack.
    if (f.size > 0 && total > f.size) {
        i64 excess = total - f.size;
        while (excess > 0 && !f.extents.empty()) {
            Extent& last = f.extents.back();
            if (last.length <= excess) { excess -= last.length; f.extents.pop_back(); }
            else { last.length -= excess; excess = 0; }
        }
        total = f.size;
    }
    f.recoverable = total;
    if (f.size <= 0) f.size = total;
    if (f.alloc_size <= 0) f.alloc_size = total;
}

bool extentsPlausible(const std::vector<Extent>& ex, i64 size, i64 volumeSize) {
    if (ex.empty()) return size == 0;
    i64 total = 0;
    for (const auto& e : ex) {
        if (e.length <= 0) return false;
        if (!e.sparse && (e.offset < 0 || e.offset + e.length > volumeSize)) return false;
        total += e.length;
        if (total > volumeSize) return false;
    }
    if (size > 0 && total + 65536 < size) return false;   // far too little data for the size
    return true;
}

}  // namespace ghost
