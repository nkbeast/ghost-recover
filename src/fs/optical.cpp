// GHOST//RECOVER — ISO 9660 (with Joliet and Rock Ridge) and UDF.
//
// The old ISO parser walked directory records but mangled every name: it
// compared the "." and ".." entries against string literals that can never
// match a one-byte identifier, never read the Joliet supplementary descriptor
// it claimed to detect, and ignored Rock Ridge entirely. UDF was a stub that
// returned nothing at all.
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <set>
#include <unordered_map>
#include <vector>

namespace ghost {

// ===========================================================================
// ISO 9660
// ===========================================================================
namespace iso9660 {
namespace {

constexpr u32 kSector = 2048;

struct DirRec {
    u32 lba = 0;
    u32 size = 0;
    u8  flags = 0;
    std::string name;
    i64 mtime = 0;
    u32 mode = 0;
    bool valid = false;
    size_t length = 0;
};

i64 isoDateToUnix(const Bytes& b, size_t o) {
    if (!b.has(o, 7)) return 0;
    struct tm tmv{};
    tmv.tm_year = b.u8at(o);              // years since 1900
    tmv.tm_mon  = (int)b.u8at(o + 1) - 1;
    tmv.tm_mday = b.u8at(o + 2);
    tmv.tm_hour = b.u8at(o + 3);
    tmv.tm_min  = b.u8at(o + 4);
    tmv.tm_sec  = b.u8at(o + 5);
    if (tmv.tm_mon < 0 || tmv.tm_mon > 11 || tmv.tm_mday < 1) return 0;
    time_t t = timegm(&tmv);
    if (t == (time_t)-1) return 0;
    i8 tz = (i8)b.u8at(o + 6);            // 15-minute offsets from GMT
    return (i64)t - (i64)tz * 15 * 60;
}

// Rock Ridge / SUSP: pull the real POSIX name and metadata out of the system
// use area that follows the ISO name.
void parseSusp(const Bytes& b, size_t start, size_t end, std::string& nameOut,
               u32& modeOut, i64& mtimeOut, bool& sawRockRidge) {
    size_t p = start;
    int guard = 0;
    while (p + 4 <= end && guard++ < 256) {
        char sig0 = (char)b.u8at(p);
        char sig1 = (char)b.u8at(p + 1);
        u8   len  = b.u8at(p + 2);
        if (len < 4 || p + len > end) break;
        if (sig0 == 'N' && sig1 == 'M') {
            u8 flags = b.u8at(p + 4);
            size_t textLen = len - 5;
            if (textLen && b.has(p + 5, textLen)) {
                std::string part = b.str(p + 5, textLen);
                if (flags & 0x01) nameOut += part;      // CONTINUE
                else nameOut = part;
                sawRockRidge = true;
            }
        } else if (sig0 == 'P' && sig1 == 'X' && len >= 36) {
            modeOut = b.le32(p + 4);
            sawRockRidge = true;
        } else if (sig0 == 'T' && sig1 == 'F' && len >= 5) {
            u8 flags = b.u8at(p + 4);
            size_t q = p + 5;
            bool longForm = (flags & 0x80) != 0;
            size_t stamp = longForm ? 17 : 7;
            // bit 0 create, bit 1 modify, bit 2 access
            if (flags & 0x01) q += stamp;
            if (flags & 0x02) {
                if (!longForm) mtimeOut = isoDateToUnix(b, q);
                sawRockRidge = true;
            }
        } else if (sig0 == 'S' && sig1 == 'T') {
            break;
        }
        p += len;
    }
}

DirRec parseDirRec(const Bytes& b, size_t p, bool joliet) {
    DirRec r;
    u8 len = b.u8at(p);
    if (len < 33 || !b.has(p, len)) return r;
    r.length = len;
    u8 extAttrLen = b.u8at(p + 1);
    r.lba   = b.le32(p + 2) + extAttrLen;
    r.size  = b.le32(p + 10);
    r.mtime = isoDateToUnix(b, p + 18);
    r.flags = b.u8at(p + 25);
    u8 nameLen = b.u8at(p + 32);
    if (!b.has(p + 33, nameLen)) return r;

    if (nameLen == 1 && (b.u8at(p + 33) == 0 || b.u8at(p + 33) == 1)) {
        r.name = (b.u8at(p + 33) == 0) ? "." : "..";
    } else if (joliet) {
        r.name = utf16beToUtf8(b.p + p + 33, nameLen);
    } else {
        r.name = b.str(p + 33, nameLen);
    }
    // Strip the ";1" version suffix and a trailing dot on extension-less names.
    size_t semi = r.name.find(';');
    if (semi != std::string::npos) r.name.resize(semi);
    if (!r.name.empty() && r.name.back() == '.') r.name.pop_back();

    size_t sysStart = p + 33 + nameLen;
    if ((nameLen & 1) == 0) sysStart++;              // padding byte
    size_t sysEnd = p + len;
    bool rr = false;
    if (sysStart < sysEnd) parseSusp(b, sysStart, sysEnd, r.name, r.mode, r.mtime, rr);
    r.valid = !r.name.empty();
    return r;
}

}  // namespace

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "iso9660";
    const i64 volume = disk.size();

    // Volume descriptor set starts at sector 16.
    u32 rootLba = 0, rootSize = 0;
    u32 jolietRootLba = 0, jolietRootSize = 0;
    bool haveJoliet = false;
    for (int sector = 16; sector < 40; sector++) {
        auto vd = disk.readBlock((u64)sector * kSector, kSector);
        Bytes b(vd);
        if (vd.size() < kSector || !b.eq(1, "CD001", 5)) {
            if (vd.size() >= 6 && b.u8at(0) == 0xFF) break;
            continue;
        }
        u8 type = b.u8at(0);
        if (type == 0xFF) break;                     // terminator
        if (type == 1) {                             // primary
            rootLba  = b.le32(158);
            rootSize = b.le32(166);
            res.label = b.trimmed(40, 32);
            res.total_blocks = b.le32(80);
            res.block_size = b.le16(128);
        } else if (type == 2) {                      // supplementary — Joliet?
            std::string esc = b.str(88, 32);
            if (esc.compare(0, 3, "%/@") == 0 || esc.compare(0, 3, "%/C") == 0 ||
                esc.compare(0, 3, "%/E") == 0) {
                haveJoliet = true;
                jolietRootLba  = b.le32(158);
                jolietRootSize = b.le32(166);
            }
        }
    }

    if (rootLba == 0 && jolietRootLba == 0) {
        res.ok = false;
        res.error = "no ISO 9660 primary volume descriptor found in sectors 16-40";
        return res;
    }

    res.ok = true;
    res.volume_size = volume;
    if (res.block_size == 0) res.block_size = kSector;
    res.technique("volume_descriptor_parse");
    res.technique("recursive_directory_walk");

    bool useJoliet = haveJoliet && jolietRootLba != 0;
    if (useJoliet) {
        res.technique("joliet_supplementary_descriptor");
        res.bump("joliet", 1);
        rootLba  = jolietRootLba;
        rootSize = jolietRootSize;
    }

    prog.setPhase("walking ISO directory tree");
    struct Pending { u32 lba, size; std::string path; };
    std::vector<Pending> queue{{rootLba, rootSize, ""}};
    std::set<u32> visited;
    std::set<u64> claimed;      // sectors used by known files, for the orphan pass
    bool sawRockRidge = false;
    i64 dirs = 0;

    while (!queue.empty() && !prog.cancelled() && (i64)res.files.size() < opt.max_files) {
        Pending cur = queue.back();
        queue.pop_back();
        if (cur.lba == 0 || cur.size == 0) continue;
        if (!visited.insert(cur.lba).second) continue;
        i64 off = (i64)cur.lba * kSector;
        if (off < 0 || off >= volume) continue;
        i64 want = std::min<i64>(cur.size, 32LL * 1024 * 1024);
        auto buf = disk.readBlock((u64)off, want);
        if (buf.empty()) continue;
        Bytes b(buf);
        dirs++;

        size_t p = 0;
        while (p < b.size()) {
            u8 len = b.u8at(p);
            if (len == 0) {
                // Records never straddle a sector; skip to the next one.
                size_t next = ((p / kSector) + 1) * kSector;
                if (next <= p) break;
                p = next;
                continue;
            }
            DirRec r = parseDirRec(b, p, useJoliet);
            p += len;
            if (!r.valid || r.name == "." || r.name == "..") continue;
            if (r.mode) sawRockRidge = true;

            std::string path = cur.path + "/" + r.name;
            if (r.flags & 0x02) {
                queue.push_back({r.lba, r.size, path});
                RecoveredFile f;
                f.id = r.lba;
                f.name = r.name;
                f.path = path;
                f.is_dir = true;
                f.kind = FileKind::Directory;
                f.mtime = r.mtime;
                f.mode = r.mode & 0x0FFF;
                f.method = "recursive_directory_walk";
                res.files.push_back(std::move(f));
                continue;
            }

            RecoveredFile f;
            f.id = r.lba;
            f.name = r.name;
            f.path = path;
            f.size = r.size;
            f.mtime = r.mtime;
            f.mode = r.mode & 0x0FFF;
            f.method = "extent_data_recovery";
            i64 fo = (i64)r.lba * kSector;
            if (fo >= 0 && fo < volume && r.size > 0) f.extents.push_back(Extent(fo, r.size));
            for (u64 s = r.lba; s < (u64)r.lba + (r.size + kSector - 1) / kSector; s++)
                claimed.insert(s);
            finalizeFile(f, volume);
            res.files.push_back(std::move(f));
        }
    }
    if (sawRockRidge) { res.technique("rock_ridge_extensions"); res.bump("rock_ridge", 1); }
    res.bump("directories", dirs);

    // ---- orphaned directory records ---------------------------------------
    // Multi-session discs and truncated burns leave directory records that the
    // active volume descriptor no longer references.
    if (opt.orphans && !prog.cancelled()) {
        prog.setPhase("scanning for orphaned ISO records");
        i64 orphans = 0;
        i64 limit = std::min<i64>(volume, 8LL * 1024 * 1024 * 1024);
        for (i64 off = 0; off + (i64)kSector <= limit && orphans < 20000; off += kSector) {
            u64 sec = (u64)(off / kSector);
            if (visited.count((u32)sec) || claimed.count(sec)) continue;
            auto buf = disk.readBlock((u64)off, kSector);
            if (buf.size() < 64) break;
            Bytes b(buf);
            // A directory extent starts with the "." record: length >= 34,
            // name length 1, identifier 0x00.
            if (b.u8at(0) < 34 || b.u8at(32) != 1 || b.u8at(33) != 0) continue;
            if (!(b.u8at(25) & 0x02)) continue;
            size_t p = 0;
            int found = 0;
            while (p < b.size() && found < 256) {
                u8 len = b.u8at(p);
                if (len == 0) break;
                DirRec r = parseDirRec(b, p, false);
                p += len;
                if (!r.valid || r.name == "." || r.name == ".." || (r.flags & 0x02)) continue;
                if (claimed.count(r.lba)) continue;
                RecoveredFile f;
                f.id = r.lba;
                f.name = r.name;
                f.path = "/$orphans/" + r.name;
                f.size = r.size;
                f.mtime = r.mtime;
                f.is_deleted = true;
                f.confidence = 0.5;
                f.method = "orphaned_directory_record_scan";
                i64 fo = (i64)r.lba * kSector;
                if (fo >= 0 && fo < volume && r.size > 0) f.extents.push_back(Extent(fo, r.size));
                finalizeFile(f, volume);
                res.files.push_back(std::move(f));
                orphans++;
                found++;
            }
        }
        if (orphans) {
            res.technique("orphaned_directory_record_scan");
            res.bump("orphaned_records", orphans);
        }
    }

    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace iso9660

// ===========================================================================
// UDF
// ===========================================================================
namespace udf {
namespace {

struct Tag {
    u16 id = 0;
    u16 version = 0;
    u32 location = 0;
    bool valid = false;
};


Tag readTag(const Bytes& b, size_t o) {
    Tag t;
    if (!b.has(o, 16)) return t;
    t.id = b.le16(o);
    t.version = b.le16(o + 2);
    t.location = b.le32(o + 12);
    // Checksum byte 4 covers bytes 0-3 and 5-15.
    u8 sum = 0;
    for (int i = 0; i < 16; i++) { if (i == 4) continue; sum = (u8)(sum + b.u8at(o + i)); }
    t.valid = (sum == b.u8at(o + 4)) && t.id != 0;
    return t;
}

std::string dstring(const Bytes& b, size_t o, size_t len) {
    if (!b.has(o, len) || len < 2) return {};
    u8 enc = b.u8at(o);
    size_t actual = b.u8at(o + len - 1);   // last byte holds the used length
    if (actual == 0 || actual > len) actual = len;
    if (enc == 8)  return b.str(o + 1, actual - 1);
    if (enc == 16) return utf16beToUtf8(b.p + o + 1, actual - 1);
    return {};
}

// UDF block size follows the medium, not the format: optical media use 2048
// but hard disks, USB sticks and disk images are usually 512. Assuming 2048
// made every hard-disk-formatted UDF volume unreadable. The anchor descriptor
// records its own block address, so probing candidate sizes and requiring that
// address to match identifies the real one rather than guessing.
u32 detectBlockSize(DiskReader& d, i64 volume, u64* anchorBlockOut) {
    static const u32 kSizes[] = {2048, 512, 1024, 4096};
    for (u32 bs : kSizes) {
        if ((i64)bs * 257 > volume) continue;
        u64 lastBlock = (u64)(volume / bs) - 1;
        u64 candidates[4] = {256, lastBlock, lastBlock > 256 ? lastBlock - 256 : 0, 512};
        for (u64 blk : candidates) {
            if (blk == 0 || (i64)((blk + 1) * bs) > volume) continue;
            auto raw = d.readBlock(blk * bs, 512);
            Bytes b(raw);
            Tag t = readTag(b, 0);
            // A descriptor records the block it lives in; that is what makes
            // this probe decisive rather than a guess.
            if (t.valid && t.id == 2 && t.location == (u32)blk) {
                if (anchorBlockOut) *anchorBlockOut = blk;
                return bs;
            }
        }
    }
    return 0;
}

}  // namespace

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "udf";
    const i64 volume = disk.size();
    res.volume_size = volume;

    // ---- anchor volume descriptor pointer --------------------------------
    prog.setPhase("locating UDF anchor");
    u64 anchorBlock = 0;
    const u32 blockSize = detectBlockSize(disk, volume, &anchorBlock);
    if (!blockSize) {
        res.ok = false;
        res.error = "no UDF anchor volume descriptor pointer found at any supported block size";
        return res;
    }
    res.bump("descriptor_block_size", blockSize);

    u32 vdsLoc = 0, vdsLen = 0;
    {
        auto raw = disk.readBlock(anchorBlock * blockSize, blockSize);
        Bytes b(raw);
        vdsLen = b.le32(16);
        vdsLoc = b.le32(20);
    }
    if (!vdsLoc) {
        res.ok = false;
        res.error = "the UDF anchor descriptor does not point at a volume descriptor sequence";
        return res;
    }

    // ---- volume descriptor sequence ---------------------------------------
    prog.setPhase("reading UDF volume descriptors");
    u32 partStart = 0, partLength = 0;
    u32 logicalBlockSize = blockSize;
    u32 fsdLba = 0;
    std::string label;
    u32 sectors = vdsLen / blockSize;
    if (sectors == 0 || sectors > 256) sectors = 64;
    for (u32 i = 0; i < sectors; i++) {
        auto raw = disk.readBlock((u64)(vdsLoc + i) * blockSize, blockSize);
        Bytes b(raw);
        Tag t = readTag(b, 0);
        if (!t.valid) continue;
        if (t.id == 1) {                       // Primary Volume Descriptor
            label = dstring(b, 24, 32);
        } else if (t.id == 5) {                // Partition Descriptor
            partStart  = b.le32(188);
            partLength = b.le32(192);
        } else if (t.id == 6) {                // Logical Volume Descriptor
            logicalBlockSize = b.le32(212);
            // logicalVolumeContentsUse is a long_ad pointing at the File Set
            fsdLba = b.le32(248 + 4);
        } else if (t.id == 8) {                // Terminating Descriptor
            break;
        }
    }
    if (logicalBlockSize < 512 || logicalBlockSize > 65536) logicalBlockSize = blockSize;

    auto lbToByte = [&](u32 lb) -> i64 { return (i64)(partStart + lb) * logicalBlockSize; };

    if (fsdLba == 0 && partLength == 0) {
        res.ok = false;
        res.error = "UDF partition and logical volume descriptors are unreadable";
        return res;
    }

    res.ok = true;
    res.label = label;
    res.block_size = logicalBlockSize;
    res.total_blocks = partLength;
    res.technique("anchor_and_vds_parse");

    // ---- file set descriptor -> root ICB -----------------------------------
    u32 rootIcb = 0;
    {
        auto raw = disk.readBlock((u64)lbToByte(fsdLba), std::max<u32>(blockSize, 512));
        Bytes b(raw);
        Tag t = readTag(b, 0);
        if (t.valid && t.id == 256) rootIcb = b.le32(400 + 4);
    }
    if (rootIcb == 0) {
        res.error = "UDF file set descriptor did not yield a root ICB";
        return res;
    }
    res.technique("file_set_descriptor");

    // ---- walk file entries -------------------------------------------------
    prog.setPhase("walking UDF file entries");

    struct Fe {
        bool valid = false;
        bool isDir = false;
        u64  informationLength = 0;
        i64  mtime = 0;
        u32  permissions = 0;
        u16  linkCount = 0;
        std::vector<Extent> extents;
        std::vector<u8> inlineData;
    };

    auto readFileEntry = [&](u32 lb) -> Fe {
        Fe fe;
        auto raw = disk.readBlock((u64)lbToByte(lb), std::max<u32>(blockSize, logicalBlockSize));
        Bytes b(raw);
        Tag t = readTag(b, 0);
        if (!t.valid) return fe;
        bool extended;
        if (t.id == 261) extended = false;
        else if (t.id == 266) extended = true;
        else return fe;

        size_t icbTag = 16;
        u8 fileType = b.u8at(icbTag + 11);
        u16 icbFlags = b.le16(icbTag + 18);
        fe.isDir = (fileType == 4);
        fe.linkCount = b.le16(48);
        fe.permissions = b.le32(44);
        fe.informationLength = b.le64(56);
        // Timestamp: 12-byte UDF timestamp, year is a signed 16-bit at +2.
        size_t modOff = extended ? 96 : 84;
        {
            struct tm tmv{};
            tmv.tm_year = (i16)b.le16(modOff + 2) - 1900;
            tmv.tm_mon  = (int)b.u8at(modOff + 4) - 1;
            tmv.tm_mday = b.u8at(modOff + 5);
            tmv.tm_hour = b.u8at(modOff + 6);
            tmv.tm_min  = b.u8at(modOff + 7);
            tmv.tm_sec  = b.u8at(modOff + 8);
            if (tmv.tm_mon >= 0 && tmv.tm_mon <= 11 && tmv.tm_mday >= 1) {
                time_t tt = timegm(&tmv);
                if (tt != (time_t)-1) fe.mtime = (i64)tt;
            }
        }

        size_t lenEaOff = extended ? 208 : 168;
        u32 lenEa = b.le32(lenEaOff);
        u32 lenAd = b.le32(lenEaOff + 4);
        size_t adStart = (extended ? 216 : 176) + lenEa;
        u8 adType = (u8)(icbFlags & 0x07);

        if (adType == 3) {                       // data stored inline in the ICB
            if (b.has(adStart, lenAd))
                fe.inlineData.assign(b.p + adStart, b.p + adStart + lenAd);
            fe.valid = true;
            return fe;
        }

        size_t adSize = (adType == 0) ? 8 : (adType == 1 ? 16 : 20);
        for (size_t p = adStart; p + adSize <= adStart + lenAd && b.has(p, adSize); p += adSize) {
            u32 lenField = b.le32(p);
            u32 extLen = lenField & 0x3FFFFFFFu;
            u8  extType = (u8)(lenField >> 30);
            if (extLen == 0) break;
            u32 pos = b.le32(p + 4);
            if (extType == 1 || extType == 3) continue;   // not-recorded / continuation
            i64 off = lbToByte(pos);
            if (off < 0 || off >= volume) continue;
            fe.extents.push_back(Extent(off, extLen));
        }
        fe.valid = true;
        return fe;
    };

    struct Pending { u32 icb; std::string path; };
    std::vector<Pending> queue{{rootIcb, ""}};
    std::set<u32> visited;
    i64 entries = 0;

    while (!queue.empty() && !prog.cancelled() && (i64)res.files.size() < opt.max_files) {
        Pending cur = queue.back();
        queue.pop_back();
        if (!visited.insert(cur.icb).second) continue;
        Fe dir = readFileEntry(cur.icb);
        if (!dir.valid || !dir.isDir) continue;

        // Concatenate the directory's extents and walk the FIDs.
        std::vector<u8> buf;
        for (const auto& e : dir.extents) {
            auto part = disk.readBlock((u64)e.offset, std::min<i64>(e.length, 16LL * 1024 * 1024));
            buf.insert(buf.end(), part.begin(), part.end());
            if (buf.size() > 32u * 1024 * 1024) break;
        }
        if (buf.empty() && !dir.inlineData.empty()) buf = dir.inlineData;
        Bytes b(buf);

        size_t p = 0;
        while (p + 38 <= b.size()) {
            Tag t = readTag(b, p);
            if (!t.valid || t.id != 257) {
                p += 4;
                continue;
            }
            u8  chars   = b.u8at(p + 18);
            u8  idLen   = b.u8at(p + 19);
            u32 childLb = b.le32(p + 20 + 4);
            u16 lenImpl = b.le16(p + 36);
            size_t nameOff = p + 38 + lenImpl;
            size_t total = 38 + lenImpl + idLen;
            total = (total + 3) & ~size_t(3);

            bool isParent = (chars & 0x08) != 0;
            bool isDeleted = (chars & 0x04) != 0;
            bool isDirFlag = (chars & 0x02) != 0;
            std::string name;
            if (idLen && b.has(nameOff, idLen)) name = dstring(b, nameOff, idLen);
            p += total;
            if (isParent || name.empty()) continue;
            entries++;

            std::string path = cur.path + "/" + name;
            if (isDirFlag && !isDeleted) queue.push_back({childLb, path});

            Fe fe = readFileEntry(childLb);
            RecoveredFile f;
            f.id = childLb;
            f.name = name;
            f.path = path;
            f.is_dir = isDirFlag;
            f.kind = isDirFlag ? FileKind::Directory : FileKind::Regular;
            f.is_deleted = isDeleted;
            f.mtime = fe.mtime;
            f.mode = fe.permissions & 0x0FFF;
            f.nlink = fe.linkCount;
            f.size = (i64)fe.informationLength;
            f.method = isDeleted ? "deleted_file_identifier" : "file_entry_walk";
            if (!fe.inlineData.empty()) {
                f.resident = fe.inlineData;
                f.method += "+inline_ad";
            } else {
                f.extents = fe.extents;
            }
            finalizeFile(f, volume);
            if (isDeleted) f.confidence = f.recoverable > 0 ? 0.7 : 0.2;
            res.files.push_back(std::move(f));
        }
    }

    res.technique("file_entry_walk");
    res.technique("allocation_descriptor_decoding");
    res.bump("file_identifiers", entries);
    prog.setFound((i64)res.files.size());
    return res;
}

}  // namespace udf
}  // namespace ghost
