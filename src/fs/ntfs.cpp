// GHOST//RECOVER — NTFS driver.
//
// The previous file was a 13-line stub that returned an empty result with a
// list of technique names it never implemented, so every NTFS volume recovered
// zero files. This is a real implementation:
//
//   boot sector + $MFT bootstrap (with $MFTMirr and raw "FILE" scan fallbacks)
//   update-sequence fixups
//   resident and non-resident attributes, $ATTRIBUTE_LIST continuation records
//   signed runlist decoding, sparse runs, alternate data streams
//   $FILE_NAME parent references -> full path reconstruction
//   deleted record detection, $I30 index-slack mining, $UsnJrnl change journal
#include "ghost/fs.h"

#include "ghost/util.h"

#include <algorithm>
#include <cstring>
#include <map>
#include <set>
#include <unordered_map>

namespace ghost {
namespace ntfs {

namespace {

constexpr u32 kAttrStandardInfo = 0x10;
constexpr u32 kAttrFileName     = 0x30;
constexpr u32 kAttrVolumeName   = 0x60;
constexpr u32 kAttrData         = 0x80;
constexpr u32 kAttrIndexRoot    = 0x90;
constexpr u32 kAttrIndexAlloc   = 0xA0;
constexpr u32 kAttrEnd          = 0xFFFFFFFF;

constexpr u16 kRecInUse     = 0x0001;
constexpr u16 kRecDirectory = 0x0002;

constexpr u16 kAttrCompressed = 0x0001;
constexpr u16 kAttrEncrypted  = 0x4000;
constexpr u16 kAttrSparse     = 0x8000;

struct Run {
    i64  lcn = 0;      // -1 for a sparse run
    i64  clusters = 0;
};

// Decodes an NTFS runlist. Each element is a header byte whose nibbles give the
// widths of the following length and offset fields; the offset is a *signed*
// delta from the previous run's LCN, which is why it must be sign-extended.
std::vector<Run> decodeRunlist(const Bytes& b, size_t off, i64 maxClusters) {
    std::vector<Run> runs;
    i64 lcn = 0;
    size_t p = off;
    while (b.has(p, 1)) {
        u8 head = b.u8at(p);
        if (head == 0) break;
        int lenLen = head & 0x0F;
        int offLen = (head >> 4) & 0x0F;
        if (lenLen == 0 || lenLen > 8 || offLen > 8) break;
        p++;
        if (!b.has(p, (size_t)(lenLen + offLen))) break;

        i64 length = (i64)b.ule(p, lenLen);
        p += lenLen;
        if (length <= 0) break;
        if (maxClusters > 0 && length > maxClusters) length = maxClusters;

        if (offLen == 0) {
            runs.push_back({-1, length});          // sparse
        } else {
            i64 delta = b.sle(p, offLen);
            p += offLen;
            lcn += delta;
            if (lcn < 0) break;
            runs.push_back({lcn, length});
        }
        if (runs.size() > 65536) break;
    }
    return runs;
}

struct Attr {
    u32  type = 0;
    bool nonresident = false;
    u16  flags = 0;
    std::string name;         // empty = unnamed stream
    // resident
    std::vector<u8> value;
    // non-resident
    i64  start_vcn = 0, last_vcn = 0;
    i64  alloc_size = 0, real_size = 0, init_size = 0;
    std::vector<Run> runs;
    u16  attr_id = 0;
};

struct Record {
    bool valid = false;
    bool in_use = false;
    bool is_dir = false;
    u64  record_no = 0;
    u64  base_ref = 0;
    u16  sequence = 0;
    u16  link_count = 0;
    std::vector<Attr> attrs;
};

// -------------------------------------------------------------------------
struct NtfsFs {
    DiskReader* d = nullptr;
    i64  volume = 0;
    u32  sector_size = 512;
    u32  cluster_size = 4096;
    u32  record_size = 1024;
    u32  index_size = 4096;
    u64  total_sectors = 0;
    u64  mft_lcn = 0, mftmirr_lcn = 0;
    std::string serial, label;
    std::vector<Run> mft_runs;
    u64  mft_records = 0;

    i64 clusterOffset(i64 lcn) const { return lcn * (i64)cluster_size; }

    bool readBoot(std::string* err) {
        auto raw = d->readBlock(0, 512);
        Bytes b(raw);
        if (raw.size() < 512) { if (err) *err = "cannot read NTFS boot sector"; return false; }
        if (!b.eq(3, "NTFS    ", 8)) { if (err) *err = "NTFS OEM signature missing"; return false; }

        sector_size = b.le16(0x0B);
        u8 spc = b.u8at(0x0D);
        // A negative exponent encodes a power of two; clamp the shift so a
        // hostile byte cannot shift a 1u past its width (UB).
        u32 sectorsPerCluster = (spc > 0x80)
                                    ? (1u << std::min<unsigned>(31, 0x100u - (u32)spc))
                                    : (u32)spc;
        if (sector_size < 256 || sector_size > 4096 || (sector_size & (sector_size - 1)))
            { if (err) *err = "implausible bytes-per-sector"; return false; }
        if (sectorsPerCluster == 0 || sectorsPerCluster > 256)
            { if (err) *err = "implausible sectors-per-cluster"; return false; }
        cluster_size  = sector_size * sectorsPerCluster;
        total_sectors = b.le64(0x28);
        mft_lcn       = b.le64(0x30);
        mftmirr_lcn   = b.le64(0x38);

        // (1u << 0x80) would be UB; derive the magnitude without negating the
        // most negative i8 and clamp the shift to 31 bits.
        u8 b40 = b.u8at(0x40);
        i8 cpr = (i8)b40;
        u32 cprShift = (u32)(-1 - cpr) + 1u;
        record_size = (cpr < 0) ? (1u << std::min<unsigned>(31, cprShift))
                                : (u32)cpr * cluster_size;
        u8 b44 = b.u8at(0x44);
        i8 cpi = (i8)b44;
        u32 cpiShift = (u32)(-1 - cpi) + 1u;
        index_size = (cpi < 0) ? (1u << std::min<unsigned>(31, cpiShift))
                               : (u32)cpi * cluster_size;
        if (record_size < 256 || record_size > 65536) record_size = 1024;
        if (index_size < 256 || index_size > 1 << 20) index_size = 4096;

        serial = toHex(raw.data() + 0x48, 8);
        return true;
    }

    // Update-sequence fixups: NTFS overwrites the last two bytes of every
    // sector in a metadata block with a check value and stores the originals in
    // an array. Without restoring them, every structure that straddles a sector
    // boundary is silently corrupt.
    bool applyFixups(std::vector<u8>& blk) const {
        Bytes b(blk);
        u16 usaOff = b.le16(0x04);
        u16 usaCount = b.le16(0x06);
        if (usaCount == 0 || usaOff == 0) return false;
        if (!b.has(usaOff, (size_t)usaCount * 2)) return false;
        u16 usn = b.le16(usaOff);
        for (u16 i = 1; i < usaCount; i++) {
            size_t secEnd = (size_t)i * sector_size - 2;
            if (secEnd + 2 > blk.size()) return false;
            u16 cur = (u16)(blk[secEnd] | (u16)blk[secEnd + 1] << 8);
            if (cur != usn) return false;                    // block is torn
            u16 orig = b.le16(usaOff + (size_t)i * 2);
            blk[secEnd]     = (u8)(orig & 0xFF);
            blk[secEnd + 1] = (u8)(orig >> 8);
        }
        return true;
    }

    std::vector<Attr> parseAttrs(const std::vector<u8>& rec) const {
        std::vector<Attr> out;
        Bytes b(rec);
        size_t p = b.le16(0x14);
        u32 used = b.le32(0x18);
        size_t limit = std::min<size_t>(rec.size(), used ? used : rec.size());
        int guard = 0;
        while (p + 8 <= limit && guard++ < 512) {
            u32 type = b.le32(p);
            if (type == kAttrEnd) break;
            u32 len = b.le32(p + 4);
            if (len < 16 || p + len > limit) break;

            Attr a;
            a.type        = type;
            a.nonresident = b.u8at(p + 8) != 0;
            u8  nameLen   = b.u8at(p + 9);
            u16 nameOff   = b.le16(p + 0x0A);
            a.flags       = b.le16(p + 0x0C);
            a.attr_id     = b.le16(p + 0x0E);
            if (nameLen && b.has(p + nameOff, (size_t)nameLen * 2))
                a.name = utf16leToUtf8(b.p + p + nameOff, (size_t)nameLen * 2);

            if (!a.nonresident) {
                u32 vlen = b.le32(p + 0x10);
                u16 voff = b.le16(p + 0x14);
                if (b.has(p + voff, vlen) && vlen <= len)
                    a.value.assign(b.p + p + voff, b.p + p + voff + vlen);
            } else {
                a.start_vcn  = (i64)b.le64(p + 0x10);
                a.last_vcn   = (i64)b.le64(p + 0x18);
                u16 runOff   = b.le16(p + 0x20);
                a.alloc_size = (i64)b.le64(p + 0x28);
                a.real_size  = (i64)b.le64(p + 0x30);
                a.init_size  = (i64)b.le64(p + 0x38);
                if (runOff && runOff < len) {
                    Bytes rl(b.p + p, std::min<size_t>(len, limit - p));
                    a.runs = decodeRunlist(rl, runOff, (i64)(volume / (i64)cluster_size) + 1);
                }
            }
            out.push_back(std::move(a));
            p += len;
        }
        return out;
    }

    Record parseRecord(std::vector<u8> raw) const {
        Record r;
        Bytes b(raw);
        if (raw.size() < 48) return r;
        if (!b.eq(0, "FILE", 4)) {
            // BAAD marks a record chkdsk found corrupt; its attributes may still
            // be partly readable, so parse it but flag low confidence.
            if (!b.eq(0, "BAAD", 4)) return r;
        }
        std::vector<u8> fixed = std::move(raw);
        applyFixups(fixed);
        Bytes fb(fixed);
        u16 flags     = fb.le16(0x16);
        r.sequence    = fb.le16(0x10);
        r.link_count  = fb.le16(0x12);
        r.base_ref    = fb.le64(0x20);
        r.record_no   = fb.le32(0x2C);
        r.in_use      = (flags & kRecInUse) != 0;
        r.is_dir      = (flags & kRecDirectory) != 0;
        r.attrs       = parseAttrs(fixed);
        r.valid       = true;
        return r;
    }

    // Read a byte range described by a runlist.
    std::vector<u8> readRuns(const std::vector<Run>& runs, i64 offset, i64 length) const {
        std::vector<u8> out;
        if (length <= 0) return out;
        out.reserve((size_t)std::min<i64>(length, 64LL * 1024 * 1024));
        i64 pos = 0;
        for (const auto& run : runs) {
            i64 runBytes = run.clusters * (i64)cluster_size;
            if (pos + runBytes <= offset) { pos += runBytes; continue; }
            i64 skip = std::max<i64>(0, offset - pos);
            i64 take = std::min(runBytes - skip, length - (i64)out.size());
            if (take <= 0) break;
            if (run.lcn < 0) {
                out.insert(out.end(), (size_t)take, 0);
            } else {
                i64 off = clusterOffset(run.lcn) + skip;
                auto chunk = d->readBlock((u64)off, take);
                out.insert(out.end(), chunk.begin(), chunk.end());
                if ((i64)chunk.size() < take) break;
            }
            pos += runBytes;
            if ((i64)out.size() >= length) break;
        }
        return out;
    }

    std::vector<Extent> runsToExtents(const std::vector<Run>& runs) const {
        std::vector<Extent> ex;
        ex.reserve(runs.size());
        for (const auto& r : runs) {
            i64 bytes = r.clusters * (i64)cluster_size;
            if (bytes <= 0) continue;
            if (r.lcn < 0) { ex.push_back(Extent(0, bytes, true)); continue; }
            i64 off = clusterOffset(r.lcn);
            if (off < 0 || off >= volume) continue;
            if (!ex.empty() && !ex.back().sparse && ex.back().offset + ex.back().length == off)
                ex.back().length += bytes;
            else
                ex.push_back(Extent(off, bytes));
        }
        return ex;
    }

    // ---- $MFT bootstrap --------------------------------------------------
    bool loadMft(ScanResult& res) {
        auto bootstrap = [&](u64 lcn) -> bool {
            i64 off = clusterOffset((i64)lcn);
            if (off < 0 || off + record_size > volume) return false;
            auto raw = d->readBlock((u64)off, record_size);
            if (raw.size() < record_size) return false;
            Record r = parseRecord(raw);
            if (!r.valid) return false;
            for (const auto& a : r.attrs) {
                if (a.type == kAttrData && a.name.empty() && a.nonresident && !a.runs.empty()) {
                    mft_runs = a.runs;
                    i64 bytes = 0;
                    for (const auto& run : mft_runs) bytes += run.clusters * (i64)cluster_size;
                    mft_records = (u64)(bytes / record_size);
                    return mft_records > 0;
                }
            }
            return false;
        };

        if (mft_lcn && bootstrap(mft_lcn)) {
            res.technique("mft_bootstrap");
            return true;
        }
        if (mftmirr_lcn && bootstrap(mftmirr_lcn)) {
            res.technique("mftmirr_fallback");
            res.bump("mft_recovered_from_mirror", 1);
            return true;
        }

        // Boot sector or $MFT record 0 is unusable — locate the MFT by scanning
        // for a run of "FILE" records at cluster boundaries.
        res.technique("mft_signature_scan");
        i64 step = cluster_size;
        i64 limit = std::min<i64>(volume, 8LL * 1024 * 1024 * 1024);
        for (i64 off = 0; off + record_size <= limit; off += step) {
            auto probe = d->readBlock((u64)off, 8);
            if (probe.size() < 8 || std::memcmp(probe.data(), "FILE", 4) != 0) continue;
            // Require several consecutive records to avoid landing on a stray
            // "FILE" string inside user data.
            int consecutive = 0;
            for (int k = 0; k < 8; k++) {
                auto p2 = d->readBlock((u64)(off + (i64)k * record_size), 4);
                if (p2.size() == 4 && std::memcmp(p2.data(), "FILE", 4) == 0) consecutive++;
                else break;
            }
            if (consecutive < 4) continue;
            auto raw = d->readBlock((u64)off, record_size);
            Record r = parseRecord(raw);
            bool gotRuns = false;
            for (const auto& a : r.attrs) {
                if (a.type == kAttrData && a.name.empty() && a.nonresident && !a.runs.empty()) {
                    mft_runs = a.runs;
                    gotRuns = true;
                    break;
                }
            }
            if (!gotRuns) {
                // Treat the contiguous region we found as the MFT.
                i64 avail = volume - off;
                mft_runs = {Run{off / (i64)cluster_size, avail / (i64)cluster_size}};
            }
            i64 bytes = 0;
            for (const auto& run : mft_runs) bytes += run.clusters * (i64)cluster_size;
            mft_records = (u64)(bytes / record_size);
            res.bump("mft_found_by_scan_at", off);
            return mft_records > 0;
        }
        return false;
    }

    std::vector<u8> readRecord(u64 index) const {
        return readRuns(mft_runs, (i64)index * record_size, record_size);
    }
};

// -------------------------------------------------------------------------
struct FileNameInfo {
    u64 parent = 0;
    std::string name;
    u8  space = 0xFF;      // 0 POSIX, 1 Win32, 2 DOS, 3 Win32+DOS
    i64 alloc = 0, real = 0;
    i64 crtime = 0, mtime = 0, ctime = 0, atime = 0;
    bool valid = false;
};

FileNameInfo parseFileName(const std::vector<u8>& v) {
    FileNameInfo fn;
    Bytes b(v);
    if (v.size() < 0x42) return fn;
    fn.parent = b.le64(0x00) & 0x0000FFFFFFFFFFFFull;
    fn.crtime = filetimeToUnix(b.le64(0x08));
    fn.mtime  = filetimeToUnix(b.le64(0x10));
    fn.ctime  = filetimeToUnix(b.le64(0x18));
    fn.atime  = filetimeToUnix(b.le64(0x20));
    fn.alloc  = (i64)b.le64(0x28);
    fn.real   = (i64)b.le64(0x30);
    u8 len    = b.u8at(0x40);
    fn.space  = b.u8at(0x41);
    if (!b.has(0x42, (size_t)len * 2)) return fn;
    fn.name = utf16leToUtf8(b.p + 0x42, (size_t)len * 2);
    fn.valid = !fn.name.empty();
    return fn;
}

// Directory index entries. Deleted files frequently survive here after their
// MFT record has been reused, so this recovers names the MFT no longer has.
void parseIndexEntries(const std::vector<u8>& buf, size_t start, size_t end,
                       const std::function<void(u64, const FileNameInfo&)>& cb) {
    Bytes b(buf);
    size_t p = start;
    int guard = 0;
    while (p + 16 <= end && p + 16 <= b.size() && guard++ < 8192) {
        u64 ref = b.le64(p);
        u16 entryLen = b.le16(p + 8);
        u16 streamLen = b.le16(p + 10);
        u8  flags = b.u8at(p + 12);
        if (entryLen < 16 || p + entryLen > end) break;
        if (streamLen >= 0x42 && b.has(p + 16, streamLen)) {
            std::vector<u8> fnBuf(b.p + p + 16, b.p + p + 16 + streamLen);
            FileNameInfo fn = parseFileName(fnBuf);
            if (fn.valid) cb(ref & 0x0000FFFFFFFFFFFFull, fn);
        }
        if (flags & 0x02) break;         // last entry in this node
        p += entryLen;
    }
}

}  // namespace

// ---------------------------------------------------------------------------

ScanResult scan(DiskReader& disk, const ScanOptions& opt, Progress& prog) {
    ScanResult res;
    res.filesystem = "ntfs";

    NtfsFs fs;
    fs.d = &disk;
    fs.volume = disk.size();

    std::string err;
    if (!fs.readBoot(&err)) {
        // The boot sector is mirrored in the last sector of the volume.
        auto backup = disk.readBlock((u64)std::max<i64>(0, fs.volume - 512), 512);
        if (backup.size() == 512 && Bytes(backup).eq(3, "NTFS    ", 8)) {
            // Re-parse from the backup by temporarily reading it as sector 0.
            Bytes b(backup);
            fs.sector_size = b.le16(0x0B);
            u8 spc = b.u8at(0x0D);
            // A negative exponent encodes a power of two; clamp the shift so a
            // hostile byte cannot shift a 1u past its width (UB), mirroring the
            // primary boot sector parsing in readBoot().
            u32 spcv = (spc > 0x80) ? (1u << std::min<unsigned>(31, 0x100u - (u32)spc)) : spc;
            if (fs.sector_size >= 256 && spcv > 0 && spcv <= 256) {
                fs.cluster_size = fs.sector_size * spcv;
                fs.total_sectors = b.le64(0x28);
                fs.mft_lcn = b.le64(0x30);
                fs.mftmirr_lcn = b.le64(0x38);
                i8 cpr = (i8)b.u8at(0x40);
                // (1u << 0x80) would be UB; derive the magnitude without
                // negating the most negative i8 and clamp the shift to 31 bits.
                u32 cprShift = (u32)(-1 - cpr) + 1u;
                fs.record_size = (cpr < 0) ? (1u << std::min<unsigned>(31, cprShift))
                                           : (u32)cpr * fs.cluster_size;
                if (fs.record_size < 256 || fs.record_size > 65536) fs.record_size = 1024;
                fs.serial = toHex(backup.data() + 0x48, 8);
                res.technique("backup_boot_sector_recovery");
                res.bump("boot_sector_recovered_from_backup", 1);
            } else {
                res.ok = false;
                res.error = err;
                return res;
            }
        } else {
            res.ok = false;
            res.error = err;
            return res;
        }
    }

    res.block_size  = fs.cluster_size;
    res.uuid        = fs.serial;
    res.volume_size = fs.volume;
    // total_sectors * sector_size can overflow u64 on a corrupt boot sector;
    // fall back to the volume size rather than wrapping.
    u64 totalBytes = fs.volume;
    if (fs.total_sectors && fs.total_sectors <= UINT64_MAX / fs.sector_size)
        totalBytes = fs.total_sectors * fs.sector_size;
    res.total_blocks = (i64)(totalBytes / fs.cluster_size);

    if (!fs.loadMft(res)) {
        res.ok = false;
        res.error = "could not locate the $MFT — the volume header and its mirror are both "
                    "unusable and no MFT signature run was found";
        return res;
    }
    res.total_inodes = (i64)fs.mft_records;
    res.bump("mft_records", (i64)fs.mft_records);
    res.bump("mft_record_size", fs.record_size);
    res.ok = true;

    // ---- pass 1: walk every MFT record -----------------------------------
    prog.setPhase("walking $MFT");
    u64 limit = fs.mft_records;
    if (limit > 40000000ull) limit = 40000000ull;
    prog.set(0, (i64)limit);

    struct Node {
        RecoveredFile file;
        u64  parent = 0;
        bool have_name = false;
        bool base_present = true;
    };
    std::unordered_map<u64, Node> nodes;
    nodes.reserve(std::min<size_t>((size_t)limit, 300000));

    // Attributes can live in child records referenced by $ATTRIBUTE_LIST; those
    // children are visited too, and their $DATA is folded into the base record.
    std::unordered_map<u64, std::vector<Attr>> childAttrs;

    // Read the MFT in large chunks rather than one record at a time.
    const u64 recordsPerChunk = std::max<u64>(1, (4 * 1024 * 1024) / fs.record_size);
    std::vector<u8> chunk;
    i64 badRecords = 0, adsCount = 0, compressedCount = 0;

    for (u64 idx = 0; idx < limit; idx += recordsPerChunk) {
        if (prog.cancelled()) break;
        // The nodes map holds a full RecoveredFile per record and grows without
        // bound on huge volumes; stop harvesting when we already have more than
        // the scan will ever report (ext/xfs cap the same way).
        if ((i64)nodes.size() >= (i64)opt.max_files * 2) break;
        prog.set((i64)idx, (i64)limit);
        u64 count = std::min<u64>(recordsPerChunk, limit - idx);
        chunk = fs.readRuns(fs.mft_runs, (i64)idx * fs.record_size, (i64)(count * fs.record_size));
        if (chunk.empty()) break;
        u64 got = chunk.size() / fs.record_size;

        for (u64 k = 0; k < got; k++) {
            u64 recNo = idx + k;
            std::vector<u8> raw(chunk.begin() + (size_t)(k * fs.record_size),
                                chunk.begin() + (size_t)((k + 1) * fs.record_size));
            if (raw.size() < 48) continue;
            if (std::memcmp(raw.data(), "FILE", 4) != 0) {
                if (std::memcmp(raw.data(), "BAAD", 4) == 0) badRecords++;
                continue;
            }
            Record r = fs.parseRecord(std::move(raw));
            if (!r.valid) continue;
            if (r.record_no == 0 && recNo != 0) r.record_no = recNo;

            u64 baseNo = r.base_ref & 0x0000FFFFFFFFFFFFull;
            if (baseNo != 0 && baseNo != recNo) {
                // Continuation record — stash its attributes for the base.
                auto& v = childAttrs[baseNo];
                for (auto& a : r.attrs) v.push_back(std::move(a));
                continue;
            }

            Node node;
            RecoveredFile& f = node.file;
            f.id = recNo;
            f.is_deleted = !r.in_use;
            f.is_dir = r.is_dir;
            f.kind = r.is_dir ? FileKind::Directory : FileKind::Regular;
            f.nlink = r.link_count;
            f.method = r.in_use ? "mft_record_walk" : "deleted_mft_record";

            FileNameInfo best;
            for (const auto& a : r.attrs) {
                switch (a.type) {
                    case kAttrStandardInfo: {
                        Bytes b(a.value);
                        if (a.value.size() >= 0x30) {
                            f.crtime = filetimeToUnix(b.le64(0x00));
                            f.mtime  = filetimeToUnix(b.le64(0x08));
                            f.ctime  = filetimeToUnix(b.le64(0x10));
                            f.atime  = filetimeToUnix(b.le64(0x18));
                            u32 dosFlags = b.le32(0x20);
                            if (dosFlags & 0x4000) f.is_encrypted = true;
                            if (dosFlags & 0x0800) f.is_compressed = true;
                        }
                        break;
                    }
                    case kAttrFileName: {
                        FileNameInfo fn = parseFileName(a.value);
                        if (!fn.valid) break;
                        // Prefer Win32 / POSIX names over the 8.3 DOS alias.
                        bool better = !best.valid ||
                                      (best.space == 2 && fn.space != 2) ||
                                      (fn.space == 1 || fn.space == 3);
                        if (better) best = fn;
                        break;
                    }
                    case kAttrVolumeName:
                        if (!a.value.empty())
                            res.label = utf16leToUtf8(a.value.data(), a.value.size());
                        break;
                    default: break;
                }
            }
            if (best.valid) {
                f.name = best.name;
                node.parent = best.parent;
                node.have_name = true;
                if (f.size == 0) f.size = best.real;
                if (f.alloc_size == 0) f.alloc_size = best.alloc;
                if (f.crtime == 0) f.crtime = best.crtime;
                if (f.mtime == 0) f.mtime = best.mtime;
            } else {
                f.name = (f.is_deleted ? "deleted_mft_" : "mft_") + std::to_string(recNo);
            }
            nodes.emplace(recNo, std::move(node));
        }
    }
    res.technique("mft_record_walk");
    res.technique("update_sequence_fixups");
    res.technique("runlist_decoding");
    if (badRecords) res.bump("baad_records", badRecords);

    // ---- attach $DATA (including continuation records and ADS) ------------
    prog.setPhase("resolving data streams");
    std::vector<RecoveredFile> streams;   // alternate data streams become their own rows

    for (u64 idx = 0; idx < limit && !prog.cancelled(); idx += recordsPerChunk) {
        u64 count = std::min<u64>(recordsPerChunk, limit - idx);
        chunk = fs.readRuns(fs.mft_runs, (i64)idx * fs.record_size, (i64)(count * fs.record_size));
        if (chunk.empty()) break;
        u64 got = chunk.size() / fs.record_size;
        for (u64 k = 0; k < got; k++) {
            u64 recNo = idx + k;
            auto nit = nodes.find(recNo);
            if (nit == nodes.end()) continue;
            std::vector<u8> raw(chunk.begin() + (size_t)(k * fs.record_size),
                                chunk.begin() + (size_t)((k + 1) * fs.record_size));
            if (raw.size() < 48 || std::memcmp(raw.data(), "FILE", 4) != 0) continue;
            Record r = fs.parseRecord(std::move(raw));
            if (!r.valid) continue;

            std::vector<Attr> all = std::move(r.attrs);
            auto ca = childAttrs.find(recNo);
            if (ca != childAttrs.end())
                for (auto& a : ca->second) all.push_back(a);

            RecoveredFile& f = nit->second.file;
            bool haveMain = false;

            for (const auto& a : all) {
                if (a.type != kAttrData) continue;
                bool isMain = a.name.empty();
                if (a.flags & kAttrCompressed) { compressedCount++; }

                if (!a.nonresident) {
                    if (isMain) {
                        f.resident = a.value;
                        if (f.size <= 0) f.size = (i64)a.value.size();
                        f.method += "+resident_data";
                        haveMain = true;
                    } else if (!a.value.empty()) {
                        RecoveredFile ads = f;
                        ads.extents.clear();
                        ads.resident = a.value;
                        ads.size = (i64)a.value.size();
                        ads.is_adstream = true;
                        ads.name = f.name + ":" + a.name;
                        ads.method = "alternate_data_stream";
                        streams.push_back(std::move(ads));
                        adsCount++;
                    }
                    continue;
                }
                if (a.runs.empty()) continue;
                auto ex = fs.runsToExtents(a.runs);
                if (isMain) {
                    if (a.start_vcn == 0) {
                        f.extents = ex;
                        if (a.real_size > 0) f.size = a.real_size;
                        if (a.alloc_size > 0) f.alloc_size = a.alloc_size;
                    } else {
                        f.extents.insert(f.extents.end(), ex.begin(), ex.end());
                    }
                    f.is_compressed |= (a.flags & kAttrCompressed) != 0;
                    f.is_encrypted  |= (a.flags & kAttrEncrypted) != 0;
                    f.is_sparse     |= (a.flags & kAttrSparse) != 0;
                    // A compressed data stream is one LZNT1 unit chain: the
                    // clusters hold back-to-back units whose length is found
                    // by decoding. Only a single contiguous extent lets us
                    // feed the whole stream to the decoder; sparse runs break
                    // the chain, so those stay flagged and undecoded.
                    if ((a.flags & kAttrCompressed) && !(a.flags & kAttrSparse) &&
                        f.extents.size() == 1 && f.size > 0) {
                        f.codec = "lznt1";
                        f.decomp_sizes.assign(1, f.size);
                    }
                    haveMain = true;
                } else {
                    RecoveredFile ads = f;
                    ads.resident.clear();
                    ads.extents = ex;
                    ads.size = a.real_size;
                    ads.alloc_size = a.alloc_size;
                    ads.is_adstream = true;
                    ads.name = f.name + ":" + a.name;
                    ads.method = "alternate_data_stream";
                    finalizeFile(ads, fs.volume);
                    streams.push_back(std::move(ads));
                    adsCount++;
                }
            }
            if (!haveMain && !f.is_dir && f.size > 0) f.method += "+no_data_runs";
        }
    }
    if (adsCount) { res.technique("alternate_data_streams"); res.bump("alternate_data_streams", adsCount); }
    if (compressedCount) res.bump("compressed_streams", compressedCount);

    // ---- $I30 index slack -------------------------------------------------
    if (opt.slack && !prog.cancelled()) {
        prog.setPhase("mining $I30 index slack");
        i64 slackNames = 0;
        std::unordered_map<u64, std::pair<u64, std::string>> indexNames;

        for (u64 idx = 0; idx < limit && !prog.cancelled(); idx += recordsPerChunk) {
            u64 count = std::min<u64>(recordsPerChunk, limit - idx);
            chunk = fs.readRuns(fs.mft_runs, (i64)idx * fs.record_size, (i64)(count * fs.record_size));
            if (chunk.empty()) break;
            u64 got = chunk.size() / fs.record_size;
            for (u64 k = 0; k < got; k++) {
                u64 recNo = idx + k;
                auto nit = nodes.find(recNo);
                if (nit == nodes.end() || !nit->second.file.is_dir) continue;
                std::vector<u8> raw(chunk.begin() + (size_t)(k * fs.record_size),
                                    chunk.begin() + (size_t)((k + 1) * fs.record_size));
                if (raw.size() < 48 || std::memcmp(raw.data(), "FILE", 4) != 0) continue;
                Record r = fs.parseRecord(std::move(raw));

                auto emit = [&](u64 ref, const FileNameInfo& fn) {
                    if (ref == 0 || fn.name.empty()) return;
                    if (nodes.count(ref)) return;               // MFT already has it
                    if (indexNames.count(ref)) return;
                    indexNames[ref] = {recNo, fn.name};
                    slackNames++;
                };

                for (const auto& a : r.attrs) {
                    if (a.type == kAttrIndexRoot && a.name == "$I30" && a.value.size() > 32) {
                        Bytes b(a.value);
                        size_t entryOff = 16 + b.le32(16);
                        size_t entryEnd = 16 + b.le32(20);
                        parseIndexEntries(a.value, entryOff, std::min(entryEnd, a.value.size()), emit);
                    } else if (a.type == kAttrIndexAlloc && a.name == "$I30" && !a.runs.empty()) {
                        i64 total = 0;
                        for (const auto& run : a.runs) total += run.clusters * (i64)fs.cluster_size;
                        total = std::min<i64>(total, 16LL * 1024 * 1024);
                        for (i64 off = 0; off + fs.index_size <= total; off += fs.index_size) {
                            auto blk = fs.readRuns(a.runs, off, fs.index_size);
                            if (blk.size() < 32) break;
                            if (std::memcmp(blk.data(), "INDX", 4) != 0) continue;
                            fs.applyFixups(blk);
                            Bytes b(blk);
                            size_t entryOff = 24 + b.le32(24);
                            // Walk the whole buffer, not just the used range:
                            // the space past the used length is exactly where
                            // deleted entries linger.
                            parseIndexEntries(blk, entryOff, blk.size(), emit);
                        }
                    }
                }
            }
        }
        for (const auto& [ref, pr] : indexNames) {
            RecoveredFile f;
            f.id = ref;
            f.name = pr.second;
            f.parent_id = pr.first;
            f.is_deleted = true;
            f.method = "i30_index_slack";
            f.confidence = 0.2;    // name only — the MFT record is gone
            nodes[ref].file = f;
            nodes[ref].parent = pr.first;
            nodes[ref].have_name = true;
        }
        if (slackNames) {
            res.technique("i30_index_slack");
            res.bump("index_slack_names", slackNames);
        }
    }

    // ---- $UsnJrnl change journal ------------------------------------------
    if (opt.journal && !prog.cancelled()) {
        prog.setPhase("reading $UsnJrnl");
        // $Extend is MFT record 11; find $UsnJrnl by name among the records we
        // already parsed, then read its $J data stream.
        u64 usnRec = 0;
        for (const auto& [no, n] : nodes)
            if (n.file.name == "$UsnJrnl") { usnRec = no; break; }
        i64 usnDeletes = 0;
        if (usnRec) {
            auto raw = fs.readRecord(usnRec);
            if (raw.size() >= 48 && std::memcmp(raw.data(), "FILE", 4) == 0) {
                Record r = fs.parseRecord(std::move(raw));
                for (const auto& a : r.attrs) {
                    if (a.type != kAttrData || a.name != "$J" || a.runs.empty()) continue;
                    i64 total = 0;
                    for (const auto& run : a.runs) total += run.clusters * (i64)fs.cluster_size;
                    i64 cap = std::min<i64>(total, 256LL * 1024 * 1024);
                    const i64 step = 4LL * 1024 * 1024;
                    for (i64 off = std::max<i64>(0, total - cap); off < total && !prog.cancelled();
                         off += step) {
                        auto buf = fs.readRuns(a.runs, off, std::min(step, total - off));
                        Bytes b(buf);
                        size_t p = 0;
                        while (p + 60 <= b.size()) {
                            u32 recLen = b.le32(p);
                            if (recLen < 60 || recLen > 1024 || p + recLen > b.size()) { p += 8; continue; }
                            u16 major = b.le16(p + 4);
                            if (major != 2 && major != 3) { p += 8; continue; }
                            u64 fileRef = b.le64(p + 8) & 0x0000FFFFFFFFFFFFull;
                            u64 parentRef = b.le64(p + 16) & 0x0000FFFFFFFFFFFFull;
                            u32 reason = b.le32(p + 40);
                            u16 nameLen = b.le16(p + 56);
                            u16 nameOff = b.le16(p + 58);
                            if (nameLen && b.has(p + nameOff, nameLen)) {
                                std::string nm = utf16leToUtf8(b.p + p + nameOff, nameLen);
                                const u32 kDelete = 0x00000200;   // USN_REASON_FILE_DELETE
                                if ((reason & kDelete) && !nm.empty() && !nodes.count(fileRef)) {
                                    RecoveredFile f;
                                    f.id = fileRef;
                                    f.name = nm;
                                    f.parent_id = parentRef;
                                    f.is_deleted = true;
                                    f.method = "usn_journal";
                                    f.confidence = 0.15;
                                    nodes[fileRef].file = f;
                                    nodes[fileRef].parent = parentRef;
                                    nodes[fileRef].have_name = true;
                                    usnDeletes++;
                                }
                            }
                            p += recLen;
                        }
                    }
                    break;
                }
            }
        }
        if (usnDeletes) {
            res.technique("usn_journal");
            res.bump("usn_deleted_names", usnDeletes);
        }
    }

    // ---- path reconstruction ----------------------------------------------
    prog.setPhase("reconstructing paths");
    auto pathOf = [&](u64 rec) -> std::string {
        std::vector<std::string> parts;
        u64 cur = rec;
        int guard = 0;
        while (cur != 5 && guard++ < 128) {                 // record 5 is the root
            auto it = nodes.find(cur);
            if (it == nodes.end() || !it->second.have_name) break;
            parts.push_back(it->second.file.name);
            u64 par = it->second.parent;
            if (par == cur || par == 0) break;
            cur = par;
        }
        if (parts.empty()) return {};
        std::string out;
        for (auto it = parts.rbegin(); it != parts.rend(); ++it) { out += '/'; out += *it; }
        return out;
    };

    res.files.reserve(std::min<size_t>(nodes.size() + streams.size(), (size_t)opt.max_files));
    i64 deletedRecoverable = 0;
    i64 emptyRecords = 0;
    for (auto& [rec, n] : nodes) {
        if ((i64)res.files.size() >= opt.max_files) break;
        RecoveredFile& f = n.file;
        if (rec < 16 && !opt.include_live) continue;        // NTFS metafiles
        if (!f.is_deleted && !opt.include_live) continue;
        // A record that is not in use, has never had a name and holds no data
        // was simply never allocated — mkntfs pre-creates a run of them. They
        // are not recoverable files and would otherwise swamp the results.
        if (f.is_deleted && !n.have_name && f.extents.empty() && f.resident.empty() &&
            f.size == 0 && f.method != "i30_index_slack" && f.method != "usn_journal") {
            emptyRecords++;
            continue;
        }
        f.parent_id = n.parent;
        f.path = pathOf(rec);
        if (rec == 5) f.path = "/";                 // record 5 is the root dir
        else if (f.path.empty()) f.path = "/$orphans/" + f.name;
        finalizeFile(f, fs.volume);
        if (f.is_deleted) {
            if (f.recoverable <= 0 && f.resident.empty()) f.confidence = std::min(f.confidence, 0.1);
            else if (f.size > 0) f.confidence = std::min(1.0, (double)std::max<i64>(f.recoverable, (i64)f.resident.size()) / (double)f.size);
            if (f.recoverable > 0 || !f.resident.empty()) deletedRecoverable++;
        }
        res.files.push_back(std::move(f));
    }
    for (auto& s : streams) {
        if ((i64)res.files.size() >= opt.max_files) break;
        u64 baseRec = s.id;
        std::string base = pathOf(baseRec);
        s.path = base.empty() ? ("/$orphans/" + s.name) : (dirName(base) + "/" + s.name);
        res.files.push_back(std::move(s));
    }

    res.bump("deleted_with_recoverable_data", deletedRecoverable);
    res.bump("unallocated_mft_records", emptyRecords);
    res.technique("file_name_attribute_paths");
    prog.setFound((i64)res.files.size());

    std::sort(res.files.begin(), res.files.end(),
              [](const RecoveredFile& a, const RecoveredFile& b) {
                  if (a.is_deleted != b.is_deleted) return a.is_deleted > b.is_deleted;
                  return a.path < b.path;
              });
    return res;
}

}  // namespace ntfs
}  // namespace ghost
