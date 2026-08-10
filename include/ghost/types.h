// GHOST//RECOVER — core value types shared by every subsystem.
#pragma once

#include <atomic>
#include <cstdint>
#include <cstring>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace ghost {

using u8  = uint8_t;   using i8  = int8_t;
using u16 = uint16_t;  using i16 = int16_t;
using u32 = uint32_t;  using i32 = int32_t;
using u64 = uint64_t;  using i64 = int64_t;

// ---------------------------------------------------------------------------
// Bounds-checked little/big-endian accessors.
//
// Every filesystem parser in this codebase reads packed on-disk structures out
// of a heap buffer whose length is not guaranteed (a truncated image, a bad
// sector that read short). Reading past the end used to segfault the whole
// server, so all field access goes through these helpers which return 0 when
// the requested field would fall outside the buffer.
// ---------------------------------------------------------------------------
struct Bytes {
    const u8* p = nullptr;
    size_t    n = 0;

    Bytes() = default;
    Bytes(const u8* ptr, size_t len) : p(ptr), n(len) {}
    Bytes(const std::vector<u8>& v) : p(v.data()), n(v.size()) {}

    bool has(size_t off, size_t len) const { return p && off + len >= off && off + len <= n; }
    size_t size() const { return n; }
    bool empty() const { return n == 0; }

    u8  u8at (size_t o) const { return has(o, 1) ? p[o] : 0; }
    u16 le16 (size_t o) const { return has(o, 2) ? (u16)(p[o] | (u16)p[o+1] << 8) : 0; }
    u32 le24 (size_t o) const { return has(o, 3) ? ((u32)p[o] | (u32)p[o+1] << 8 | (u32)p[o+2] << 16) : 0; }
    u32 le32 (size_t o) const { return has(o, 4) ? ((u32)p[o] | (u32)p[o+1] << 8 | (u32)p[o+2] << 16 | (u32)p[o+3] << 24) : 0; }
    u64 le48 (size_t o) const { u64 v = 0; if (has(o, 6)) for (int i = 5; i >= 0; i--) v = (v << 8) | p[o+i]; return v; }
    u64 le64 (size_t o) const { u64 v = 0; if (has(o, 8)) for (int i = 7; i >= 0; i--) v = (v << 8) | p[o+i]; return v; }
    u16 be16 (size_t o) const { return has(o, 2) ? (u16)((u16)p[o] << 8 | p[o+1]) : 0; }
    u32 be24 (size_t o) const { return has(o, 3) ? ((u32)p[o] << 16 | (u32)p[o+1] << 8 | (u32)p[o+2]) : 0; }
    u32 be32 (size_t o) const { return has(o, 4) ? ((u32)p[o] << 24 | (u32)p[o+1] << 16 | (u32)p[o+2] << 8 | (u32)p[o+3]) : 0; }
    u64 be64 (size_t o) const { u64 v = 0; if (has(o, 8)) for (int i = 0; i < 8; i++) v = (v << 8) | p[o+i]; return v; }
    i64 sle   (size_t o, int width) const {  // signed little-endian of arbitrary width (NTFS runlists)
        if (!has(o, (size_t)width) || width <= 0 || width > 8) return 0;
        i64 v = 0;
        for (int i = width - 1; i >= 0; i--) v = (v << 8) | p[o+i];
        int shift = 64 - width * 8;
        return (v << shift) >> shift;  // sign-extend
    }
    u64 ule   (size_t o, int width) const {
        if (!has(o, (size_t)width) || width <= 0 || width > 8) return 0;
        u64 v = 0;
        for (int i = width - 1; i >= 0; i--) v = (v << 8) | p[o+i];
        return v;
    }
    bool eq(size_t o, const char* magic, size_t len) const {
        return has(o, len) && std::memcmp(p + o, magic, len) == 0;
    }
    std::string str(size_t o, size_t len) const {
        if (!has(o, len)) return {};
        return std::string(reinterpret_cast<const char*>(p + o), len);
    }
    // Fixed-width field trimmed of trailing spaces/NULs — volume labels etc.
    std::string trimmed(size_t o, size_t len) const {
        std::string s = str(o, len);
        while (!s.empty() && (s.back() == ' ' || s.back() == '\0')) s.pop_back();
        return s;
    }
};

// ---------------------------------------------------------------------------
// A contiguous run of bytes on the device. Files are described as ordered
// lists of extents so fragmented recovery is correct — the previous engine
// modelled a file as a single (offset,size) pair, which silently corrupted
// every fragmented file it "recovered".
// ---------------------------------------------------------------------------
struct Extent {
    i64  offset = 0;      // byte offset, relative to the reader's window
    i64  length = 0;      // byte count
    bool sparse = false;  // hole: emit zeroes, do not read the device

    Extent() = default;
    Extent(i64 o, i64 l, bool s = false) : offset(o), length(l), sparse(s) {}
};

enum class FileKind : u8 { Regular = 0, Directory, Symlink, Device, Fifo, Socket, Other };

const char* fileKindName(FileKind k);

// ---------------------------------------------------------------------------
// One recovered object. Produced by every filesystem driver and by the carver.
// ---------------------------------------------------------------------------
struct RecoveredFile {
    u64         id          = 0;    // inode number / MFT reference / cluster
    u64         parent_id   = 0;
    std::string name;
    std::string path;               // reconstructed absolute path within the volume
    i64         size        = 0;    // logical size from metadata
    i64         alloc_size  = 0;    // allocated size on disk

    std::vector<Extent> extents;    // data runs; empty for resident/inline files
    std::vector<u8>     resident;   // inline data (ext4 inline_data, NTFS resident $DATA)

    bool is_deleted    = false;
    bool is_dir        = false;
    bool is_sparse     = false;
    bool is_compressed = false;
    bool is_encrypted  = false;
    bool is_adstream   = false;     // NTFS alternate data stream

    FileKind kind = FileKind::Regular;
    i64 mtime = 0, atime = 0, ctime = 0, crtime = 0, dtime = 0;  // unix epoch seconds
    u32 uid = 0, gid = 0, mode = 0;
    u32 nlink = 0;

    std::string method;             // which technique surfaced this file
    double      confidence = 1.0;   // 0..1 — how likely the data is intact
    i64         recoverable = 0;    // sum(extents) clamped to size

    // Non-empty when the extents hold compressed blocks that the extractor must
    // decode. Each extent is then one independently compressed block.
    // Values: "" (raw) | "zlib-block" | "lzma-block"
    std::string codec;

    // SquashFS-style tail packing: the final extent is a block shared with other
    // files, and only [fragment_offset, fragment_offset + fragment_length) of it
    // (after decoding) belongs to this file. -1 = the whole extent is ours.
    i64 fragment_offset = -1;
    i64 fragment_length = 0;

    i64 dataBytes() const {
        if (!resident.empty()) return (i64)resident.size();
        i64 t = 0;
        for (const auto& e : extents) t += e.length;
        return t;
    }
};

// ---------------------------------------------------------------------------
// Result of a filesystem metadata scan.
// ---------------------------------------------------------------------------
struct ScanResult {
    bool        ok = false;
    std::string filesystem;
    std::string error;
    std::string label;
    std::string uuid;

    i64 block_size   = 0;
    i64 total_blocks = 0;
    i64 free_blocks  = 0;
    i64 total_inodes = 0;
    i64 free_inodes  = 0;
    i64 volume_size  = 0;

    std::vector<RecoveredFile> files;
    std::vector<std::string>   techniques;   // techniques that actually ran and produced data
    std::map<std::string, i64> stats;        // named counters shown in the UI

    i64 deleted_found = 0;

    void bump(const std::string& k, i64 by = 1) { stats[k] += by; }
    void technique(const std::string& t) {
        for (const auto& x : techniques) if (x == t) return;
        techniques.push_back(t);
    }
};

// ---------------------------------------------------------------------------
// Carving
// ---------------------------------------------------------------------------
struct CarvedFile {
    std::string format;      // "JPEG"
    std::string ext;         // "jpg"
    std::string category;    // "image" | "video" | "audio" | "document" | ...
    i64         offset = 0;
    i64         size   = 0;
    std::string file;        // path written on the host filesystem
    std::string md5;
    std::string sha1;
    double      entropy    = 0.0;
    double      confidence = 1.0;
    bool        validated  = false;   // format validator confirmed structure
    bool        whole_file = false;   // validation covered the file end to end
    bool        truncated  = false;   // hit a size cap / end of device
    bool        fragmented = false;   // reassembled from more than one run
    std::vector<Extent> extents;
};

struct CarveResult {
    bool        ok = false;
    std::string error;
    i64 image_size        = 0;
    i64 bytes_scanned     = 0;
    i64 signatures_loaded = 0;
    i64 candidates_seen   = 0;   // signature hits before validation
    i64 rejected          = 0;   // hits discarded by validators/entropy
    i64 duplicates        = 0;
    i64 files_recovered   = 0;
    i64 elapsed_ms        = 0;
    std::map<std::string, i64> by_format;
    std::map<std::string, i64> by_category;
    std::vector<CarvedFile>    files;
};

// ---------------------------------------------------------------------------
// Detection / geometry
// ---------------------------------------------------------------------------
struct DetectResult {
    bool        detected = false;
    std::string filesystem;
    std::string family;
    std::string label;
    std::string uuid;
    i64         size_bytes  = 0;
    double      size_mb     = 0;
    i64         block_size  = 0;
    double      confidence  = 0;
    std::string note;        // human-readable hint (e.g. "whole disk — pick a partition")
    std::string error;
    bool        is_container = false;   // partition table / LVM / LUKS / RAID member
    std::string container;              // "mbr" | "gpt" | "lvm2" | "luks" | "mdraid" ...
};

struct FsEntry {
    std::string id, name, family, category, magic;
    bool        readonly = false;
    bool        supported = false;   // has a real metadata driver (not carve-only)
};

struct DiskInfo {
    std::string name, display_name, device_path;
    std::string type, type_label;
    i64    size_bytes = 0;
    double size_gb    = 0;
    bool   removable = false, rotational = false, accessible = true;
    std::string status_message, vendor, model, serial, wwid, transport;
    i64    logical_sector = 512, physical_sector = 512;
    int    partition_count = 0;
    bool   is_raid_member = false;
    std::vector<std::string> holders;
};

struct PartitionInfo {
    std::string table;                 // "mbr" | "gpt" | "bsd" | "apm" | "recovered"
    int         entry  = 0;
    std::string type;                  // human-readable type
    std::string type_guid;             // GPT type GUID / MBR type byte hex
    std::string uuid;                  // GPT unique partition GUID
    std::string status;                // "active" | "inactive" | "deleted" | "unallocated"
    i64    start_lba = 0, size_lba = 0, start_byte = 0, size_bytes = 0;
    double size_mb   = 0;
    std::string name, note;

    std::string filesystem;
    std::string fs_status;             // "healthy" | "damaged" | "unknown" | "unallocated"
    std::string label;
    std::string fs_uuid;
    i64    used_bytes   = -1;
    i64    free_bytes   = -1;
    int    used_percent = -1;
    bool   bootable     = false;
    bool   recovered    = false;       // found by signature scan, not in a table
    double confidence   = 1.0;
};

struct PartitionScanResult {
    bool        ok = false;
    std::string partition_table;
    std::string error;
    std::vector<PartitionInfo> partitions;
    std::vector<PartitionInfo> deleted_partitions;   // recovered + unallocated regions
    int  count = 0, deleted_count = 0;
    i64  image_size = 0;
    std::string disk_model, disk_serial, disk_type, disk_guid;
    i64  sector_size = 512, total_sectors = 0;
    bool gpt_primary_ok = false, gpt_backup_ok = false, mbr_ok = false;
    std::vector<std::string> warnings;
};

struct RepairResult {
    bool        ok = false;
    bool        applied = false;      // true only when bytes were actually written
    std::string action, detail, error;
    std::vector<std::string> steps;
};

struct ExtractResult {
    bool        ok = false;
    std::string error;
    std::string output_dir;
    int  files_written = 0;
    int  files_failed  = 0;
    // Written, but still in the filesystem's compressed form because this
    // engine has no decoder for that codec. The file exists and is the right
    // size, which is exactly why staying quiet about it would be worse than
    // reporting a failure.
    int  files_undecoded = 0;
    i64  bytes_written = 0;
    std::vector<std::string> failures;
    std::vector<std::string> undecoded;
};

struct SaveResult {
    bool ok = false;
    std::string path, error;
    i64 size = 0;
};

// ---------------------------------------------------------------------------
// Progress reporting — shared between a worker thread and the HTTP poller.
// ---------------------------------------------------------------------------
class Progress {
public:
    void setPhase(const std::string& p) {
        std::lock_guard<std::mutex> lk(m_);
        phase_ = p;
    }
    std::string phase() const {
        std::lock_guard<std::mutex> lk(m_);
        return phase_;
    }
    void set(i64 done, i64 total) { done_ = done; total_ = total; }
    void add(i64 n) { done_ += n; }
    void setFound(i64 n) { found_ = n; }
    void addFound(i64 n = 1) { found_ += n; }

    i64 done()  const { return done_; }
    i64 total() const { return total_; }
    i64 found() const { return found_; }
    double percent() const {
        i64 t = total_.load();
        if (t <= 0) return 0.0;
        double p = 100.0 * (double)done_.load() / (double)t;
        return p < 0 ? 0 : (p > 100 ? 100 : p);
    }
    void cancel() { cancel_ = true; }
    bool cancelled() const { return cancel_.load(); }

private:
    mutable std::mutex  m_;
    std::string         phase_ = "starting";
    std::atomic<i64>    done_{0}, total_{0}, found_{0};
    std::atomic<bool>   cancel_{false};
};

// Null-object progress so drivers never need to null-check.
Progress& nullProgress();

}  // namespace ghost
